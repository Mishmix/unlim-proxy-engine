"""Background loops: scraping, the five check queues, geo enrichment, and the
in-memory hot pool the API serves from.

Everything runs as asyncio tasks inside the single process. SQLite is the durable
record; `Scheduler.pool` is the sorted snapshot that `/v1/proxy` answers from, so a
request never touches the database.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta

from .checker import Checker, gather_limited
from .config import Settings
from .geo import Geo
from .models import L1Result, Proxy
from .scoring import score, uptime_ratio
from .scraper import Scraper
from .storage import Storage, push_history, utcnow

log = logging.getLogger(__name__)

# A client that has lost its way could report faster than the recheck loop drains.
# The cap makes that a dropped signal instead of unbounded memory.
_REPORT_RECHECK_CAP = 5000


def _ago(seconds: int) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Scheduler:
    def __init__(self, settings: Settings, storage: Storage) -> None:
        self.settings = settings
        self.storage = storage
        self.checker = Checker(settings.checker)
        self.geo = Geo(settings.geo)
        self.scraper = Scraper(settings, storage)
        self.pool: list[Proxy] = []
        self.started_at = time.time()
        self.last_scrape_at: str | None = None
        self._tasks: list[asyncio.Task] = []
        self._db_lock = asyncio.Lock()
        self._recently_served: dict[int, float] = {}
        self._cold_buffer: list[Proxy] = []
        self._report_recheck: dict[int, Proxy] = {}

    # ─── lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        await self.checker.detect_own_ip()
        await self.rebuild_pool()
        # The geo databases are ~200 MB on a cold start. The `geo_refresh` loop
        # downloads them in the background; blocking here would keep the API from
        # answering for minutes. Enrichment simply waits until they land.
        loops: list[tuple[str, Callable[[], Awaitable[None]], int]] = [
            ("scrape", self._scrape_once, self.settings.scraper.interval_sec),
            ("cold", self._cold_once, 1),
            ("hot", self._hot_once, self.settings.queues.hot_interval_sec),
            ("warm", self._warm_once, self.settings.queues.warm_interval_sec),
            ("l2", self._l2_once, self.settings.queues.l2_interval_sec),
            ("youtube", self._yt_once, self.settings.queues.yt_interval_sec),
            ("report", self._report_once, 5),
            ("quarantine", self._quarantine_once, self.settings.queues.quarantine_interval_sec),
            ("enrich", self._enrich_once, 20),
            ("maintenance", self._maintenance_once, 600),
            ("geo_refresh", self._geo_refresh_once, self.settings.geo.refresh_interval_sec),
        ]
        self._tasks = [
            asyncio.create_task(self._loop(name, fn, interval), name=name)
            for name, fn, interval in loops
        ]
        log.info("scheduler started", extra={"loops": [n for n, _, _ in loops]})

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        self.geo.close()

    async def _loop(self, name: str, fn: Callable[[], Awaitable[None]], interval: int) -> None:
        """Never let one failing cycle kill a queue; log it and try again next tick."""
        while True:
            started = time.monotonic()
            try:
                await fn()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("loop cycle failed", extra={"loop": name})
            delay = max(interval - (time.monotonic() - started), 1.0 if interval <= 1 else 5.0)
            await asyncio.sleep(delay)

    # ─── scraping ──────────────────────────────────────────────────────────

    async def _scrape_once(self) -> None:
        sources, results = await self.scraper.fetch_all()
        async with self._db_lock:
            await self.scraper.store(sources, results)
        self.last_scrape_at = utcnow()

    # ─── check queues ──────────────────────────────────────────────────────

    async def _cold_once(self) -> None:
        """The carousel of candidates that have never answered, oldest attempt first.

        Fetched a window at a time rather than a batch at a time: the query reads and
        materialises twenty thousand rows while holding the lock every other queue
        needs, and doing that once per window instead of once per second is the same
        work for a tenth of the cost.
        """
        if not self._cold_buffer:
            window = self.settings.queues.cold_batch * self.settings.queues.cold_window_batches
            async with self._db_lock:
                self._cold_buffer = await self.storage.fetch_cold(window)
        batch, self._cold_buffer = (
            self._cold_buffer[: self.settings.queues.cold_batch],
            self._cold_buffer[self.settings.queues.cold_batch :],
        )
        if batch:
            await self._run_l1(
                batch, self.settings.queues.cold_concurrency, "cold", prefilter=True
            )

    async def _hot_once(self) -> None:
        async with self._db_lock:
            batch = await self.storage.fetch_hot(self.settings.queues.hot_concurrency * 12)
        if batch:
            await self._run_l1(batch, self.settings.queues.hot_concurrency, "hot")
            await self.rebuild_pool()

    async def _warm_once(self) -> None:
        async with self._db_lock:
            batch = await self.storage.fetch_warm(
                self.settings.queues.warm_concurrency * 6,
                self.settings.queues.fail_streak_quarantine,
            )
        if batch:
            await self._run_l1(batch, self.settings.queues.warm_concurrency, "warm")

    async def _quarantine_once(self) -> None:
        async with self._db_lock:
            batch = await self.storage.fetch_quarantine(
                self.settings.queues.quarantine_concurrency * 4,
                self.settings.queues.fail_streak_quarantine,
                _ago(self.settings.queues.quarantine_interval_sec),
            )
        if batch:
            await self._run_l1(batch, self.settings.queues.quarantine_concurrency, "quarantine")

    async def _l2_once(self) -> None:
        """Only the hot pool, never more often than `l2_min_interval_sec` per proxy —
        hammering /search is itself what triggers the captcha."""
        async with self._db_lock:
            batch = await self.storage.fetch_l2_due(
                self.settings.queues.l2_concurrency * 8,
                _ago(self.settings.checker.l2_min_interval_sec),
            )
        if not batch:
            return
        results = await gather_limited(
            [self.checker.check_l2(p.host, p.port, p.protocol) for p in batch],
            self.settings.queues.l2_concurrency,
        )
        clean = 0
        async with self._db_lock:
            for proxy, result in zip(batch, results, strict=True):
                if isinstance(result, BaseException):
                    continue
                proxy.google_clean = int(result.status == "SEARCH_OK")
                proxy.google_status = result.status
                clean += proxy.google_clean
                await self.storage.record_l2(proxy.id, result.status, score(proxy))
            await self.storage.record_checks("l2", clean, len(batch))
            await self.storage.commit()
        log.info("l2 sweep", extra={"checked": len(batch), "search_ok": clean})
        await self.rebuild_pool()

    async def _yt_once(self) -> None:
        """Whether a live proxy can actually load YouTube, which is what the
        `target=` filter promises. Two page loads per proxy, so it stays on the hot
        pool only and each proxy is re-tested at most every `yt_min_interval_sec`.

        The sweep ends in `rebuild_pool`: the flags it writes are the entire content of
        `?target=`, and without a rebuild they sat in the database until some other
        queue happened to refresh the pool the API answers from.
        """
        async with self._db_lock:
            batch = await self.storage.fetch_yt_due(
                self.settings.queues.yt_batch,
                _ago(self.settings.checker.yt_min_interval_sec),
            )
        if not batch:
            return
        results = await gather_limited(
            [self.checker.check_youtube(p.host, p.port, p.protocol) for p in batch],
            self.settings.queues.yt_concurrency,
        )
        rows: list[tuple] = []
        both = 0
        for proxy, result in zip(batch, results, strict=True):
            search_ok, channel_ok = (False, False) if isinstance(result, BaseException) else result
            rows.append((proxy.id, search_ok, channel_ok))
            both += search_ok and channel_ok
        async with self._db_lock:
            await self.storage.record_yt_many(rows, self.settings.queues.yt_fail_grace)
            await self.storage.record_checks("yt", both, len(batch))
            await self.storage.commit()
        log.info("youtube sweep", extra={"checked": len(batch), "dual_clean": both})
        await self.rebuild_pool()

    async def _run_l1(
        self, batch: Sequence[Proxy], concurrency: int, queue: str, prefilter: bool = False
    ) -> None:
        started = time.monotonic()
        results = await gather_limited(
            [
                self.checker.check_l1(
                    p.host,
                    p.port,
                    None if p.protocol == "unknown" else p.protocol,
                    prefilter=prefilter,
                )
                for p in batch
            ],
            concurrency,
        )
        alive = 0
        updates: list[tuple] = []
        async with self._db_lock:
            for proxy, result in zip(batch, results, strict=True):
                if isinstance(result, BaseException):
                    result = L1Result(ok=False)
                alive += result.ok
                updates.append(await self._apply_l1(proxy, result))
            await self.storage.record_l1_many(updates)
            await self.storage.record_checks("l1", alive, len(batch))
            await self.storage.commit()
        log.info(
            "l1 sweep",
            extra={
                "queue": queue,
                "checked": len(batch),
                "alive": alive,
                "sec": round(time.monotonic() - started, 1),
            },
        )

    async def _apply_l1(self, proxy: Proxy, result: L1Result) -> tuple:
        """Returns the row `record_l1_many` needs, so a sweep writes in two statements."""
        if result.ok and result.protocol and result.protocol != proxy.protocol:
            # The handshake, not the source's file name, decides the protocol. Resolving
            # may merge this row into an existing one, so keep the surviving id.
            proxy.id = await self.storage.resolve_protocol(
                proxy.id, proxy.host, proxy.port, result.protocol
            )
            proxy.protocol = result.protocol
        history = push_history(proxy.history, result.ok)
        ratio = uptime_ratio(history)
        proxy.history = history
        proxy.uptime_ratio = ratio
        if result.ok:
            proxy.latency_ms = result.latency_ms
        return (proxy.id, result.ok, result.latency_ms, history, ratio, score(proxy, ratio))

    # ─── enrichment ────────────────────────────────────────────────────────

    async def _enrich_once(self) -> None:
        """Geo is a local mmdb lookup, so it is cheap and runs for every live proxy.
        Anonymity costs two requests through the proxy, so it runs once per proxy."""
        async with self._db_lock:
            pending_geo = await self.storage.fetch_pending_geo(5000)
            for proxy in pending_geo:
                fields = self.geo.lookup(proxy.host)
                if fields:
                    await self.storage.set_geo(proxy.id, fields)
                    for key, value in fields.items():
                        setattr(proxy, key, value)
                elif self.geo.ready:
                    await self.storage.set_geo(proxy.id, {"asn_type": "residential"})
            if pending_geo:
                await self.storage.commit()

            pending_anon = await self.storage.fetch_pending_anonymity(60)

        if pending_anon:
            levels = await gather_limited(
                [self.checker.check_anonymity(p.host, p.port, p.protocol) for p in pending_anon],
                30,
            )
            async with self._db_lock:
                for proxy, level in zip(pending_anon, levels, strict=True):
                    if isinstance(level, BaseException):
                        level = None
                    await self.storage.set_anonymity(proxy.id, level)
                await self.storage.commit()

    async def _maintenance_once(self) -> None:
        async with self._db_lock:
            removed = await self.storage.prune(
                self.settings.queues.fail_streak_delete, self.settings.queues.stale_unseen_days
            )
            await self.storage.recompute_source_totals()
        if removed:
            log.info("pruned dead proxies", extra={"removed": removed})
        cutoff = time.time() - self.settings.app.rotation_cooldown_sec
        self._recently_served = {k: v for k, v in self._recently_served.items() if v > cutoff}

    async def _geo_refresh_once(self) -> None:
        await self.geo.refresh()

    # ─── hot pool ──────────────────────────────────────────────────────────

    async def rebuild_pool(self) -> None:
        async with self._db_lock:
            alive = await self.storage.fetch_alive()
        for proxy in alive:
            proxy.uptime_ratio = uptime_ratio(proxy.history)
            proxy.score = score(proxy, proxy.uptime_ratio)
        alive.sort(key=lambda p: p.score, reverse=True)
        self.pool = alive

    # ─── selection for the API ─────────────────────────────────────────────

    def pick(self, candidates: list[Proxy], top_n: int, cooldown_sec: int) -> Proxy | None:
        """Random pick from the top slice, skipping anything served in the last
        `cooldown_sec` — unless that would leave nothing to return."""
        if not candidates:
            return None
        now = time.time()
        top = candidates[:top_n]
        fresh = [p for p in top if now - self._recently_served.get(p.id, 0.0) >= cooldown_sec]
        pool = fresh or top
        chosen = random.choice(pool)  # noqa: S311 — rotation, not cryptography
        self._recently_served[chosen.id] = now
        return chosen

    async def report(self, host: str, port: int, protocol: str, ok: bool) -> bool:
        """Client feedback beats our own probes, so it also forces a recheck — but the
        recheck happens on `_report_once`, not here.

        This used to run the L1 probe and a full `rebuild_pool` inline, before
        answering. A dead proxy takes the whole `l1_total_timeout_sec` to prove itself
        dead, so reporting one cost the caller several seconds. The Lead Engine client
        measured over six seconds, wired a short timeout around the call, and then muted
        its own reporting after a few of those — so the pool stopped hearing which
        proxies its heaviest user had burned, which is exactly the signal it most wants.
        Answering immediately and rechecking in the background costs the pool nothing
        and gets the feedback back.
        """
        async with self._db_lock:
            updated = await self.storage.apply_client_report(host, port, protocol, ok)
            proxy = await self.storage.find(host, port, protocol)
        if not updated or proxy is None:
            return False
        if not ok and len(self._report_recheck) < _REPORT_RECHECK_CAP:
            # Keyed by id: a client burning through a batch reports the same proxy
            # more than once, and one recheck settles all of them.
            self._report_recheck[proxy.id] = proxy
        return True

    async def _report_once(self) -> None:
        """Rechecks what clients reported dead, in one batch instead of one at a time.

        Batching matters as much as the deferral: every recheck ends in a
        `rebuild_pool`, which reads and re-sorts the entire live pool, and doing that
        per report would make a busy client the most expensive thing in the process.
        """
        if not self._report_recheck:
            return
        batch = list(self._report_recheck.values())
        self._report_recheck.clear()
        await self._run_l1(batch, min(len(batch), self.settings.queues.hot_concurrency), "report")
        await self.rebuild_pool()
