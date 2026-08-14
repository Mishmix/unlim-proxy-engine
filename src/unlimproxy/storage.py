"""SQLite persistence. One file, WAL mode, no external services.

The API never reads from here — it serves from the in-memory hot pool built by the
scheduler. SQLite is the durable record and the work queue.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite

from .models import Candidate, Proxy, SourceStats

log = logging.getLogger(__name__)

HISTORY_WINDOW = 20

TABLES = """
CREATE TABLE IF NOT EXISTS proxies (
  id INTEGER PRIMARY KEY,
  host TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
  country TEXT, country_name TEXT, city TEXT,
  asn TEXT, asn_org TEXT, asn_type TEXT,
  anonymity TEXT,
  latency_ms INTEGER,
  google_status TEXT,
  google_clean INTEGER NOT NULL DEFAULT 0,
  score REAL NOT NULL DEFAULT 0,
  alive INTEGER NOT NULL DEFAULT 0,
  alive_streak INTEGER NOT NULL DEFAULT 0,
  fail_streak INTEGER NOT NULL DEFAULT 0,
  checks_total INTEGER NOT NULL DEFAULT 0,
  checks_ok INTEGER NOT NULL DEFAULT 0,
  client_reports_ok INTEGER NOT NULL DEFAULT 0,
  client_reports_fail INTEGER NOT NULL DEFAULT 0,
  first_seen_at TEXT, last_seen_in_source_at TEXT,
  last_check_at TEXT, last_verified_at TEXT, last_l2_at TEXT,
  source TEXT,
  history TEXT NOT NULL DEFAULT '',
  last_report_fail_at TEXT,
  uptime_ratio REAL NOT NULL DEFAULT 0,
  geo_done INTEGER NOT NULL DEFAULT 0,
  anonymity_done INTEGER NOT NULL DEFAULT 0,
  parser_clean INTEGER NOT NULL DEFAULT 0,
  aiohttp_clean INTEGER NOT NULL DEFAULT 0,
  dual_clean INTEGER NOT NULL DEFAULT 0,
  last_yt_at TEXT,
  yt_fail_streak INTEGER NOT NULL DEFAULT 0,
  UNIQUE(host, port, protocol)
);

CREATE TABLE IF NOT EXISTS sources (
  name TEXT PRIMARY KEY,
  url TEXT,
  etag TEXT,
  last_fetch_at TEXT,
  fetched_total INTEGER NOT NULL DEFAULT 0,
  alive_total INTEGER NOT NULL DEFAULT 0,
  google_clean_total INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  ok INTEGER NOT NULL
);

"""

# Kept apart from the tables: an index over a column that only `_migrate` adds cannot
# be created until that migration has run.
INDEXES = """
-- The old cold index was `(last_check_at) WHERE last_check_at IS NULL`. Its name
-- would survive `IF NOT EXISTS` untouched on an existing database, so it is dropped
-- by name and the carousel gets its own.
DROP INDEX IF EXISTS idx_proxies_cold;
-- Predicate and column match `fetch_cold` exactly, so the window is an index walk
-- rather than a sort of three quarters of a million rows under the lock.
CREATE INDEX IF NOT EXISTS idx_proxies_carousel
  ON proxies(last_check_at) WHERE checks_ok = 0 AND alive = 0;
CREATE INDEX IF NOT EXISTS idx_proxies_alive ON proxies(alive, fail_streak, last_check_at);
CREATE INDEX IF NOT EXISTS idx_proxies_l2 ON proxies(alive, last_l2_at);
CREATE INDEX IF NOT EXISTS idx_proxies_yt ON proxies(alive, last_yt_at);
CREATE INDEX IF NOT EXISTS idx_checks_at ON checks(at);
"""

# `CREATE TABLE IF NOT EXISTS` does nothing to a database that already exists, so
# every column added after the first release has to be introduced here as well.
_ADDED_COLUMNS = {
    "parser_clean": "INTEGER NOT NULL DEFAULT 0",
    "aiohttp_clean": "INTEGER NOT NULL DEFAULT 0",
    "dual_clean": "INTEGER NOT NULL DEFAULT 0",
    "last_yt_at": "TEXT",
    "yt_fail_streak": "INTEGER NOT NULL DEFAULT 0",
}

_UPSERT = """
INSERT INTO proxies (host, port, protocol, source, first_seen_at, last_seen_in_source_at,
                     country, city, asn, asn_org, anonymity)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(host, port, protocol) DO UPDATE SET
  last_seen_in_source_at = excluded.last_seen_in_source_at,
  country  = COALESCE(proxies.country,  excluded.country),
  city     = COALESCE(proxies.city,     excluded.city),
  asn      = COALESCE(proxies.asn,      excluded.asn),
  asn_org  = COALESCE(proxies.asn_org,  excluded.asn_org)
"""


def utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def age_sec(value: str | None) -> int | None:
    ts = parse_ts(value)
    return None if ts is None else int((datetime.now(UTC) - ts).total_seconds())


class Storage:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._db: aiosqlite.Connection | None = None

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Storage.open() was not awaited")
        return self._db

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(self.path, timeout=30)
        self._db.row_factory = sqlite3.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA busy_timeout=30000")
        await self._db.execute("PRAGMA temp_store=MEMORY")
        # 64 MB of page cache against a 240 MB database. The default is 2 MB, which
        # sends nearly every read to disk — and reads here happen under the lock that
        # `/v1/report` and every check queue wait on, so page cache misses are latency
        # everyone feels. Bounded and predictable, against a 1 GB container limit.
        await self._db.execute("PRAGMA cache_size=-65536")
        await self._db.executescript(TABLES)
        await self._migrate()
        await self._db.executescript(INDEXES)
        await self._db.commit()

    async def _migrate(self) -> None:
        rows = await self._rows("PRAGMA table_info(proxies)")
        present = {row["name"] for row in rows}
        for column, spec in _ADDED_COLUMNS.items():
            if column not in present:
                await self.db.execute(f"ALTER TABLE proxies ADD COLUMN {column} {spec}")
                log.info("added column", extra={"column": column})

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    # ─── candidates ────────────────────────────────────────────────────────

    async def upsert_candidates(self, candidates: Sequence[Candidate]) -> int:
        """Insert new `(host, port, protocol)` triples; refresh `last_seen_in_source_at`
        for known ones. Returns how many rows were newly created."""
        if not candidates:
            return 0
        now = utcnow()
        rows = [
            (
                c.host,
                c.port,
                c.protocol or "unknown",
                c.source,
                now,
                now,
                c.country,
                c.city,
                c.asn,
                c.asn_org,
                c.anonymity,
            )
            for c in candidates
        ]
        before = await self.count("SELECT COUNT(*) FROM proxies")
        await self.db.executemany(_UPSERT, rows)
        await self.db.commit()
        after = await self.count("SELECT COUNT(*) FROM proxies")
        return after - before

    async def resolve_protocol(self, proxy_id: int, host: str, port: int, protocol: str) -> int:
        """Rewrite a row whose protocol was `unknown` once the handshake settled it.

        Returns the id that represents this proxy from now on. A popular proxy usually
        arrives twice — labelled by a trustworthy source and unlabelled by a bulk dump —
        so the resolved triple often already exists. In that case the placeholder is
        dropped and the caller must record the check against the surviving row, or the
        successful check is lost entirely.
        """
        try:
            await self.db.execute(
                "UPDATE proxies SET protocol = ? WHERE id = ?", (protocol, proxy_id)
            )
            return proxy_id
        except sqlite3.IntegrityError:
            rows = await self._rows(
                "SELECT id FROM proxies WHERE host = ? AND port = ? AND protocol = ?",
                (host, port, protocol),
            )
            await self.db.execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
            return rows[0]["id"] if rows else proxy_id

    # ─── check results ─────────────────────────────────────────────────────

    async def record_l1(
        self,
        proxy_id: int,
        ok: bool,
        latency_ms: int | None,
        history: str,
        uptime_ratio: float,
        score: float,
    ) -> None:
        await self.record_l1_many([(proxy_id, ok, latency_ms, history, uptime_ratio, score)])

    async def record_l1_many(self, results: Sequence[tuple]) -> None:
        """One round trip per outcome instead of one per proxy.

        A cold sweep applies thousands of these at a time and aiosqlite charges a
        thread hand-off for every statement, so the per-row cost is the transport,
        not the SQL. Entries are `(proxy_id, ok, latency_ms, history, uptime_ratio,
        score)`.

        `google_clean` is deliberately left alone on failure: it records the last L2
        verdict, and a proxy is only re-tested every ten minutes. Clearing it on every
        failed liveness check would wipe the flag on the first flap — with a five-minute
        half-life that is nearly every proxy — and nothing could restore it until the L2
        window reopened. Freshness is carried by `last_verified_at`.
        """
        if not results:
            return
        now = utcnow()
        ok_rows = [
            (r[2], now, now, r[3], r[4], r[5], r[0]) for r in results if r[1]
        ]
        fail_rows = [(now, r[3], r[4], r[5], r[0]) for r in results if not r[1]]
        if ok_rows:
            await self.db.executemany(
                """UPDATE proxies SET alive = 1, alive_streak = alive_streak + 1,
                       fail_streak = 0, checks_total = checks_total + 1,
                       checks_ok = checks_ok + 1, latency_ms = ?, last_check_at = ?,
                       last_verified_at = ?, history = ?, uptime_ratio = ?, score = ?
                   WHERE id = ?""",
                ok_rows,
            )
        if fail_rows:
            await self.db.executemany(
                """UPDATE proxies SET alive = 0, alive_streak = 0,
                       fail_streak = fail_streak + 1, checks_total = checks_total + 1,
                       last_check_at = ?, history = ?, uptime_ratio = ?, score = ?
                   WHERE id = ?""",
                fail_rows,
            )

    async def record_yt_many(self, results: Sequence[tuple], fail_grace: int) -> None:
        """Entries are `(proxy_id, search_ok, channel_ok)`.

        A probe that reached YouTube at all writes its verdict straight through. A
        probe that reached nothing does *not* clear the flags immediately: it only
        counts, and the flags survive until `fail_grace` consecutive misses.

        Without that grace the `?target=youtube` set collapsed to zero on a regular
        beat, and the client had to fall back to less-verified proxies to keep working.
        Two page loads through a free proxy fail for reasons that have nothing to do
        with YouTube reachability, and the set is re-swept far more often than the
        proxies in it actually change, so one miss is noise. Two in a row is a verdict.

        SQLite reads every right-hand side from the pre-update row, so `yt_fail_streak
        + 1` below is this probe's streak in all four columns.
        """
        if not results:
            return
        now = utcnow()
        await self.db.executemany(
            f"""UPDATE proxies SET
                    yt_fail_streak = CASE WHEN ?3 THEN 0 ELSE yt_fail_streak + 1 END,
                    parser_clean = CASE WHEN ?3 THEN ?1
                        WHEN yt_fail_streak + 1 >= {fail_grace} THEN 0
                        ELSE parser_clean END,
                    aiohttp_clean = CASE WHEN ?3 THEN ?2
                        WHEN yt_fail_streak + 1 >= {fail_grace} THEN 0
                        ELSE aiohttp_clean END,
                    dual_clean = CASE WHEN ?3 THEN (?1 AND ?2)
                        WHEN yt_fail_streak + 1 >= {fail_grace} THEN 0
                        ELSE dual_clean END,
                    last_yt_at = ?4
                WHERE id = ?5""",
            [(int(s), int(c), int(s or c), now, pid) for pid, s, c in results],
        )

    async def fetch_yt_due(self, limit: int, older_than: str) -> list[Proxy]:
        """Never-probed proxies first, then the longest-unseen.

        The old ordering led with `dual_clean DESC`, which spent every sweep
        re-testing the proxies already in the set before it would look at a single new
        candidate. The set could therefore only shrink: it re-litigated its own members
        and never grew. Freshness is what re-probing is for, so freshness is what
        orders the queue.
        """
        return await self._proxies(
            """SELECT * FROM proxies
               WHERE alive = 1 AND (last_yt_at IS NULL OR last_yt_at < ?)
               ORDER BY last_yt_at, score DESC LIMIT ?""",
            (older_than, limit),
        )

    async def record_l2(self, proxy_id: int, status: str, score: float) -> None:
        await self.db.execute(
            """UPDATE proxies SET google_status = ?, google_clean = ?, last_l2_at = ?,
                   score = ? WHERE id = ?""",
            (status, int(status == "SEARCH_OK"), utcnow(), score, proxy_id),
        )

    async def record_checks(self, kind: str, ok: int, total: int) -> None:
        now = utcnow()
        await self.db.execute(
            "INSERT INTO checks (at, kind, ok) VALUES (?, ?, ?)", (now, kind, ok)
        )
        await self.db.execute(
            "INSERT INTO checks (at, kind, ok) VALUES (?, ?, ?)", (now, f"{kind}_total", total)
        )

    # Every geo lookup can produce a different subset of keys, so writing them one row
    # at a time needs one statement per row. `GEO_COLUMNS` fixes the shape instead:
    # a missing key writes NULL through COALESCE, which keeps whatever is already
    # there, and the whole batch becomes a single `executemany`.
    GEO_COLUMNS = ("country", "country_name", "city", "asn", "asn_org", "asn_type")

    async def set_geo_many(self, rows: Sequence[tuple[int, dict[str, Any]]]) -> None:
        """One statement for the whole batch.

        This used to be one `UPDATE` per proxy, issued inside the scheduler's database
        lock. aiosqlite charges a thread hand-off per statement, so a batch of five
        thousand held the lock that every queue and every `/v1/stats` waits on for tens
        of seconds — measured at 29.7 s on a `POST /v1/report` that does nothing but a
        lookup and an update. The pool used to be small enough for it not to show.
        """
        if not rows:
            return
        assignments = ", ".join(f"{c} = COALESCE(?, {c})" for c in self.GEO_COLUMNS)
        await self.db.executemany(
            f"UPDATE proxies SET {assignments}, geo_done = 1 WHERE id = ?",
            [
                (*(fields.get(c) for c in self.GEO_COLUMNS), proxy_id)
                for proxy_id, fields in rows
            ],
        )

    async def set_anonymity(self, proxy_id: int, level: str | None) -> None:
        await self.db.execute(
            "UPDATE proxies SET anonymity = COALESCE(?, anonymity), anonymity_done = 1 "
            "WHERE id = ?",
            (level, proxy_id),
        )

    async def apply_client_report(self, host: str, port: int, protocol: str, ok: bool) -> int:
        column = "client_reports_ok" if ok else "client_reports_fail"
        stamp = "last_report_fail_at = NULL" if ok else "last_report_fail_at = ?"
        params: tuple[Any, ...] = (host, port, protocol) if ok else (utcnow(), host, port, protocol)
        cursor = await self.db.execute(
            f"UPDATE proxies SET {column} = {column} + 1, {stamp} "
            "WHERE host = ? AND port = ? AND protocol = ?",
            params,
        )
        await self.db.commit()
        return cursor.rowcount

    # ─── queue selection ───────────────────────────────────────────────────

    async def fetch_cold(self, limit: int) -> list[Proxy]:
        """The carousel: candidates that have never answered, longest wait first.

        `checks_ok = 0`, not `last_check_at IS NULL`. That one predicate was the whole
        bottleneck. A free proxy blinks — it answers, vanishes for an hour, answers
        again — and selecting on `last_check_at IS NULL` gave every address exactly one
        sample in its lifetime. The ~99 % that missed that single sample fell out of
        every queue at once, because `warm` and `quarantine` both demand
        `checks_ok > 0`: an address that never answered on its first try belonged
        nowhere and was never probed again.

        Measured on the live 782 530-row database: 782 127 rows sat in no queue at all,
        the service ran 1.7 L1 checks a second against a capacity of a hundred, and the
        pool was a 187-proxy fossil of one long-finished pass. A direct probe of 8 000
        of those orphans from the server found 42 % reachable over TCP and 6.17 % fully
        alive — roughly 48 000 live proxies already in the database, invisible.

        So this is not a backlog to drain. Every address that has not yet proved itself
        keeps coming round, and one that was dead an hour ago is found the next time it
        wakes up. An address leaves only by answering, into `hot`, or by `prune` at
        `fail_streak_delete`.

        No source striding and no protocol ordering. Both existed to decide *which*
        rows a one-shot drain would ever reach, and a carousel reaches all of them, so
        the only thing left to order by is who has waited longest. They were not free
        either: `ROW_NUMBER() OVER (PARTITION BY source …)` cannot use an index, and on
        this database it made the window query take **7.3 s** against **0.45 s** for
        the plain ordering — while holding the lock every other queue needs. NULL sorts
        first in SQLite, so a freshly scraped candidate still jumps ahead of the round.

        `INDEXED BY` because the planner gets this one wrong. Left to itself it takes
        `idx_proxies_yt` for the `alive = 0` seek and then builds a temp B-tree for the
        ordering — 0.40 s, and growing with the table. Walking the carousel index
        instead is 0.063 s and stops at the LIMIT. `ANALYZE` does not change its mind.
        The hint is safe because `INDEXES` creates that index on every `open`.
        """
        return await self._proxies(
            """SELECT * FROM proxies INDEXED BY idx_proxies_carousel
               WHERE checks_ok = 0 AND alive = 0
               ORDER BY last_check_at LIMIT ?""",
            (limit,),
        )

    async def fetch_hot(self, limit: int) -> list[Proxy]:
        return await self._proxies(
            """SELECT * FROM proxies WHERE alive = 1 AND alive_streak > 0
               ORDER BY last_check_at ASC LIMIT ?""",
            (limit,),
        )

    async def fetch_warm(self, limit: int, max_fail_streak: int) -> list[Proxy]:
        return await self._proxies(
            """SELECT * FROM proxies
               WHERE alive = 0 AND fail_streak BETWEEN 1 AND ? AND checks_ok > 0
               ORDER BY last_check_at ASC LIMIT ?""",
            (max_fail_streak, limit),
        )

    async def fetch_quarantine(
        self, limit: int, min_fail_streak: int, older_than: str
    ) -> list[Proxy]:
        return await self._proxies(
            """SELECT * FROM proxies
               WHERE fail_streak >= ? AND checks_ok > 0 AND last_check_at < ?
               ORDER BY last_check_at ASC LIMIT ?""",
            (min_fail_streak, older_than, limit),
        )

    async def fetch_l2_due(self, limit: int, older_than: str) -> list[Proxy]:
        return await self._proxies(
            """SELECT * FROM proxies
               WHERE alive = 1 AND (last_l2_at IS NULL OR last_l2_at < ?)
               ORDER BY google_clean DESC, last_l2_at IS NOT NULL, score DESC LIMIT ?""",
            (older_than, limit),
        )

    async def fetch_pending_geo(self, limit: int) -> list[Proxy]:
        return await self._proxies(
            "SELECT * FROM proxies WHERE alive = 1 AND geo_done = 0 LIMIT ?", (limit,)
        )

    async def fetch_pending_anonymity(self, limit: int) -> list[Proxy]:
        return await self._proxies(
            "SELECT * FROM proxies WHERE alive = 1 AND anonymity_done = 0 LIMIT ?", (limit,)
        )

    async def fetch_alive(self) -> list[Proxy]:
        """Everything the API may serve — the source of the in-memory hot pool."""
        return await self._proxies("SELECT * FROM proxies WHERE alive = 1")

    async def find(self, host: str, port: int, protocol: str) -> Proxy | None:
        rows = await self._rows(
            "SELECT * FROM proxies WHERE host = ? AND port = ? AND protocol = ?",
            (host, port, protocol),
        )
        return Proxy.from_row(rows[0]) if rows else None

    # ─── maintenance ───────────────────────────────────────────────────────

    async def prune(self, proven_stale_days: int, stale_unseen_days: int) -> int:
        """Two different deaths, and they need two different rules — both in time.

        A proxy that *worked* is retired when it has not worked for
        `proven_stale_days`. This used to count consecutive failed probes instead, and
        that was a bug waiting for the sweep rate to change: the same threshold of 10
        meant five hours at one probe per thirty minutes and twenty minutes at one
        probe per two. Retention is a claim about proxies — "gone for three days is
        gone" — so it has no business being expressed in units of our own sweep rate.

        A candidate that has never answered is retired by its sources instead: when no
        list has carried it for `stale_unseen_days`, it is gone. That is the honest
        signal, because it is the one that does not depend on our own probe luck. The
        rule stays scoped away from `checks_ok = 0` for the same reason as before —
        the carousel re-tries everything, and the next scrape would put every deleted
        address straight back at the front of the queue, having learned nothing.
        """
        cutoff = (datetime.now(UTC) - timedelta(days=stale_unseen_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        proven_cutoff = (datetime.now(UTC) - timedelta(days=proven_stale_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cursor = await self.db.execute(
            """DELETE FROM proxies
               WHERE (checks_ok > 0 AND alive = 0
                      AND COALESCE(last_verified_at, '') < ?)
                  OR (checks_ok = 0 AND alive = 0 AND last_seen_in_source_at < ?)""",
            (proven_cutoff, cutoff),
        )
        await self.db.execute("DELETE FROM checks WHERE at < ?", (_minutes_ago(60),))
        await self.db.commit()
        return cursor.rowcount

    # ─── sources ───────────────────────────────────────────────────────────

    async def load_sources(self) -> dict[str, SourceStats]:
        rows = await self._rows("SELECT * FROM sources", ())
        return {
            r["name"]: SourceStats(
                name=r["name"],
                url=r["url"] or "",
                etag=r["etag"],
                last_fetch_at=r["last_fetch_at"],
                fetched_total=r["fetched_total"],
                alive_total=r["alive_total"],
                google_clean_total=r["google_clean_total"],
            )
            for r in rows
        }

    async def save_source(self, stats: SourceStats) -> None:
        await self.db.execute(
            """INSERT INTO sources (name, url, etag, last_fetch_at, fetched_total,
                                    alive_total, google_clean_total)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET
                 url = excluded.url, etag = excluded.etag,
                 last_fetch_at = excluded.last_fetch_at,
                 fetched_total = excluded.fetched_total,
                 alive_total = excluded.alive_total,
                 google_clean_total = excluded.google_clean_total""",
            (
                stats.name,
                stats.url,
                stats.etag,
                stats.last_fetch_at,
                stats.fetched_total,
                stats.alive_total,
                stats.google_clean_total,
            ),
        )
        await self.db.commit()

    async def recompute_source_totals(self) -> None:
        """Recount alive/google-clean per source from the proxies table.

        Recomputing is idempotent; incrementing counters from check results would
        drift as soon as a proxy is rechecked or pruned.
        """
        await self.db.execute(
            """UPDATE sources SET
                 alive_total = COALESCE((SELECT COUNT(*) FROM proxies p
                     WHERE p.source = sources.name AND p.checks_ok > 0), 0),
                 google_clean_total = COALESCE((SELECT COUNT(*) FROM proxies p
                     WHERE p.source = sources.name AND p.google_status = 'SEARCH_OK'), 0)"""
        )
        await self.db.commit()

    # ─── stats ─────────────────────────────────────────────────────────────

    async def pool_counts(self, fail_streak_quarantine: int) -> dict[str, int]:
        row = (
            await self._rows(
                # `carousel` is what the cold queue can actually serve, and it is the
                # honest backlog reading now that the queue re-tries. `unchecked` stays
                # as the narrower "never tried even once", which sits near zero.
                """SELECT COUNT(*) AS total,
                          SUM(last_check_at IS NULL) AS unchecked,
                          SUM(checks_ok = 0 AND alive = 0) AS carousel,
                          SUM(alive) AS alive,
                          SUM(alive AND google_clean) AS google_clean,
                          SUM(alive AND dual_clean) AS youtube_clean,
                          SUM(fail_streak >= ? AND checks_ok > 0) AS quarantine
                   FROM proxies""",
                (fail_streak_quarantine,),
            )
        )[0]
        return {
            k: int(row[k] or 0)
            for k in (
                "total",
                "unchecked",
                "carousel",
                "alive",
                "google_clean",
                "youtube_clean",
                "quarantine",
            )
        }

    async def group_counts(self, column: str) -> dict[str, int]:
        if column not in {"protocol", "country", "anonymity", "asn_type"}:
            raise ValueError(column)
        rows = await self._rows(
            f"SELECT {column} AS k, COUNT(*) AS n FROM proxies WHERE alive = 1 "
            f"AND {column} IS NOT NULL GROUP BY k ORDER BY n DESC",
            (),
        )
        return {r["k"]: r["n"] for r in rows}

    async def checks_per_min(self) -> dict[str, int]:
        cutoff = _minutes_ago(5)
        rows = await self._rows(
            "SELECT kind, SUM(ok) AS n FROM checks WHERE at >= ? GROUP BY kind", (cutoff,)
        )
        counts = {r["kind"]: int(r["n"] or 0) for r in rows}
        # `record_checks` writes two rows per sweep: `<kind>` carries the successes and
        # `<kind>_total` the attempts, so a yield can be read off the pair.
        return {
            "l1_per_min": counts.get("l1_total", 0) // 5,
            "l1_alive_per_min": counts.get("l1", 0) // 5,
            "l2_per_min": counts.get("l2_total", 0) // 5,
            "l2_clean_per_min": counts.get("l2", 0) // 5,
            "yt_per_min": counts.get("yt_total", 0) // 5,
            "yt_clean_per_min": counts.get("yt", 0) // 5,
        }

    async def count(self, sql: str, params: Iterable[Any] = ()) -> int:
        async with self.db.execute(sql, tuple(params)) as cursor:
            row = await cursor.fetchone()
        return int(row[0]) if row else 0

    async def commit(self) -> None:
        await self.db.commit()

    async def _rows(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        async with self.db.execute(sql, tuple(params)) as cursor:
            return list(await cursor.fetchall())

    async def _proxies(self, sql: str, params: Iterable[Any] = ()) -> list[Proxy]:
        return [Proxy.from_row(r) for r in await self._rows(sql, params)]




def _minutes_ago(minutes: int) -> str:
    return (datetime.now(UTC) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def push_history(history: str, ok: bool) -> str:
    return (history + ("1" if ok else "0"))[-HISTORY_WINDOW:]
