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

# How many rounds of the cold queue a source has to sit out between its own candidates.
# 1 means it appears in every round; the worst sources appear in one round out of 40.
_BEST_STRIDE, _WORST_STRIDE, _UNRANKED_STRIDE, _DEAD_STRIDE = 1, 8, 8, 40


def _cold_stride(weight: float, best: float) -> int:
    """How many rounds a source sits out between its own candidates.

    Pure round-robin samples every source, which is what a cold start needs, but it
    also gives a dump that has proven worthless exactly as many slots as the best
    curated feed. Pure rank ordering does the opposite and lets one source own the
    whole window. Striding is the middle: everyone appears, a source appears as often
    as its hit rate compares to the best one, and a source `cold_queue_weight` has
    zeroed appears rarely without ever being switched off — it still contributes
    unique addresses.

    The ratio is against the best weight rather than the rank position, so sources
    that have not been measured yet all share one weight and therefore one stride
    instead of being spread out by an ordering that means nothing.
    """
    if weight <= 0:
        return _DEAD_STRIDE
    if best <= 0:
        return _BEST_STRIDE
    return min(_WORST_STRIDE, max(_BEST_STRIDE, round(best / weight)))

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
CREATE INDEX IF NOT EXISTS idx_proxies_cold
  ON proxies(last_check_at) WHERE last_check_at IS NULL;
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

    async def record_yt(self, proxy_id: int, search_ok: bool, channel_ok: bool) -> None:
        await self.db.execute(
            """UPDATE proxies SET parser_clean = ?, aiohttp_clean = ?, dual_clean = ?,
                   last_yt_at = ? WHERE id = ?""",
            (
                int(search_ok),
                int(channel_ok),
                int(search_ok and channel_ok),
                utcnow(),
                proxy_id,
            ),
        )

    async def fetch_yt_due(self, limit: int, older_than: str) -> list[Proxy]:
        return await self._proxies(
            """SELECT * FROM proxies
               WHERE alive = 1 AND (last_yt_at IS NULL OR last_yt_at < ?)
               ORDER BY dual_clean DESC, last_yt_at IS NOT NULL, score DESC LIMIT ?""",
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

    async def set_geo(self, proxy_id: int, fields: dict[str, Any]) -> None:
        assignments = ", ".join(f"{k} = ?" for k in fields)
        await self.db.execute(
            f"UPDATE proxies SET {assignments}, geo_done = 1 WHERE id = ?",
            (*fields.values(), proxy_id),
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

    async def fetch_cold(self, limit: int, source_scores: dict[str, float]) -> list[Proxy]:
        """Never-checked candidates, one round of every source at a time, and within a
        round SOCKS5 → SOCKS4 → unknown → HTTP then by source hit rate (RESEARCH 1.2:
        32 % / 14.5 % / 1.0 %, and 1.4 on junk sources).

        Ordering by rank alone lets a single source own the whole window: on a live
        664 000-row backlog, a 20 000-row window went entirely to two sources and one
        of them spent 15 668 checks to return nothing. Ranking cannot fix that, because
        a source with no measured hit rate yet falls back to its configured priority
        and ties with a dozen others. `ROW_NUMBER` per source turns the window into
        rounds, so every source is sampled early enough for `cold_queue_weight` to
        learn what it is worth and demote it.

        All of it has to stay in SQL; re-sorting a pre-fetched window in Python cannot
        recover rows the window never contained.
        """
        ranked = sorted(source_scores, key=lambda name: -source_scores[name])
        if ranked:
            best = source_scores[ranked[0]]
            branches = " ".join(
                f"WHEN ? THEN {_cold_stride(source_scores[name], best)}" for name in ranked
            )
            stride = f"CASE source {branches} ELSE {_UNRANKED_STRIDE} END"
            params: tuple[Any, ...] = (*ranked, limit)
        else:
            stride, params = "1", (limit,)
        protocol_order = (
            "CASE protocol WHEN 'socks5' THEN 0 WHEN 'socks4' THEN 1 "
            "WHEN 'unknown' THEN 2 ELSE 3 END"
        )
        return await self._proxies(
            f"""SELECT * FROM (
                    SELECT *, ROW_NUMBER() OVER (
                        PARTITION BY source ORDER BY {protocol_order}, id
                    ) AS cold_round
                    FROM proxies WHERE last_check_at IS NULL
                )
                ORDER BY cold_round * ({stride}), {protocol_order}, id
                LIMIT ?""",
            params,
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

    async def prune(self, fail_streak_delete: int, stale_unseen_days: int) -> int:
        cutoff = (datetime.now(UTC) - timedelta(days=stale_unseen_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cursor = await self.db.execute(
            """DELETE FROM proxies
               WHERE fail_streak >= ?
                  OR (alive = 0 AND last_seen_in_source_at < ?)""",
            (fail_streak_delete, cutoff),
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
                """SELECT COUNT(*) AS total,
                          SUM(alive) AS alive,
                          SUM(alive AND google_clean) AS google_clean,
                          SUM(fail_streak >= ? AND checks_ok > 0) AS quarantine
                   FROM proxies""",
                (fail_streak_quarantine,),
            )
        )[0]
        return {k: int(row[k] or 0) for k in ("total", "alive", "google_clean", "quarantine")}

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
        return {
            "l1_per_min": counts.get("l1_total", 0) // 5,
            "l2_per_min": counts.get("l2_total", 0) // 5,
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
