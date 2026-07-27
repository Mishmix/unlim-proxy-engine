"""Fetch every configured source concurrently, parse, dedupe, store.

Sources are polled with `If-None-Match`; a 304 costs one request and zero parsing.
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp

from .config import Settings, SourceCfg
from .models import Candidate, ScrapeResult, SourceStats
from .parsers import parse
from .storage import Storage, utcnow

log = logging.getLogger(__name__)


class Scraper:
    def __init__(self, settings: Settings, storage: Storage) -> None:
        self.settings = settings
        self.storage = storage
        self._semaphore = asyncio.Semaphore(settings.scraper.concurrency)

    async def fetch_all(self) -> tuple[list[SourceCfg], list[ScrapeResult]]:
        """Network only. Kept apart from `store` so the scheduler does not hold the
        database lock across 84 HTTP requests — that stalled every check queue for
        about 25 seconds out of every 180."""
        stats = await self.storage.load_sources()
        sources = sorted(self.settings.enabled_sources, key=lambda s: (s.priority, s.name))
        timeout = aiohttp.ClientTimeout(total=self.settings.scraper.timeout_sec)
        headers = {"User-Agent": self.settings.checker.user_agent}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            results = await asyncio.gather(
                *(
                    self._fetch_source(session, s, stats[s.name].etag if s.name in stats else None)
                    for s in sources
                )
            )
        return sources, results

    async def store(
        self, sources: list[SourceCfg], results: list[ScrapeResult]
    ) -> list[ScrapeResult]:
        stats = await self.storage.load_sources()

        # Insert in priority order so the best source wins the `source` attribution.
        seen: set[tuple[str, int, str]] = set()
        for source, result in zip(sources, results, strict=True):
            unique: list[Candidate] = []
            for candidate in result.candidates:
                key = (candidate.host, candidate.port, candidate.protocol or "unknown")
                if key not in seen:
                    seen.add(key)
                    unique.append(candidate)
            result.new = await self.storage.upsert_candidates(unique)
            result.candidates = []

            entry = stats.get(source.name)
            if entry is None:
                entry = stats[source.name] = SourceStats(name=source.name, url=source.url)
            entry.url = source.url
            if not result.not_modified and result.error is None:
                entry.etag = result.etag
                entry.fetched_total += result.new
            entry.last_fetch_at = utcnow()
            await self.storage.save_source(entry)

        await self.storage.recompute_source_totals()
        total_fetched = sum(r.fetched for r in results)
        log.info(
            "scrape finished",
            extra={
                "sources": len(sources),
                "fetched": total_fetched,
                "unique": len(seen),
                "new": sum(r.new for r in results),
                "not_modified": sum(r.not_modified for r in results),
                "errors": sum(r.error is not None for r in results),
            },
        )
        return results

    async def _fetch_source(
        self, session: aiohttp.ClientSession, source: SourceCfg, etag: str | None
    ) -> ScrapeResult:
        result = ScrapeResult(source=source.name)
        async with self._semaphore:
            for page in range(1, max(source.pages, 1) + 1):
                url = source.url.replace("{page}", str(page))
                try:
                    body, new_etag, not_modified = await self._get(
                        session, url, etag if page == 1 else None
                    )
                except (TimeoutError, aiohttp.ClientError, ValueError) as exc:
                    result.error = f"{type(exc).__name__}: {exc}"
                    log.warning(
                        "source fetch failed",
                        extra={"source": source.name, "err": result.error},
                    )
                    break
                if not_modified:
                    result.not_modified = True
                    break
                if page == 1:
                    result.etag = new_etag
                candidates = parse(source, body)
                result.candidates.extend(candidates)
                result.fetched += len(candidates)
                if not candidates:
                    break
        return result

    async def _get(
        self, session: aiohttp.ClientSession, url: str, etag: str | None
    ) -> tuple[str, str | None, bool]:
        headers = {"If-None-Match": etag} if etag else {}
        async with session.get(url, headers=headers) as response:
            if response.status == 304:
                return "", etag, True
            response.raise_for_status()
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.content.iter_chunked(65536):
                size += len(chunk)
                if size > self.settings.scraper.max_bytes:
                    raise ValueError(f"response exceeds {self.settings.scraper.max_bytes} bytes")
                chunks.append(chunk)
            body = b"".join(chunks).decode("utf-8", errors="replace")
            return body, response.headers.get("ETag"), False


