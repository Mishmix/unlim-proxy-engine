"""The HTTP API.

Every response is served from the scheduler's in-memory pool, so a request costs a
list scan and no disk I/O.
"""

from __future__ import annotations

import csv
import io
import time
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, StringConstraints

from .config import Settings
from .models import Proxy
from .parsers import normalize_protocol
from .scheduler import Scheduler
from .scoring import source_score
from .storage import age_sec

Format = Literal["json", "txt", "csv"]
CountryCode = Annotated[str, StringConstraints(min_length=2, max_length=2, to_upper=True)]

CSV_COLUMNS = (
    "proxy",
    "protocol",
    "host",
    "port",
    "country",
    "city",
    "asn",
    "asn_org",
    "asn_type",
    "anonymity",
    "latency_ms",
    "google_clean",
    "score",
    "uptime_ratio",
    "last_verified_at",
    "age_sec",
)


class Filters(BaseModel):
    limit: int = 20
    protocol: list[str] = []
    country: list[str] = []
    exclude_country: list[str] = []
    max_latency_ms: int = 5000
    google_clean: bool = False
    anonymity: str | None = None
    asn_type: str | None = None
    min_score: float = 0.0
    max_age_sec: int = 300


class ReportBody(BaseModel):
    proxy: str = Field(description="`protocol://host:port`, exactly as the API returned it")
    ok: bool
    reason: str | None = None


def filters(
    limit: Annotated[int, Query(ge=1, le=500)] = 20,
    protocol: Annotated[list[Literal["http", "socks4", "socks5"]] | None, Query()] = None,
    country: Annotated[list[CountryCode] | None, Query()] = None,
    exclude_country: Annotated[list[CountryCode] | None, Query()] = None,
    max_latency_ms: Annotated[int, Query(ge=1)] = 5000,
    google_clean: bool = False,
    anonymity: Literal["elite", "anonymous", "transparent"] | None = None,
    asn_type: Literal["residential", "datacenter"] | None = None,
    min_score: Annotated[float, Query(ge=0, le=100)] = 0.0,
    max_age_sec: Annotated[int, Query(ge=1)] = 300,
) -> Filters:
    return Filters(
        limit=limit,
        protocol=protocol or [],
        country=[c.upper() for c in country or []],
        exclude_country=[c.upper() for c in exclude_country or []],
        max_latency_ms=max_latency_ms,
        google_clean=google_clean,
        anonymity=anonymity,
        asn_type=asn_type,
        min_score=min_score,
        max_age_sec=max_age_sec,
    )


def matches(proxy: Proxy, f: Filters) -> bool:
    if f.google_clean and not proxy.google_clean:
        return False
    if f.protocol and proxy.protocol not in f.protocol:
        return False
    if f.country and (proxy.country or "") not in f.country:
        return False
    if f.exclude_country and (proxy.country or "") in f.exclude_country:
        return False
    if proxy.latency_ms is None or proxy.latency_ms > f.max_latency_ms:
        return False
    if f.anonymity and proxy.anonymity != f.anonymity:
        return False
    if f.asn_type and proxy.asn_type != f.asn_type:
        return False
    if proxy.score < f.min_score:
        return False
    age = age_sec(proxy.last_verified_at)
    return age is not None and age <= f.max_age_sec


def select(pool: list[Proxy], f: Filters) -> list[Proxy]:
    """`pool` is already sorted by score, so filtering preserves the ordering."""
    out = []
    for proxy in pool:
        if matches(proxy, f):
            out.append(proxy)
            if len(out) >= f.limit:
                break
    return out


def serialize(proxy: Proxy) -> dict:
    return {
        "proxy": proxy.url,
        "protocol": proxy.protocol,
        "host": proxy.host,
        "port": proxy.port,
        "country": proxy.country,
        "country_name": proxy.country_name,
        "city": proxy.city,
        "asn": proxy.asn,
        "asn_org": proxy.asn_org,
        "asn_type": proxy.asn_type,
        "anonymity": proxy.anonymity,
        "latency_ms": proxy.latency_ms,
        "google_clean": bool(proxy.google_clean),
        "score": proxy.score,
        "uptime_ratio": round(proxy.uptime_ratio, 2),
        "last_verified_at": proxy.last_verified_at,
        "age_sec": age_sec(proxy.last_verified_at),
    }


def render(proxies: list[Proxy], fmt: Format):
    if fmt == "txt":
        return PlainTextResponse("\n".join(p.url for p in proxies) + ("\n" if proxies else ""))
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(serialize(p) for p in proxies)
        return PlainTextResponse(buffer.getvalue(), media_type="text/csv")
    return JSONResponse({"count": len(proxies), "proxies": [serialize(p) for p in proxies]})


def create_app(settings: Settings, scheduler: Scheduler) -> FastAPI:
    app = FastAPI(
        title="Unlim Proxy",
        version="0.1.0",
        summary="Self-updating pool of free proxies, validated against Google.",
    )
    app.state.settings = settings
    app.state.scheduler = scheduler

    def require_key(x_api_key: Annotated[str | None, Header()] = None) -> None:
        if settings.api_key and x_api_key != settings.api_key:
            raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")

    guard = [Depends(require_key)]

    @app.get("/v1/proxy", dependencies=guard, summary="One proxy, rotated")
    async def one_proxy(f: Annotated[Filters, Depends(filters)]):
        candidates = select(scheduler.pool, f.model_copy(update={"limit": 10_000}))
        chosen = scheduler.pick(
            candidates, settings.app.rotation_top_n, settings.app.rotation_cooldown_sec
        )
        if chosen is None:
            raise HTTPException(status_code=404, detail="no proxy matches these filters")
        return serialize(chosen)

    @app.get("/v1/proxies", dependencies=guard, summary="Filtered list, best score first")
    async def many_proxies(
        f: Annotated[Filters, Depends(filters)], format: Format = "json"  # noqa: A002
    ):
        return render(select(scheduler.pool, f), format)

    @app.post("/v1/report", dependencies=guard, summary="Client feedback on a proxy")
    async def report(body: ReportBody):
        parsed = _parse_proxy_url(body.proxy)
        if parsed is None:
            raise HTTPException(status_code=422, detail="expected protocol://host:port")
        host, port, protocol = parsed
        known = await scheduler.report(host, port, protocol, body.ok)
        if not known:
            raise HTTPException(status_code=404, detail="unknown proxy")
        return {"status": "accepted"}

    @app.get("/v1/stats", dependencies=guard, summary="Pool and source statistics")
    async def stats():
        storage = scheduler.storage
        counts = await storage.pool_counts(settings.queues.fail_streak_quarantine)
        sources = await storage.load_sources()
        return {
            "pool": counts,
            "by_protocol": await storage.group_counts("protocol"),
            "by_country": await storage.group_counts("country"),
            "by_anonymity": await storage.group_counts("anonymity"),
            "by_asn_type": await storage.group_counts("asn_type"),
            "checks": await storage.checks_per_min(),
            "sources": sorted(
                (
                    {
                        "name": s.name,
                        "fetched": s.fetched_total,
                        "alive": s.alive_total,
                        "google_clean": s.google_clean_total,
                        "score": round(source_score(s), 4),
                        "last_fetch": s.last_fetch_at,
                    }
                    for s in sources.values()
                ),
                key=lambda s: s["score"],
                reverse=True,
            ),
            "uptime_sec": int(time.time() - scheduler.started_at),
            "last_scrape_at": scheduler.last_scrape_at,
        }

    @app.get("/healthz", summary="Liveness probe")
    async def healthz():
        alive = len(scheduler.pool)
        if alive == 0 and time.time() - scheduler.started_at > 600:
            return JSONResponse({"status": "degraded", "pool_alive": 0}, status_code=503)
        return {"status": "ok", "pool_alive": alive}

    return app


def _parse_proxy_url(value: str) -> tuple[str, int, str] | None:
    scheme, sep, rest = value.strip().partition("://")
    if not sep:
        return None
    protocol = normalize_protocol(scheme)
    host, colon, port_text = rest.partition(":")
    if protocol is None or not colon or not port_text.isdigit():
        return None
    return host, int(port_text), protocol
