"""The HTTP API.

Every response is served from the scheduler's in-memory pool, so a request costs a
list scan and no disk I/O.
"""

from __future__ import annotations

import csv
import io
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, StringConstraints

from .config import Settings
from .models import Proxy
from .parsers import normalize_protocol
from .scheduler import Scheduler
from .scoring import source_score
from .storage import age_sec

Format = Literal["json", "txt", "csv"]
CountryCode = Annotated[str, StringConstraints(min_length=2, max_length=2, to_upper=True)]
Target = Literal["parser", "search", "aiohttp", "youtube"]
TARGET_HELP = (
    "Restrict to proxies that passed the YouTube probe: `parser`/`search` for the "
    "search results page, `aiohttp` for direct channel HTML, `youtube` for both. "
    "A proxy that has not been probed yet does not match."
)

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
    "parser_clean",
    "aiohttp_clean",
    "dual_clean",
    "score",
    "uptime_ratio",
    "last_verified_at",
    "age_sec",
)


class Filters(BaseModel):
    limit: int = 20
    target: Target | None = None
    protocol: list[str] = []
    country: list[str] = []
    exclude_country: list[str] = []
    max_latency_ms: int = 5000
    google_clean: bool = False
    anonymity: str | None = None
    asn_type: str | None = None
    min_score: float = 0.0
    max_age_sec: int = 300
    max_target_age_sec: int = 3600


class ReportBody(BaseModel):
    proxy: str = Field(description="`protocol://host:port`, exactly as the API returned it")
    ok: bool
    reason: str | None = None


def filters(
    limit: Annotated[int, Query(ge=1, le=100000)] = 20,
    target: Annotated[Target | None, Query(description=TARGET_HELP)] = None,
    protocol: Annotated[list[Literal["http", "socks4", "socks5"]] | None, Query()] = None,
    country: Annotated[list[CountryCode] | None, Query()] = None,
    exclude_country: Annotated[list[CountryCode] | None, Query()] = None,
    max_latency_ms: Annotated[int, Query(ge=1)] = 5000,
    google_clean: bool = False,
    anonymity: Literal["elite", "anonymous", "transparent"] | None = None,
    asn_type: Literal["residential", "datacenter"] | None = None,
    min_score: Annotated[float, Query(ge=0, le=100)] = 0.0,
    max_age_sec: Annotated[int, Query(ge=1)] = 300,
    max_target_age_sec: Annotated[
        int,
        Query(
            ge=1,
            description=(
                "Freshness bound for the ?target= verdict itself. `max_age_sec` only "
                "ages the liveness check; the YouTube probe runs on its own, much "
                "slower cadence, so without this a proxy could be verified alive "
                "seconds ago and carry a YouTube verdict from an hour back."
            ),
        ),
    ] = 3600,
) -> Filters:
    return Filters(
        limit=limit,
        target=target,
        protocol=protocol or [],
        country=[c.upper() for c in country or []],
        exclude_country=[c.upper() for c in exclude_country or []],
        max_latency_ms=max_latency_ms,
        google_clean=google_clean,
        anonymity=anonymity,
        asn_type=asn_type,
        min_score=min_score,
        max_age_sec=max_age_sec,
        max_target_age_sec=max_target_age_sec,
    )


def matches(proxy: Proxy, f: Filters) -> bool:
    if f.target in ("parser", "search") and not proxy.parser_clean:
        return False
    if f.target == "aiohttp" and not proxy.aiohttp_clean:
        return False
    if f.target == "youtube" and not proxy.dual_clean:
        return False
    if f.target is not None:
        # All three target flags are written by the same sweep, so one timestamp
        # bounds all of them. A verdict older than the sweep's own cadence means the
        # sweep has not reached this proxy, not that the proxy is still good.
        target_age = age_sec(proxy.last_yt_at)
        if target_age is None or target_age > f.max_target_age_sec:
            return False
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
        "parser_clean": bool(proxy.parser_clean),
        "aiohttp_clean": bool(proxy.aiohttp_clean),
        "dual_clean": bool(proxy.dual_clean),
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

    app.state.api_logs = []

    allowed_keys = {k.strip() for k in (settings.api_key or "").split(",") if k.strip()}

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/v1/"):
            client_ip = request.client.host if request.client else "unknown"
            ts = datetime.now(UTC).strftime("%H:%M:%S")
            # Anyone who can reach /v1 lands in this ring, including requests that
            # failed auth, so the recorded strings are attacker-chosen. The dashboard
            # escapes them; capping the length here keeps one caller from filling the
            # whole view with a single request.
            app.state.api_logs.insert(0, {
                "time": ts,
                "client_ip": client_ip,
                "method": request.method,
                "path": str(request.url.path)[:200],
                "query": str(request.url.query)[:200],
                "status": response.status_code
            })
            if len(app.state.api_logs) > 100:
                app.state.api_logs.pop()
        return response

    def require_key(
        x_api_key: str | None = Header(None),
        api_key: str | None = Query(None),
        key: str | None = Query(None),
    ) -> str:
        provided = x_api_key or api_key or key
        if allowed_keys and (not provided or provided not in allowed_keys):
            raise HTTPException(status_code=401, detail="invalid or missing API Key")
        return provided or ""

    guard = [Depends(require_key)]

    @app.post("/v1/auth/verify", summary="Verify API key")
    async def verify_auth(body: dict):
        k = body.get("key", "").strip()
        if not allowed_keys or k in allowed_keys:
            return {"valid": True}
        return JSONResponse({"valid": False, "detail": "Invalid API Key"}, status_code=401)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def login_page():
        login_path = Path(__file__).parent / "login.html"
        if login_path.exists():
            return HTMLResponse(content=login_path.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>Unlim Proxy Login</h1>")

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_page():
        """Served without the key on purpose.

        The file is an empty shell — every number in it arrives later from `/v1/*`,
        which is guarded. Guarding the shell as well only looked safer: the page can
        be reached exactly once, through the redirect that carries the key in the
        query string, and the panel then strips that key out of the address bar so it
        does not sit in history or in a screenshot. Reloading the page after that sent
        a request with no key at all and the operator got a raw 401 body instead of
        their panel. Bookmarking it never worked either.
        """
        dash_path = Path(__file__).parent / "dashboard.html"
        if dash_path.exists():
            return HTMLResponse(content=dash_path.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>Unlim Proxy Dashboard</h1>")

    @app.get("/v1/logs", dependencies=guard, summary="Recent API request logs")
    async def get_api_logs():
        return {"logs": app.state.api_logs}

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
