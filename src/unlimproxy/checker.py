"""Proxy verification.

L1  — liveness against `google.com/generate_204`, which also settles the protocol
      when the source label could not be trusted.
L2  — a real `google.com/search` request, classified into SEARCH_OK / CAPTCHA /
      PARTIAL / FAIL. Only SEARCH_OK counts as `google_clean`.

TLS verification is on everywhere and there is no switch to turn it off. A free proxy
that cannot complete an honest handshake to Google is a proxy we do not want.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
import re
import time
from urllib.parse import urlencode

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType

from .config import CheckerCfg
from .models import Anonymity, GoogleStatus, L1Result, L2Result, Protocol

log = logging.getLogger(__name__)

_PROXY_TYPES = {
    "http": ProxyType.HTTP,
    "socks4": ProxyType.SOCKS4,
    "socks5": ProxyType.SOCKS5,
}

CAPTCHA_MARKERS = (
    "unusual traffic",
    "/sorry/",
    "recaptcha",
    "captcha-form",
    "our systems have detected",
)

_HEADER_LEAK = re.compile(
    r"(x-forwarded-for|via|x-real-ip|forwarded|proxy-connection|client-ip)", re.I
)


def classify_google(status: int | None, body: str, cfg: CheckerCfg) -> GoogleStatus:
    """The single place that decides whether a proxy is usable against Google.

    `status` is None when the request never produced a response.
    """
    if status is None or not body:
        return "FAIL"
    lowered = body.lower()
    if any(marker in lowered for marker in CAPTCHA_MARKERS):
        return "CAPTCHA"
    size = len(body.encode("utf-8", errors="ignore"))
    if size >= cfg.l2_ok_min_bytes:
        return "SEARCH_OK"
    if size >= cfg.l2_partial_min_bytes:
        return "PARTIAL"
    return "FAIL"


class Checker:
    def __init__(self, cfg: CheckerCfg) -> None:
        self.cfg = cfg
        self.own_ip: str | None = None

    async def detect_own_ip(self) -> str | None:
        """One direct request at startup; the anonymity check compares against it."""
        timeout = aiohttp.ClientTimeout(total=15, connect=self.cfg.connect_timeout_sec)
        try:
            async with (
                aiohttp.ClientSession(timeout=timeout, headers=self._headers()) as session,
                session.get(self.cfg.anonymity_ip_url) as response,
            ):
                self.own_ip = (await response.json(content_type=None)).get("ip")
        except (TimeoutError, aiohttp.ClientError, json.JSONDecodeError, KeyError) as exc:
            log.warning("own IP detection failed", extra={"err": str(exc)})
        log.info("own external IP", extra={"ip": self.own_ip})
        return self.own_ip

    # ─── L1 ────────────────────────────────────────────────────────────────

    async def check_l1(
        self, host: str, port: int, protocol: str | None, prefilter: bool = False
    ) -> L1Result:
        """HTTP 204 from Google means alive. An unknown protocol is resolved by trying
        SOCKS5 → SOCKS4 → HTTP and keeping whichever handshake succeeds first.

        `prefilter` demands a cheap TCP probe first even when the protocol is known.
        It buys throughput at the cost of a few live proxies whose SYN-ACK is slower
        than `tcp_probe_timeout_sec`, so it belongs on the cold queue — which is
        mostly dead addresses and where a missed proxy comes back next pass — and
        never on the queues that re-verify proxies already in the pool.
        """
        order: list[Protocol] = (
            [protocol] if protocol in _PROXY_TYPES else list(self.cfg.protocol_probe_order)
        )
        if (len(order) > 1 or prefilter) and not await self._tcp_reachable(host, port):
            # Most candidates are simply unreachable. One TCP probe settles that for
            # all three protocols instead of burning three connect timeouts.
            return L1Result(ok=False)
        for candidate in order:
            started = time.monotonic()
            if await self._request_204(host, port, candidate):
                return L1Result(
                    ok=True,
                    protocol=candidate,
                    latency_ms=int((time.monotonic() - started) * 1000),
                )
        return L1Result(ok=False, protocol=protocol if protocol in _PROXY_TYPES else None)

    async def _tcp_reachable(self, host: str, port: int) -> bool:
        """Its own, much shorter budget: a proxy that has not completed the TCP
        handshake within a couple of seconds will not survive the TLS one either.
        Measured on a 5000-address sample, 94 % of successful connects land inside
        2 s and the median lands in 73 ms."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), self.cfg.tcp_probe_timeout_sec
            )
        except (OSError, TimeoutError):
            return False
        writer.close()
        with contextlib.suppress(OSError, TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        return True

    async def _request_204(self, host: str, port: int, protocol: str) -> bool:
        try:
            async with (
                self._session(host, port, protocol, self.cfg.l1_total_timeout_sec) as session,
                session.get(self.cfg.l1_url, allow_redirects=False) as response,
            ):
                await response.read()
                return response.status == 204
        except Exception:  # noqa: BLE001 — every proxy failure mode ends here
            return False

    # ─── L2 ────────────────────────────────────────────────────────────────

    async def check_l2(self, host: str, port: int, protocol: str) -> L2Result:
        query = random.choice(self.cfg.l2_queries)  # noqa: S311 — not security relevant
        url = f"{self.cfg.l2_url}?{urlencode({'q': query})}"
        try:
            async with (
                self._session(host, port, protocol, self.cfg.l2_total_timeout_sec) as session,
                session.get(url, allow_redirects=True) as response,
            ):
                body = await response.text(errors="replace")
                status: int | None = response.status
                if "/sorry/" in str(response.url):
                    return L2Result("CAPTCHA", len(body))
        except Exception:  # noqa: BLE001
            body, status = "", None
        return L2Result(classify_google(status, body, self.cfg), len(body))

    # ─── YouTube ───────────────────────────────────────────────────────────

    async def _youtube_page_ok(self, host: str, port: int, protocol: str, url: str) -> bool:
        try:
            async with (
                self._session(host, port, protocol, self.cfg.yt_total_timeout_sec) as session,
                session.get(url, allow_redirects=True) as response,
            ):
                if response.status != 200:
                    return False
                body = await response.text(errors="replace")
        except Exception:  # noqa: BLE001 — every proxy failure mode ends here
            return False
        lowered = body.lower()
        if any(marker in lowered for marker in CAPTCHA_MARKERS):
            return False
        return len(body.encode("utf-8", errors="ignore")) >= self.cfg.yt_ok_min_bytes

    async def check_youtube(self, host: str, port: int, protocol: str) -> tuple[bool, bool]:
        """`(search_ok, channel_ok)` — the two pages a YouTube scraper actually needs.

        Sequential on purpose. Firing both at once through one proxy measurably kills
        it: a staggered two-connection variant of the L1 probe recovered 17 % of a
        known-live set where the sequential one recovered 50 %.
        """
        search_ok = await self._youtube_page_ok(host, port, protocol, self.cfg.yt_search_url)
        channel_ok = await self._youtube_page_ok(host, port, protocol, self.cfg.yt_channel_url)
        return search_ok, channel_ok

    # ─── anonymity ─────────────────────────────────────────────────────────

    async def check_anonymity(self, host: str, port: int, protocol: str) -> Anonymity | None:
        """`transparent` if the exit IP is ours, `anonymous` if a forwarding header
        carries our IP, `elite` otherwise."""
        if not self.own_ip:
            return None
        seen_ip = await self._fetch(host, port, protocol, self.cfg.anonymity_ip_url)
        if seen_ip is None:
            return None
        if self.own_ip in seen_ip:
            return "transparent"
        judge = await self._fetch(host, port, protocol, self.cfg.anonymity_judge_url)
        if judge and self.own_ip in judge:
            return "anonymous"
        if judge:
            leaked = [
                line
                for line in judge.splitlines()
                if _HEADER_LEAK.search(line) and self.own_ip in line
            ]
            if leaked:
                return "anonymous"
        return "elite"

    async def _fetch(self, host: str, port: int, protocol: str, url: str) -> str | None:
        try:
            async with (
                self._session(host, port, protocol, self.cfg.l2_total_timeout_sec) as session,
                session.get(url) as response,
            ):
                return await response.text(errors="replace")
        except Exception:  # noqa: BLE001
            return None

    # ─── plumbing ──────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent": self.cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def _session(
        self, host: str, port: int, protocol: str, total_timeout: float
    ) -> aiohttp.ClientSession:
        connector = ProxyConnector(
            proxy_type=_PROXY_TYPES[protocol],
            host=host,
            port=port,
            rdns=protocol != "socks4",
            limit=1,
            ttl_dns_cache=300,
        )
        return aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(
                total=total_timeout, connect=self.cfg.connect_timeout_sec
            ),
            headers=self._headers(),
        )


async def gather_limited(coros, concurrency: int):
    """Run coroutines with a hard concurrency cap, preserving input order."""
    semaphore = asyncio.Semaphore(concurrency)

    async def guarded(coro):
        async with semaphore:
            return await coro

    return await asyncio.gather(*(guarded(c) for c in coros), return_exceptions=True)
