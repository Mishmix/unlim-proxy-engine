"""Domain objects shared between the scraper, the checker, storage and the API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Protocol = Literal["http", "socks4", "socks5"]
GoogleStatus = Literal["SEARCH_OK", "CAPTCHA", "PARTIAL", "FAIL"]
Anonymity = Literal["elite", "anonymous", "transparent"]
AsnType = Literal["residential", "datacenter"]

PROTOCOLS: tuple[Protocol, ...] = ("http", "socks4", "socks5")
PROTOCOL_WEIGHT: dict[str, float] = {"socks5": 1.0, "socks4": 0.6, "http": 0.2}
ANONYMITY_WEIGHT: dict[str, float] = {"elite": 1.0, "anonymous": 0.6, "transparent": 0.0}
ASN_WEIGHT: dict[str, float] = {"residential": 1.0, "datacenter": 0.3}


@dataclass(slots=True, frozen=True)
class Candidate:
    """A raw `host:port` pulled from a source, before any verification."""

    host: str
    port: int
    source: str
    protocol: Protocol | None = None
    """None means the protocol is unknown and must be resolved by handshake."""
    country: str | None = None
    city: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    anonymity: Anonymity | None = None
    google_hint: bool | None = None

    @property
    def key(self) -> tuple[str, int, str | None]:
        return (self.host, self.port, self.protocol)


@dataclass(slots=True)
class L1Result:
    ok: bool
    protocol: Protocol | None = None
    latency_ms: int | None = None


@dataclass(slots=True)
class L2Result:
    status: GoogleStatus
    size: int = 0


@dataclass(slots=True)
class Proxy:
    """One row of the `proxies` table."""

    id: int
    host: str
    port: int
    protocol: Protocol
    country: str | None = None
    country_name: str | None = None
    city: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    asn_type: str | None = None
    anonymity: str | None = None
    latency_ms: int | None = None
    google_status: str | None = None
    google_clean: int = 0
    score: float = 0.0
    alive: int = 0
    alive_streak: int = 0
    fail_streak: int = 0
    checks_total: int = 0
    checks_ok: int = 0
    client_reports_ok: int = 0
    client_reports_fail: int = 0
    first_seen_at: str | None = None
    last_seen_in_source_at: str | None = None
    last_check_at: str | None = None
    last_verified_at: str | None = None
    last_l2_at: str | None = None
    source: str | None = None
    history: str = ""
    """Sliding window of the last checks, oldest first: '1' = ok, '0' = fail."""
    last_report_fail_at: str | None = None
    uptime_ratio: float = 0.0

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"

    @classmethod
    def from_row(cls, row: Any) -> Proxy:
        columns = set(row.keys())
        return cls(**{k: row[k] for k in columns & _PROXY_FIELDS})


@dataclass(slots=True)
class SourceStats:
    name: str
    url: str = ""
    etag: str | None = None
    last_fetch_at: str | None = None
    fetched_total: int = 0
    alive_total: int = 0
    google_clean_total: int = 0

    @property
    def score(self) -> float:
        return self.alive_total / max(self.fetched_total, 1)


@dataclass(slots=True)
class ScrapeResult:
    source: str
    fetched: int = 0
    new: int = 0
    not_modified: bool = False
    error: str | None = None
    etag: str | None = None
    candidates: list[Candidate] = field(default_factory=list)


_PROXY_FIELDS = frozenset(Proxy.__dataclass_fields__)
