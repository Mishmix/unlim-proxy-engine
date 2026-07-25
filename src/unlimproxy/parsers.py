"""Turn a raw source response into `Candidate` objects.

This is a system boundary: source bodies are untrusted, so every host and port is
validated and anything unparseable is dropped silently rather than raising.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable

from .config import SourceCfg
from .models import Anonymity, Candidate, Protocol

_SCHEME_ALIASES: dict[str, Protocol] = {
    "http": "http",
    "https": "http",
    "socks4": "socks4",
    "socks4a": "socks4",
    "socks5": "socks5",
    "socks5h": "socks5",
}

_ANONYMITY_ALIASES: dict[str, Anonymity] = {
    "elite": "elite",
    "high": "elite",
    "anonymous": "anonymous",
    "transparent": "transparent",
}

_HOST_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")


def normalize_protocol(raw: str | None) -> Protocol | None:
    if not raw:
        return None
    return _SCHEME_ALIASES.get(raw.strip().lower())


def _valid(host: str, port: int) -> bool:
    if not 0 < port < 65536:
        return False
    try:
        addr = ipaddress.IPv4Address(host)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_private or addr.is_multicast or addr.is_unspecified)


def _clean_lines(body: str) -> Iterable[str]:
    for raw in body.splitlines():
        line = raw.strip()
        if line and not line.startswith(("#", "//")):
            yield line


def _split_host_port(token: str) -> tuple[str, int] | None:
    match = _HOST_PORT.match(token)
    if not match:
        return None
    host, port_text = match.group(1), match.group(2)
    port = int(port_text)
    return (host, port) if _valid(host, port) else None


def parse_prefixed(body: str, source: SourceCfg) -> list[Candidate]:
    """`socks5://1.2.3.4:1080` — the scheme is the protocol."""
    out: list[Candidate] = []
    for line in _clean_lines(body):
        scheme, sep, rest = line.partition("://")
        if not sep:
            continue
        protocol = normalize_protocol(scheme)
        host_port = _split_host_port(rest.split("@")[-1].strip("/"))
        if protocol is None or host_port is None:
            continue
        out.append(
            Candidate(
                host=host_port[0],
                port=host_port[1],
                source=source.name,
                protocol=protocol if source.trust_protocol else None,
            )
        )
    return out


def parse_plain(body: str, source: SourceCfg) -> list[Candidate]:
    """`1.2.3.4:8080` — the protocol comes from `protocol_hint`, if it is trusted."""
    protocol = source.protocol_hint if source.trust_protocol else None
    out: list[Candidate] = []
    for line in _clean_lines(body):
        host_port = _split_host_port(line.split()[0])
        if host_port is None:
            continue
        out.append(
            Candidate(
                host=host_port[0], port=host_port[1], source=source.name, protocol=protocol
            )
        )
    return out


def parse_hideip(body: str, source: SourceCfg) -> list[Candidate]:
    """`1.2.3.4:8080:CountryName` — the trailing country *name* is dropped, the mmdb
    lookup is authoritative and gives us an ISO-2 code instead."""
    protocol = source.protocol_hint if source.trust_protocol else None
    out: list[Candidate] = []
    for line in _clean_lines(body):
        parts = line.split(":")
        if len(parts) < 2:
            continue
        host_port = _split_host_port(f"{parts[0]}:{parts[1]}")
        if host_port is None:
            continue
        out.append(
            Candidate(
                host=host_port[0], port=host_port[1], source=source.name, protocol=protocol
            )
        )
    return out


def parse_geonode(body: str, source: SourceCfg) -> list[Candidate]:
    """geonode JSON — carries anonymity, ASN, city, country and a `google` flag."""
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    rows = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        return []

    out: list[Candidate] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            port = int(row.get("port", 0))
        except (TypeError, ValueError):
            continue
        host = str(row.get("ip", ""))
        if not _valid(host, port):
            continue
        protocols = [normalize_protocol(p) for p in row.get("protocols") or []]
        protocols = [p for p in protocols if p is not None]
        if not protocols:
            protocols = [source.protocol_hint] if source.protocol_hint else []
        if not protocols:
            continue
        country = row.get("country")
        asn = row.get("asn")
        for protocol in dict.fromkeys(protocols):
            out.append(
                Candidate(
                    host=host,
                    port=port,
                    source=source.name,
                    protocol=protocol if source.trust_protocol else None,
                    country=country.upper()[:2] if isinstance(country, str) and country else None,
                    city=row.get("city") or None,
                    asn=asn if isinstance(asn, str) and asn.startswith("AS") else None,
                    asn_org=row.get("org") or row.get("isp") or None,
                    anonymity=_ANONYMITY_ALIASES.get(str(row.get("anonymityLevel", "")).lower()),
                    google_hint=bool(row["google"]) if "google" in row else None,
                )
            )
    return out


_PARSERS = {
    "prefixed": parse_prefixed,
    "plain": parse_plain,
    "geonode": parse_geonode,
    "hideip": parse_hideip,
}


def parse(source: SourceCfg, body: str | bytes) -> list[Candidate]:
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    return _PARSERS[source.parser](body, source)
