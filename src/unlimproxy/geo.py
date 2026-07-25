"""Offline geolocation and ASN classification.

Three mmdb files are downloaded on first run and refreshed daily: IPLocate country,
IPLocate ASN, and DB-IP city-lite. No API keys, no per-request network calls —
`maxminddb` lookups are sub-millisecond, which matters at 135 k candidates.
"""

from __future__ import annotations

import asyncio
import gzip
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiohttp
import maxminddb

from .config import GeoCfg
from .models import AsnType

log = logging.getLogger(__name__)


class Geo:
    def __init__(self, cfg: GeoCfg) -> None:
        self.cfg = cfg
        self.dir = Path(cfg.dir)
        self._readers: dict[str, maxminddb.Reader | None] = {
            "country": None,
            "asn": None,
            "city": None,
        }
        self._keywords = tuple(k.lower() for k in cfg.datacenter_keywords)

    @property
    def ready(self) -> bool:
        return any(r is not None for r in self._readers.values())

    # ─── database files ────────────────────────────────────────────────────

    async def refresh(self, force: bool = False) -> None:
        """Download anything missing or older than `refresh_interval_sec`, then reopen."""
        self.dir.mkdir(parents=True, exist_ok=True)
        now = datetime.now(UTC)
        targets = {
            "country": (self.cfg.country_url, self.dir / "iplocate-country.mmdb"),
            "asn": (self.cfg.asn_url, self.dir / "iplocate-asn.mmdb"),
            "city": (
                self.cfg.city_url.replace("{year}", f"{now.year:04d}").replace(
                    "{month}", f"{now.month:02d}"
                ),
                self.dir / "dbip-city-lite.mmdb",
            ),
        }
        stale = {
            name: (url, path)
            for name, (url, path) in targets.items()
            if url and (force or self._is_stale(path))
        }
        if stale:
            timeout = aiohttp.ClientTimeout(total=self.cfg.download_timeout_sec)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                await asyncio.gather(
                    *(
                        self._download(session, name, url, path)
                        for name, (url, path) in stale.items()
                    )
                )
        for name, (_, path) in targets.items():
            self._open(name, path)

    def _is_stale(self, path: Path) -> bool:
        if not path.exists():
            return True
        age = datetime.now(UTC).timestamp() - path.stat().st_mtime
        return age >= self.cfg.refresh_interval_sec

    async def _download(
        self, session: aiohttp.ClientSession, name: str, url: str, path: Path
    ) -> None:
        tmp = path.with_suffix(path.suffix + ".part")
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                with tmp.open("wb") as handle:
                    async for chunk in response.content.iter_chunked(1 << 20):
                        await asyncio.to_thread(handle.write, chunk)
            size = await asyncio.to_thread(_finalize, tmp, path, url.endswith(".gz"))
            log.info("geo database updated", extra={"db": name, "bytes": size})
        except (TimeoutError, aiohttp.ClientError, OSError, ValueError) as exc:
            tmp.unlink(missing_ok=True)
            log.warning("geo download failed", extra={"db": name, "err": str(exc)})

    def _open(self, name: str, path: Path) -> None:
        if not path.exists():
            return
        try:
            reader = maxminddb.open_database(path)
        except (OSError, ValueError) as exc:
            log.warning("geo database unreadable", extra={"db": name, "err": str(exc)})
            return
        old = self._readers[name]
        self._readers[name] = reader
        if old is not None:
            old.close()

    def close(self) -> None:
        for name, reader in self._readers.items():
            if reader is not None:
                reader.close()
                self._readers[name] = None

    # ─── lookups ───────────────────────────────────────────────────────────

    def lookup(self, ip: str) -> dict[str, Any]:
        """Everything we know about one IP. Missing databases just yield fewer keys."""
        out: dict[str, Any] = {}
        country = self._get("country", ip)
        if country:
            iso, name = _country_of(country)
            out["country"], out["country_name"] = iso, name

        city = self._get("city", ip)
        if city:
            iso, name = _country_of(city)
            out.setdefault("country", iso)
            out.setdefault("country_name", name)
            city_names = (city.get("city") or {}).get("names") or {}
            if city_names.get("en"):
                out["city"] = city_names["en"]

        asn = self._get("asn", ip)
        if asn:
            number = asn.get("autonomous_system_number") or _digits(asn.get("asn"))
            org = (
                asn.get("autonomous_system_organization") or asn.get("org") or asn.get("name")
            )
            if number:
                out["asn"] = f"AS{number}"
            if org:
                out["asn_org"] = org
            out["asn_type"] = self.classify_asn(org, asn.get("domain"))
        return {k: v for k, v in out.items() if v}

    def classify_asn(self, org: str | None, domain: str | None = None) -> AsnType:
        """Keyword match on the ASN org/domain. Crude, free, and good enough: what we
        need is a residential-vs-datacenter hint, and datacenter ASNs advertise it."""
        haystack = f"{org or ''} {domain or ''}".lower()
        if not haystack.strip():
            return "residential"
        return "datacenter" if any(k in haystack for k in self._keywords) else "residential"

    def _get(self, name: str, ip: str) -> dict[str, Any] | None:
        reader = self._readers[name]
        if reader is None:
            return None
        try:
            record = reader.get(ip)
        except ValueError:
            return None
        return record if isinstance(record, dict) else None


def _finalize(tmp: Path, path: Path, gzipped: bool) -> int:
    """Decompress if needed, reject anything `maxminddb` cannot open, then swap in."""
    if gzipped:
        tmp.write_bytes(gzip.decompress(tmp.read_bytes()))
    maxminddb.open_database(tmp).close()
    tmp.replace(path)
    return path.stat().st_size


def _country_of(record: dict[str, Any]) -> tuple[str | None, str | None]:
    """IPLocate uses flat `country`/`country_code`; DB-IP uses MaxMind's nested shape."""
    nested = record.get("country") if isinstance(record.get("country"), dict) else None
    if nested:
        return nested.get("iso_code"), (nested.get("names") or {}).get("en")
    iso = record.get("country_code") or record.get("country")
    name = record.get("country_name") or record.get("country")
    iso = iso.upper()[:2] if isinstance(iso, str) else None
    return iso, name if isinstance(name, str) and len(name) > 2 else None


def _digits(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    digits = value[2:] if value.upper().startswith("AS") else value
    return int(digits) if digits.isdigit() else None
