"""Configuration: `config.toml` as the base, environment variables on top.

Precedence (highest first): explicit init kwargs, `UNLIMPROXY_*` env vars,
`.env` file, `config.toml`, field defaults.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

Protocol = Literal["http", "socks4", "socks5"]
ParserName = Literal["prefixed", "plain", "geonode", "hideip", "scan"]

DEFAULT_CONFIG_PATH = Path(os.getenv("UNLIMPROXY_CONFIG", "config.toml"))


class AppCfg(BaseModel):
    db_path: Path = Path("./data/proxies.db")
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "INFO"
    rotation_cooldown_sec: int = 30
    rotation_top_n: int = 20


class ScraperCfg(BaseModel):
    interval_sec: int = 600
    concurrency: int = 10
    timeout_sec: int = 60
    max_bytes: int = 32 * 1024 * 1024


class CheckerCfg(BaseModel):
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
    )
    l1_url: str = "https://www.google.com/generate_204"
    l2_url: str = "https://www.google.com/search"
    connect_timeout_sec: float = 5
    tcp_probe_timeout_sec: float = 2
    l1_total_timeout_sec: float = 8
    l2_total_timeout_sec: float = 12
    l2_min_interval_sec: int = 600
    l2_ok_min_bytes: int = 20_000
    l2_partial_min_bytes: int = 100
    l2_queries: list[str] = ["weather", "python", "news"]
    yt_search_url: str = "https://www.youtube.com/results?search_query=test&sp=EgIQAg%3D%3D"
    yt_channel_url: str = "https://www.youtube.com/@YouTube/about"
    yt_total_timeout_sec: float = 12
    yt_ok_min_bytes: int = 10_000
    yt_required_marker: str = "ytInitialData"
    yt_min_interval_sec: int = 1800
    anonymity_ip_url: str = "https://api.ipify.org?format=json"
    anonymity_judge_url: str = "http://azenv.net/"
    protocol_probe_order: list[Protocol] = ["socks5", "socks4", "http"]


class QueuesCfg(BaseModel):
    cold_concurrency: int = 1000
    cold_batch: int = 2000
    cold_window_batches: int = 10
    hot_interval_sec: int = 90
    hot_concurrency: int = 100
    warm_interval_sec: int = 300
    warm_concurrency: int = 200
    l2_interval_sec: int = 60
    l2_concurrency: int = 30
    yt_interval_sec: int = 60
    yt_concurrency: int = 60
    yt_batch: int = 480
    yt_fail_grace: int = 2
    quarantine_interval_sec: int = 1800
    quarantine_concurrency: int = 50
    fail_streak_quarantine: int = 3
    fail_streak_delete: int = 10
    stale_unseen_days: int = 7


class GeoCfg(BaseModel):
    country_url: str = ""
    asn_url: str = ""
    city_url: str = ""
    dir: Path = Path("./data/geo")
    refresh_interval_sec: int = 86_400
    download_timeout_sec: int = 600
    datacenter_keywords: list[str] = []


class SourceCfg(BaseModel):
    name: str
    url: str
    parser: ParserName
    protocol_hint: Protocol | None = None
    trust_protocol: bool = True
    priority: int = 3
    pages: int = 1
    enabled: bool = True


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="UNLIMPROXY_",
        populate_by_name=True,
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        toml_file=DEFAULT_CONFIG_PATH,
        extra="ignore",
    )

    api_key: str | None = Field(default=None, validation_alias="API_KEY")
    app: AppCfg = AppCfg()
    scraper: ScraperCfg = ScraperCfg()
    checker: CheckerCfg = CheckerCfg()
    queues: QueuesCfg = QueuesCfg()
    geo: GeoCfg = GeoCfg()
    sources: list[SourceCfg] = []

    @property
    def enabled_sources(self) -> list[SourceCfg]:
        return [s for s in self.sources if s.enabled]

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            TomlConfigSettingsSource(settings_cls),
        )


def load_settings(config_path: Path | str | None = None) -> Settings:
    if config_path is not None:
        Settings.model_config["toml_file"] = Path(config_path)
    return Settings()


_LOG_RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    """One JSON object per line; anything passed via `extra=` becomes a top-level key."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _LOG_RESERVED:
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def setup_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    for noisy in ("aiosqlite", "asyncio", "aiohttp.access", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
