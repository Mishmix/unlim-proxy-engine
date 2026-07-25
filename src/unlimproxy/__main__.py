"""Entry point: the API and every background loop share one asyncio event loop."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator

import uvicorn
from fastapi import FastAPI

from .api import create_app
from .config import load_settings, setup_logging
from .scheduler import Scheduler
from .storage import Storage

log = logging.getLogger(__name__)


def build() -> tuple[FastAPI, object]:
    settings = load_settings()
    setup_logging(settings.app.log_level)
    storage = Storage(settings.app.db_path)
    scheduler = Scheduler(settings, storage)

    @contextlib.asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await storage.open()
        await scheduler.start()
        log.info("ready", extra={"port": settings.app.port, "auth": bool(settings.api_key)})
        try:
            yield
        finally:
            await scheduler.stop()
            await storage.close()

    app = create_app(settings, scheduler)
    app.router.lifespan_context = lifespan
    return app, settings


def main() -> None:
    app, settings = build()
    uvicorn.run(
        app,
        host=settings.app.host,
        port=settings.app.port,
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
