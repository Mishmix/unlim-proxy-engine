"""Keep the developer's environment out of the test run.

`Settings` reads `.env` and the `API_KEY` / `UNLIMPROXY_*` variables by design, so a
machine that has a real key configured turned every unauthenticated request in the
suite into a 401. Tests construct their own settings; the ambient ones are noise.
"""

from __future__ import annotations

import pytest

from unlimproxy.config import Settings

_LEAKY_VARS = ("API_KEY", "LOG_LEVEL", "COLD_CONCURRENCY")


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in _LEAKY_VARS:
        monkeypatch.delenv(name, raising=False)
    for name in list(os_environ()):
        if name.startswith("UNLIMPROXY_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setitem(Settings.model_config, "env_file", None)


def os_environ():
    import os

    return dict(os.environ)
