"""Scheduler behaviour the clients feel directly."""

import asyncio
import time

import pytest

from unlimproxy.config import Settings
from unlimproxy.models import Candidate, L1Result
from unlimproxy.scheduler import Scheduler
from unlimproxy.storage import Storage


@pytest.fixture
async def scheduler(tmp_path):
    settings = Settings(sources=[])
    settings.app.db_path = tmp_path / "t.db"
    storage = Storage(settings.app.db_path)
    await storage.open()
    sched = Scheduler(settings, storage)
    await storage.upsert_candidates([Candidate("203.0.113.9", 1080, "src", "socks5")])
    await storage.commit()
    yield sched
    await storage.close()


async def test_a_failure_report_answers_without_waiting_for_the_recheck(scheduler):
    """Regression, and the reason the pool stopped hearing from its heaviest user.

    `report` used to run the L1 probe and a full `rebuild_pool` inline. Proving a dead
    proxy dead costs the whole L1 timeout, so the caller paid seconds per report. The
    Lead Engine client measured over six seconds, wrapped a short timeout around the
    call, and then muted its own reporting after a few of those.
    """
    probes = 0

    async def slow_probe(host, port, protocol, prefilter=False):
        nonlocal probes
        probes += 1
        await asyncio.sleep(0.3)
        return L1Result(ok=False)

    scheduler.checker.check_l1 = slow_probe

    started = time.monotonic()
    assert await scheduler.report("203.0.113.9", 1080, "socks5", ok=False) is True
    assert time.monotonic() - started < 0.1, "the report must not wait on a probe"
    assert probes == 0, "the recheck belongs to the background loop"

    # It is deferred, not dropped.
    await scheduler._report_once()
    assert probes == 1
    assert not scheduler._report_recheck


async def test_repeat_reports_of_one_proxy_cost_a_single_recheck(scheduler):
    """A client burning through a batch reports the same address more than once."""
    for _ in range(5):
        await scheduler.report("203.0.113.9", 1080, "socks5", ok=False)
    assert len(scheduler._report_recheck) == 1


async def test_a_success_report_queues_no_recheck(scheduler):
    assert await scheduler.report("203.0.113.9", 1080, "socks5", ok=True) is True
    assert not scheduler._report_recheck


async def test_an_unknown_proxy_is_rejected_and_queues_nothing(scheduler):
    assert await scheduler.report("198.51.100.1", 9999, "socks5", ok=False) is False
    assert not scheduler._report_recheck


async def test_the_recheck_loop_is_a_no_op_when_nothing_was_reported(scheduler):
    await scheduler._report_once()
