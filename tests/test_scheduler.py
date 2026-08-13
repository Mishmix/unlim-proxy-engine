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


async def test_the_checker_caps_total_in_flight_checks_across_every_queue(tmp_path):
    """Per-queue limits add up; only a process-wide gate bounds the sum.

    Regression from the live service: cold 400 + hot 200 + warm 200 + quarantine 50 +
    L2 30 + YouTube 60 put 940 simultaneous TLS handshakes on a 1.2-CPU container.
    The timeouts are wall clock, so connections waiting for CPU burned their connect
    budget in the scheduler's run queue and were recorded as dead proxies — a sweep of
    1569 healthy proxies returned 322 alive and the pool fell to 87 in four minutes.
    """
    import asyncio

    from unlimproxy.checker import Checker, gather_limited
    from unlimproxy.config import Settings

    settings = Settings(sources=[])
    settings.checker.max_inflight = 5
    checker = Checker(settings.checker)

    peak = 0
    live = 0

    async def fake_tcp(host, port):
        nonlocal peak, live
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.01)
        live -= 1
        return False

    checker._tcp_reachable = fake_tcp

    # Three queues asking for far more than the gate allows, all at once.
    await asyncio.gather(
        gather_limited([checker.check_l1(f"10.0.0.{i}", 1080, None) for i in range(40)], 40),
        gather_limited([checker.check_l1(f"10.0.1.{i}", 1080, None) for i in range(40)], 40),
        gather_limited([checker.check_l1(f"10.0.2.{i}", 1080, None) for i in range(40)], 40),
    )
    assert peak <= 5, f"gate leaked: {peak} concurrent against a cap of 5"
    assert peak > 1, "the gate must not serialise the checks either"
