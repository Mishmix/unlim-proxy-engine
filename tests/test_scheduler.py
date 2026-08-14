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


async def test_page_loads_cannot_starve_the_liveness_checks():
    """Regression: the second pool collapse, 2358 alive -> 132, with the gate already in.

    Bounding the *count* of in-flight requests was not enough, because a YouTube page
    load is not the same size as an L1 probe. Measured from the server: the search
    page is 897 KB and a watch page 1.22 MB, so through a free proxy one of those
    holds its slot for ~10 s while an L1 probe holds it for ~2 s. A 272-proxy sweep
    therefore parked the shared budget and the L1 sweeps behind it timed out into
    "dead" — the logs show L1, L2 and YouTube collapsing inside the same minute.

    So heavy transfers draw on a sub-budget: they can take at most
    `max_inflight_heavy` of `max_inflight`, and the rest is always there for L1.
    """
    from unlimproxy.checker import Checker
    from unlimproxy.config import Settings

    settings = Settings(sources=[])
    settings.checker.max_inflight = 20
    settings.checker.max_inflight_heavy = 3
    checker = Checker(settings.checker)

    heavy_peak = heavy_live = 0
    l1_done = 0

    async def fake_page(host, port, protocol, url):
        nonlocal heavy_peak, heavy_live
        async with checker._heavy, checker._gate:
            heavy_live += 1
            heavy_peak = max(heavy_peak, heavy_live)
            await asyncio.sleep(0.05)  # a page load: slow, and it holds the slot
            heavy_live -= 1
        return True

    async def fake_l1(host, port, protocol=None, prefilter=False):
        nonlocal l1_done
        async with checker._gate:
            await asyncio.sleep(0.001)
            l1_done += 1
        return L1Result(ok=True)

    checker._youtube_page_ok = fake_page
    checker.check_l1 = fake_l1

    await asyncio.gather(
        *(checker.check_youtube(f"10.0.0.{i}", 1080, "socks5") for i in range(30)),
        *(checker.check_l1(f"10.0.1.{i}", 1080, "socks5") for i in range(200)),
    )
    assert heavy_peak <= 3, f"heavy budget leaked: {heavy_peak} concurrent against a cap of 3"
    assert l1_done == 200, "liveness checks must not be starved by the page loads"


def test_the_proven_proxies_are_swept_faster_than_they_blink():
    """The pool sat at 85 alive while 4 238 proven addresses went unchecked.

    Measured on the live database (14.08): 785 832 rows, 4 323 of which have ever
    answered a check, 3 829 of those in quarantine. Re-probing 600 of them minutes
    after the service marked them dead found 1.8 % answering — against 0.55 % for a
    2 000-row window of the cold carousel. Free proxies blink; a proxy that answered
    once is worth three of an address that never has, and there are only four
    thousand of them against three quarters of a million.

    At the old settings — 200 rows per 1800 s — one cycle took nine and a half hours,
    so nearly every one of those returns was missed. The invariant is that the whole
    proven set gets re-probed several times an hour.
    """
    from unlimproxy.config import load_settings

    q = load_settings("config.toml").queues
    proven = 4_500  # measured, and bounded: it only grows as addresses first answer
    cycles_per_hour = (3600 / q.quarantine_interval_sec) * q.quarantine_batch / proven
    assert cycles_per_hour >= 4, f"quarantine cycles only {cycles_per_hour:.1f}x per hour"

    # And retention is expressed in time, so speeding the sweep up cannot turn into
    # deleting the proven set faster.
    assert q.proven_stale_days >= 1
