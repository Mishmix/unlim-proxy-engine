"""Storage behaviour that the API contract depends on."""

import pytest

from unlimproxy.models import Candidate
from unlimproxy.storage import Storage, push_history


@pytest.fixture
async def storage(tmp_path):
    store = Storage(tmp_path / "t.db")
    await store.open()
    yield store
    await store.close()


async def one_proxy(store: Storage, protocol: str | None = "socks5") -> int:
    await store.upsert_candidates([Candidate("203.0.113.5", 1080, "src", protocol)])
    rows = await store._rows("SELECT id FROM proxies")
    return rows[0]["id"]


async def test_upsert_is_idempotent_per_host_port_protocol(storage):
    candidates = [
        Candidate("203.0.113.5", 1080, "a", "socks5"),
        Candidate("203.0.113.5", 1080, "b", "socks5"),  # same triple, other source
        Candidate("203.0.113.5", 1080, "a", "socks4"),  # different protocol, new row
    ]
    assert await storage.upsert_candidates(candidates) == 2
    assert await storage.upsert_candidates(candidates) == 0


async def test_wal_mode_is_on(storage):
    assert (await storage._rows("PRAGMA journal_mode"))[0][0] == "wal"


async def test_failed_liveness_check_keeps_the_last_l2_verdict(storage):
    """Regression: clearing `google_clean` on every failed check wiped the flag on the
    first flap, and the 10-minute L2 window meant nothing could restore it."""
    proxy_id = await one_proxy(storage)
    await storage.record_l1(proxy_id, True, 900, push_history("", True), 1.0, 60.0)
    await storage.record_l2(proxy_id, "SEARCH_OK", 90.0)
    await storage.commit()

    await storage.record_l1(proxy_id, False, None, push_history("1", False), 0.5, 20.0)
    await storage.commit()

    row = (await storage._rows("SELECT * FROM proxies"))[0]
    assert row["alive"] == 0
    assert row["fail_streak"] == 1
    assert row["google_status"] == "SEARCH_OK"
    assert row["google_clean"] == 1


async def test_only_search_ok_sets_google_clean(storage):
    proxy_id = await one_proxy(storage)
    for status, expected in [
        ("SEARCH_OK", 1),
        ("CAPTCHA", 0),
        ("PARTIAL", 0),
        ("FAIL", 0),
    ]:
        await storage.record_l2(proxy_id, status, 50.0)
        await storage.commit()
        row = (await storage._rows("SELECT google_clean FROM proxies"))[0]
        assert row["google_clean"] == expected, status


async def test_cold_queue_orders_by_protocol_then_source_rank(storage):
    """Both orderings must happen in SQL — a bad source's huge dump would otherwise
    fill any window that gets re-sorted in Python."""
    await storage.upsert_candidates(
        [Candidate(f"203.0.113.{i}", 8080, "junk", None) for i in range(1, 60)]
        + [Candidate("198.51.100.1", 1080, "good", "socks5")]
        + [Candidate(f"198.51.100.{i}", 8080, "good", None) for i in range(2, 5)]
    )
    batch = await storage.fetch_cold(5, {"good": 0.9, "junk": 0.001})
    assert batch[0].protocol == "socks5"
    assert [p.source for p in batch[1:4]] == ["good"] * 3


async def test_cold_queue_survives_an_empty_source_ranking(storage):
    await one_proxy(storage)
    assert len(await storage.fetch_cold(5, {})) == 1


async def test_checked_proxies_leave_the_cold_queue(storage):
    proxy_id = await one_proxy(storage)
    await storage.record_l1(proxy_id, False, None, "0", 0.0, 0.0)
    await storage.commit()
    assert await storage.fetch_cold(5, {}) == []


async def test_handshake_result_rewrites_an_unknown_protocol(storage):
    proxy_id = await one_proxy(storage, protocol=None)
    assert await storage.resolve_protocol(proxy_id, "203.0.113.5", 1080, "socks4") == proxy_id
    await storage.commit()
    assert await storage.find("203.0.113.5", 1080, "socks4") is not None


async def test_resolving_onto_an_existing_triple_returns_the_surviving_row(storage):
    """Regression: the placeholder used to be deleted and its id returned to the caller,
    so the successful check that triggered the resolve was written to a dead row."""
    await storage.upsert_candidates(
        [
            Candidate("203.0.113.5", 1080, "a", "socks4"),
            Candidate("203.0.113.5", 1080, "b", None),
        ]
    )
    rows = {r["protocol"]: r["id"] for r in await storage._rows("SELECT id, protocol FROM proxies")}
    survivor = await storage.resolve_protocol(rows["unknown"], "203.0.113.5", 1080, "socks4")
    await storage.commit()

    assert survivor == rows["socks4"]
    assert await storage.count("SELECT COUNT(*) FROM proxies") == 1

    await storage.record_l1(survivor, True, 800, "1", 1.0, 70.0)
    await storage.commit()
    assert await storage.count("SELECT COUNT(*) FROM proxies WHERE checks_ok > 0") == 1


async def test_client_report_targets_an_exact_proxy(storage):
    await one_proxy(storage)
    assert await storage.apply_client_report("203.0.113.5", 1080, "socks5", False) == 1
    assert await storage.apply_client_report("203.0.113.5", 1080, "socks4", False) == 0
    row = (await storage._rows("SELECT * FROM proxies"))[0]
    assert row["client_reports_fail"] == 1
    assert row["last_report_fail_at"] is not None


async def test_prune_removes_only_hopeless_proxies(storage):
    keep = await one_proxy(storage)
    await storage.upsert_candidates([Candidate("203.0.113.9", 1080, "src", "socks5")])
    doomed = (
        await storage._rows("SELECT id FROM proxies WHERE host = '203.0.113.9'")
    )[0]["id"]
    await storage.db.execute("UPDATE proxies SET fail_streak = 10 WHERE id = ?", (doomed,))
    await storage.commit()

    assert await storage.prune(fail_streak_delete=10, stale_unseen_days=7) == 1
    remaining = await storage._rows("SELECT id FROM proxies")
    assert [r["id"] for r in remaining] == [keep]
