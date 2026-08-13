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


async def test_cold_queue_returns_a_fresh_candidate(storage):
    await one_proxy(storage)
    assert len(await storage.fetch_cold(5)) == 1


async def test_only_answering_leaves_the_cold_queue(storage):
    """A failed check must NOT retire the address.

    This is the bug that cost the live pool nearly everything: the queue selected on
    `last_check_at IS NULL`, so one miss retired an address forever, and neither `warm`
    nor `quarantine` would take it either — both require `checks_ok > 0`. On the
    production database 782 127 of 782 530 rows sat in no queue at all. A free proxy
    blinks; one sample is not a verdict.
    """
    proxy_id = await one_proxy(storage)
    await storage.record_l1(proxy_id, False, None, "0", 0.0, 0.0)
    await storage.commit()
    assert [p.id for p in await storage.fetch_cold(5)] == [proxy_id]

    await storage.record_l1(proxy_id, True, 500, "01", 0.5, 40.0)
    await storage.commit()
    assert await storage.fetch_cold(5) == []


async def test_cold_queue_serves_the_longest_unchecked_first(storage):
    """Never-tried before re-tried, and among re-tried the one waiting longest."""
    await storage.upsert_candidates(
        [
            Candidate("203.0.113.1", 1080, "src", "socks5"),
            Candidate("203.0.113.2", 1080, "src", "socks5"),
            Candidate("203.0.113.3", 1080, "src", "socks5"),
        ]
    )
    by_host = {r["host"]: r["id"] for r in await storage._rows("SELECT id, host FROM proxies")}
    for host, stamp in (("203.0.113.2", "2026-01-01T00:00:00Z"), ("203.0.113.1", "2020-01-01Z")):
        await storage.db.execute(
            "UPDATE proxies SET last_check_at = ?, checks_total = 1, fail_streak = 1 "
            "WHERE id = ?",
            (stamp, by_host[host]),
        )
    await storage.commit()

    order = [p.host for p in await storage.fetch_cold(5)]
    assert order == ["203.0.113.3", "203.0.113.1", "203.0.113.2"]


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
    await storage.db.execute(
        "UPDATE proxies SET fail_streak = 10, checks_ok = 1 WHERE id = ?", (doomed,)
    )
    await storage.commit()

    assert await storage.prune(fail_streak_delete=10, stale_unseen_days=7) == 1
    remaining = await storage._rows("SELECT id FROM proxies")
    assert [r["id"] for r in remaining] == [keep]


async def test_prune_does_not_scythe_the_carousel(storage):
    """A candidate that has never answered is retired by its sources, not by our probe
    luck. The carousel re-tries everything, so an unscoped `fail_streak` rule would
    delete the entire backlog every ten passes — and the next scrape would put it all
    straight back, at the front of the queue, having learned nothing."""
    proxy_id = await one_proxy(storage)
    await storage.db.execute(
        "UPDATE proxies SET fail_streak = 40, checks_total = 40 WHERE id = ?", (proxy_id,)
    )
    await storage.commit()

    assert await storage.prune(fail_streak_delete=10, stale_unseen_days=7) == 0
    assert [p.id for p in await storage.fetch_cold(5)] == [proxy_id]

    # Sources dropping it is what retires it.
    await storage.db.execute(
        "UPDATE proxies SET last_seen_in_source_at = '2020-01-01T00:00:00Z' WHERE id = ?",
        (proxy_id,),
    )
    await storage.commit()
    assert await storage.prune(fail_streak_delete=10, stale_unseen_days=7) == 1


# ─── batched writes and the added columns ──────────────────────────────────


async def test_record_l1_many_applies_both_outcomes_in_one_pass(storage):
    await storage.upsert_candidates(
        [Candidate("203.0.113.5", 1080, "s", "socks5"), Candidate("203.0.113.6", 1080, "s", "http")]
    )
    rows = await storage._rows("SELECT id FROM proxies ORDER BY id")
    good, bad = rows[0]["id"], rows[1]["id"]
    await storage.record_l1_many(
        [(good, True, 700, "1", 1.0, 80.0), (bad, False, None, "0", 0.0, 0.0)]
    )
    await storage.commit()

    state = {
        r["id"]: r
        for r in await storage._rows(
            "SELECT id, alive, latency_ms, fail_streak, checks_ok, last_verified_at FROM proxies"
        )
    }
    good_row = state[good]
    assert (good_row["alive"], good_row["latency_ms"], good_row["checks_ok"]) == (1, 700, 1)
    assert state[good]["last_verified_at"] is not None
    assert (state[bad]["alive"], state[bad]["fail_streak"]) == (0, 1)
    assert state[bad]["last_verified_at"] is None


async def test_record_l1_many_tolerates_an_empty_batch(storage):
    await storage.record_l1_many([])


async def yt_flags(storage) -> tuple[int, int, int, int]:
    row = (await storage._rows("SELECT * FROM proxies"))[0]
    return (
        row["parser_clean"],
        row["aiohttp_clean"],
        row["dual_clean"],
        row["yt_fail_streak"],
    )


async def test_youtube_verdict_round_trips(storage):
    proxy_id = await one_proxy(storage)
    await storage.record_l1(proxy_id, True, 500, "1", 1.0, 70.0)
    await storage.record_yt_many([(proxy_id, True, False)], 2)
    await storage.commit()
    assert await yt_flags(storage) == (1, 0, 0, 0)

    due = await storage.fetch_yt_due(10, "2099-01-01T00:00:00Z")
    assert [p.id for p in due] == [proxy_id]
    assert not await storage.fetch_yt_due(10, "2000-01-01T00:00:00Z")


async def test_one_failed_youtube_probe_does_not_clear_the_flags(storage):
    """Hysteresis. Two page loads through a free proxy miss for reasons that have
    nothing to do with YouTube, and the sweep runs far more often than the pool turns
    over — so clearing on the first miss made `?target=youtube` collapse to zero on a
    beat and forced the client onto less-verified proxies."""
    proxy_id = await one_proxy(storage)
    await storage.record_l1(proxy_id, True, 500, "1", 1.0, 70.0)
    await storage.record_yt_many([(proxy_id, True, True)], 2)
    await storage.commit()
    assert await yt_flags(storage) == (1, 1, 1, 0)

    await storage.record_yt_many([(proxy_id, False, False)], 2)
    await storage.commit()
    assert await yt_flags(storage) == (1, 1, 1, 1), "one miss must not clear the set"

    await storage.record_yt_many([(proxy_id, False, False)], 2)
    await storage.commit()
    assert await yt_flags(storage) == (0, 0, 0, 2), "two in a row is a verdict"


async def test_a_passing_probe_resets_the_youtube_fail_streak(storage):
    proxy_id = await one_proxy(storage)
    await storage.record_l1(proxy_id, True, 500, "1", 1.0, 70.0)
    await storage.record_yt_many([(proxy_id, False, False)], 2)
    await storage.record_yt_many([(proxy_id, True, False)], 2)
    await storage.commit()
    assert await yt_flags(storage) == (1, 0, 0, 0)


async def test_youtube_queue_serves_never_probed_before_re_probes(storage):
    """Regression: the queue led with `dual_clean DESC`, so every sweep re-tested the
    proxies already in the set before it would look at one new candidate. The set could
    only shrink — it re-litigated its own members and never grew."""
    await storage.upsert_candidates(
        [
            Candidate("203.0.113.7", 1080, "src", "socks5"),  # already in the set
            Candidate("203.0.113.8", 1080, "src", "socks5"),  # never probed
        ]
    )
    ids = {r["host"]: r["id"] for r in await storage._rows("SELECT id, host FROM proxies")}
    for host in ids:
        await storage.record_l1(ids[host], True, 500, "1", 1.0, 70.0)
    await storage.record_yt_many([(ids["203.0.113.7"], True, True)], 2)
    await storage.commit()

    due = await storage.fetch_yt_due(10, "2099-01-01T00:00:00Z")
    assert [p.host for p in due] == ["203.0.113.8", "203.0.113.7"]


async def test_open_adds_columns_to_a_database_created_before_they_existed(tmp_path):
    """`CREATE TABLE IF NOT EXISTS` is a no-op on an existing file, so an upgrade has
    to reach the new columns through ALTER TABLE or every query naming them fails.

    The pre-upgrade file is produced by taking a current one and removing exactly the
    columns the upgrade adds, which keeps the fixture honest as more get added.
    """
    from unlimproxy.storage import _ADDED_COLUMNS

    path = tmp_path / "old.db"
    store = Storage(path)
    await store.open()
    try:
        await store.upsert_candidates([Candidate("203.0.113.9", 80, "s", "http")])
        # An index over a dropped column blocks the drop, exactly as it would have
        # been absent from the older schema.
        await store.db.execute("DROP INDEX IF EXISTS idx_proxies_yt")
        for column in _ADDED_COLUMNS:
            await store.db.execute(f"ALTER TABLE proxies DROP COLUMN {column}")
        await store.commit()
    finally:
        await store.close()

    reopened = Storage(path)
    await reopened.open()
    try:
        row = (await reopened._rows("SELECT * FROM proxies"))[0]
        assert row["parser_clean"] == 0
        assert row["last_yt_at"] is None
        assert await reopened.fetch_yt_due(5, "2099-01-01T00:00:00Z") == []
    finally:
        await reopened.close()


async def test_scraper_keeps_network_out_of_the_database_lock(storage, monkeypatch):
    """Regression: the whole scrape ran inside the scheduler's database lock, so 84
    HTTP fetches blocked every check queue for about 25 s out of every 180."""
    from unlimproxy.config import Settings, SourceCfg
    from unlimproxy.models import ScrapeResult
    from unlimproxy.scraper import Scraper

    settings = Settings(
        sources=[SourceCfg(name="s", url="http://example.invalid/list.txt", parser="scan")],
        _env_file=None,
    )
    scraper = Scraper(settings, storage)
    sources = settings.enabled_sources
    result = ScrapeResult(source="s")
    result.candidates = [Candidate("203.0.113.7", 1080, "s", "socks5")]
    result.fetched = 1

    stored = await scraper.store(sources, [result])
    await storage.commit()
    assert stored[0].new == 1
    assert await storage.find("203.0.113.7", 1080, "socks5") is not None


async def test_geo_batch_writes_partial_answers_without_wiping_the_rest(storage):
    """One statement for the whole batch, and every row can carry a different subset
    of keys — a lookup that only resolved the country must not blank the ASN.

    This was one `UPDATE` per proxy inside the scheduler's database lock. aiosqlite
    charges a thread hand-off per statement, so five thousand of them held the lock
    that every queue and `/v1/stats` waits on: a `POST /v1/report` doing nothing but a
    lookup and an update measured 29.7 s on the live service.
    """
    await storage.upsert_candidates(
        [Candidate("203.0.113.5", 1080, "s", "socks5"), Candidate("203.0.113.6", 1080, "s", "http")]
    )
    rows = await storage._rows("SELECT id FROM proxies ORDER BY id")
    full, partial = rows[0]["id"], rows[1]["id"]

    await storage.set_geo_many(
        [
            (full, {"country": "DE", "country_name": "Germany", "asn": "AS1", "asn_org": "X"}),
            (partial, {"country": "US"}),
        ]
    )
    await storage.commit()

    state = {r["id"]: r for r in await storage._rows("SELECT * FROM proxies")}
    assert (state[full]["country"], state[full]["asn"]) == ("DE", "AS1")
    assert state[partial]["country"] == "US"
    assert state[partial]["asn"] is None
    assert all(state[i]["geo_done"] == 1 for i in (full, partial))
    assert not await storage.fetch_pending_geo(10), "geo_done keeps them out of the queue"


async def test_geo_batch_tolerates_an_empty_batch(storage):
    await storage.set_geo_many([])
