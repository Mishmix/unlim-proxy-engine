import csv
import io
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from unlimproxy.api import create_app
from unlimproxy.config import Settings
from unlimproxy.models import Proxy
from unlimproxy.scheduler import Scheduler
from unlimproxy.scoring import score
from unlimproxy.storage import Storage


def ago(seconds: int) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_proxy(idx: int, **kwargs) -> Proxy:
    base = {
        "id": idx,
        "host": f"10.0.0.{idx}" if idx < 250 else f"11.0.0.{idx - 250}",
        "port": 1080 + idx,
        "protocol": "socks5",
        "country": "US",
        "country_name": "United States",
        "city": "Ashburn",
        "asn": "AS1",
        "asn_org": "Example",
        "asn_type": "residential",
        "anonymity": "elite",
        "latency_ms": 1000,
        "alive": 1,
        "history": "1" * 20,
        "last_verified_at": ago(5),
    }
    proxy = Proxy(**(base | kwargs))
    proxy.uptime_ratio = 1.0 if proxy.history else 0.0
    proxy.score = score(proxy)
    return proxy


@pytest.fixture
def pool() -> list[Proxy]:
    proxies = [
        make_proxy(1, google_clean=1),
        make_proxy(2, google_clean=1, country="DE", country_name="Germany"),
        make_proxy(3, protocol="socks4", latency_ms=2500),
        make_proxy(4, protocol="http", latency_ms=4000, anonymity="transparent"),
        make_proxy(5, country="RU", asn_type="datacenter", anonymity="anonymous"),
        make_proxy(6, latency_ms=4800, history="1010101010"),
        make_proxy(7, last_verified_at=ago(3600)),  # stale
    ]
    proxies.sort(key=lambda p: p.score, reverse=True)
    return proxies


@pytest.fixture
def client(pool, tmp_path) -> TestClient:
    settings = Settings(sources=[])
    settings.app.db_path = tmp_path / "t.db"
    scheduler = Scheduler(settings, Storage(settings.app.db_path))
    scheduler.pool = pool
    return TestClient(create_app(settings, scheduler))


# ─── /v1/proxies filters ───────────────────────────────────────────────────


def test_default_list_excludes_stale_entries(client):
    body = client.get("/v1/proxies").json()
    assert body["count"] == 6
    assert all(p["age_sec"] <= 300 for p in body["proxies"])


def test_sorted_by_score_descending(client):
    scores = [p["score"] for p in client.get("/v1/proxies").json()["proxies"]]
    assert scores == sorted(scores, reverse=True)


def test_limit(client):
    assert client.get("/v1/proxies?limit=2").json()["count"] == 2


@pytest.mark.parametrize(
    ("limit", "status"), [(0, 422), (1, 200), (100_000, 200), (100_001, 422)]
)
def test_limit_bounds(client, limit, status):
    assert client.get(f"/v1/proxies?limit={limit}").status_code == status


def test_protocol_filter_repeats(client):
    single = client.get("/v1/proxies?protocol=socks4").json()
    assert {p["protocol"] for p in single["proxies"]} == {"socks4"}
    both = client.get("/v1/proxies?protocol=socks4&protocol=http").json()
    assert {p["protocol"] for p in both["proxies"]} == {"socks4", "http"}


def test_unknown_protocol_is_rejected(client):
    assert client.get("/v1/proxies?protocol=carrier-pigeon").status_code == 422


def test_country_and_exclude_country(client):
    only_de = client.get("/v1/proxies?country=de").json()
    assert {p["country"] for p in only_de["proxies"]} == {"DE"}
    without_us = client.get("/v1/proxies?exclude_country=US").json()
    assert "US" not in {p["country"] for p in without_us["proxies"]}
    multi = client.get("/v1/proxies?country=DE&country=RU").json()
    assert {p["country"] for p in multi["proxies"]} == {"DE", "RU"}


def test_max_latency(client):
    body = client.get("/v1/proxies?max_latency_ms=2000").json()
    assert body["count"] and all(p["latency_ms"] <= 2000 for p in body["proxies"])


def test_google_clean_filter(client):
    body = client.get("/v1/proxies?google_clean=true").json()
    assert body["count"] == 2
    assert all(p["google_clean"] for p in body["proxies"])


def test_anonymity_and_asn_type_filters(client):
    elite = client.get("/v1/proxies?anonymity=elite").json()
    assert {p["anonymity"] for p in elite["proxies"]} == {"elite"}
    body = client.get("/v1/proxies?asn_type=datacenter").json()
    assert {p["asn_type"] for p in body["proxies"]} == {"datacenter"}


def test_min_score(client):
    body = client.get("/v1/proxies?min_score=90").json()
    assert all(p["score"] >= 90 for p in body["proxies"])


def test_max_age_sec(client):
    assert client.get("/v1/proxies?max_age_sec=7200").json()["count"] == 7
    assert client.get("/v1/proxies?max_age_sec=1").json()["count"] == 0


def test_filters_combine(client):
    body = client.get(
        "/v1/proxies?protocol=socks5&country=US&google_clean=true&max_latency_ms=1500"
    ).json()
    assert body["count"] == 1
    assert body["proxies"][0]["proxy"] == "socks5://10.0.0.1:1081"


# ─── output formats ────────────────────────────────────────────────────────


def test_txt_format(client):
    text = client.get("/v1/proxies?protocol=socks5&limit=3&format=txt").text
    lines = text.strip().split("\n")
    assert len(lines) == 3
    assert all(line.startswith("socks5://") and line.count(":") == 2 for line in lines)


def test_txt_format_is_empty_when_nothing_matches(client):
    assert client.get("/v1/proxies?country=ZZ&format=txt").text == ""


def test_csv_format(client):
    response = client.get("/v1/proxies?limit=2&format=csv")
    assert response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 2
    assert rows[0]["proxy"].startswith("socks5://")
    assert "score" in rows[0]


def test_unknown_format_is_rejected(client):
    assert client.get("/v1/proxies?format=yaml").status_code == 422


# ─── /v1/proxy rotation ────────────────────────────────────────────────────


def test_single_proxy_shape(client):
    body = client.get("/v1/proxy").json()
    assert set(body) == {
        "proxy",
        "protocol",
        "host",
        "port",
        "country",
        "country_name",
        "city",
        "asn",
        "asn_org",
        "asn_type",
        "anonymity",
        "latency_ms",
        "google_clean",
        "parser_clean",
        "aiohttp_clean",
        "dual_clean",
        "score",
        "uptime_ratio",
        "last_verified_at",
        "age_sec",
    }
    assert body["proxy"] == f"{body['protocol']}://{body['host']}:{body['port']}"


# ─── ?target= (YouTube reachability) ───────────────────────────────────────


def test_target_only_matches_probed_proxies(client):
    """An unprobed proxy must not pass as YouTube-clean — the columns default to 0."""
    assert client.get("/v1/proxies?target=youtube").json()["count"] == 0
    assert client.get("/v1/proxies?target=parser").json()["count"] == 0
    assert client.get("/v1/proxies?target=aiohttp").json()["count"] == 0


def test_target_filters_on_the_matching_column(client):
    # The stale entry is excluded by max_age_sec whatever its YouTube columns say.
    fresh = [p for p in client.app.state.scheduler.pool if p.last_verified_at != ago(3600)]
    searcher, fetcher, both_ok = fresh[0], fresh[1], fresh[2]
    for proxy in (searcher, fetcher, both_ok):
        proxy.last_yt_at = ago(60)
    searcher.parser_clean = 1
    fetcher.aiohttp_clean = 1
    both_ok.parser_clean = both_ok.aiohttp_clean = both_ok.dual_clean = 1

    search = client.get("/v1/proxies?target=search").json()
    assert {p["proxy"] for p in search["proxies"]} == {searcher.url, both_ok.url}
    aiohttp_only = client.get("/v1/proxies?target=aiohttp").json()
    assert {p["proxy"] for p in aiohttp_only["proxies"]} == {fetcher.url, both_ok.url}
    both = client.get("/v1/proxies?target=youtube").json()
    assert {p["proxy"] for p in both["proxies"]} == {both_ok.url}


def test_a_stale_youtube_verdict_does_not_pass_as_a_fresh_one(client):
    """`max_age_sec` ages the liveness check, and only that.

    Reported from the Lead Engine side: a proxy re-verified alive seconds ago can be
    carrying a YouTube verdict from an hour back, because the YouTube sweep runs on
    its own much slower cadence. The client asked for proxies verified within five
    minutes and got some whose YouTube evidence predated that by an order of
    magnitude, so `?target=youtube` promised more freshness than it had.
    """
    fresh = [p for p in client.app.state.scheduler.pool if p.last_verified_at != ago(3600)]
    stale_verdict, recent_verdict = fresh[0], fresh[1]
    for proxy in (stale_verdict, recent_verdict):
        proxy.parser_clean = proxy.aiohttp_clean = proxy.dual_clean = 1
    stale_verdict.last_yt_at = ago(7200)
    recent_verdict.last_yt_at = ago(60)

    served = client.get("/v1/proxies?target=youtube").json()
    assert {p["proxy"] for p in served["proxies"]} == {recent_verdict.url}

    # The bound is the caller's to widen when a stale verdict is good enough.
    widened = client.get("/v1/proxies?target=youtube&max_target_age_sec=10800").json()
    assert {p["proxy"] for p in widened["proxies"]} == {
        stale_verdict.url,
        recent_verdict.url,
    }


def test_unknown_target_is_rejected(client):
    assert client.get("/v1/proxies?target=tiktok").status_code == 422


def test_two_consecutive_calls_rotate(client):
    first = client.get("/v1/proxy").json()["proxy"]
    second = client.get("/v1/proxy").json()["proxy"]
    assert first != second


def test_rotation_still_answers_when_only_one_proxy_matches(client):
    url = "/v1/proxy?country=DE"
    assert client.get(url).json()["proxy"] == client.get(url).json()["proxy"]


def test_single_proxy_honours_filters(client):
    body = client.get("/v1/proxy?google_clean=true&protocol=socks5").json()
    assert body["google_clean"] is True
    assert body["protocol"] == "socks5"


def test_404_when_no_proxy_matches(client):
    assert client.get("/v1/proxy?country=ZZ").status_code == 404


def test_404_when_pool_is_empty(client):
    client.app.state.scheduler.pool = []
    assert client.get("/v1/proxy").status_code == 404


# ─── /v1/report ────────────────────────────────────────────────────────────


def test_report_rejects_a_malformed_proxy_string(client):
    body = {"proxy": "1.2.3.4:1080", "ok": False, "reason": "timeout"}
    assert client.post("/v1/report", json=body).status_code == 422


def test_report_rejects_an_unknown_scheme(client):
    body = {"proxy": "gopher://1.2.3.4:1080", "ok": True}
    assert client.post("/v1/report", json=body).status_code == 422


def test_report_requires_the_ok_field(client):
    assert client.post("/v1/report", json={"proxy": "socks5://1.2.3.4:1080"}).status_code == 422


# ─── /healthz and auth ─────────────────────────────────────────────────────


def test_healthz_is_open_and_reports_pool_size(client):
    body = client.get("/healthz").json()
    assert body == {"status": "ok", "pool_alive": 7}


def test_api_is_open_without_a_configured_key(client):
    assert client.get("/v1/proxies").status_code == 200


def test_api_key_is_enforced_when_configured(pool, tmp_path):
    settings = Settings(sources=[], api_key="s3cret")
    settings.app.db_path = tmp_path / "t.db"
    scheduler = Scheduler(settings, Storage(settings.app.db_path))
    scheduler.pool = pool
    guarded = TestClient(create_app(settings, scheduler))

    assert guarded.get("/v1/proxies").status_code == 401
    assert guarded.get("/v1/proxies", headers={"X-API-Key": "wrong"}).status_code == 401
    assert guarded.get("/v1/proxies", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert guarded.get("/healthz").status_code == 200  # always open


# ─── the panel shell vs the guarded data ───────────────────────────────────


def test_dashboard_shell_is_reachable_without_a_key(pool, tmp_path):
    """Regression: the shell was guarded, so it could be opened exactly once — through
    the redirect that carries the key in the query string. The panel then strips that
    key out of the address bar, so reloading the page sent no key at all and the
    operator got a raw 401 body instead of their panel. Bookmarking never worked.

    The shell holds no data; every number in it arrives later from `/v1/*`.
    """
    settings = Settings(sources=[], api_key="s3cret")
    settings.app.db_path = tmp_path / "t.db"
    scheduler = Scheduler(settings, Storage(settings.app.db_path))
    scheduler.pool = pool
    client = TestClient(create_app(settings, scheduler))

    for path in ("/", "/dashboard"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "s3cret" not in response.text, path

    # The data behind it stays shut.
    assert client.get("/v1/proxies").status_code == 401
    assert client.get("/v1/stats").status_code == 401
    assert client.get("/v1/logs").status_code == 401
