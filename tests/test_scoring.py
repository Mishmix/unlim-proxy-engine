from datetime import UTC, datetime, timedelta

import pytest

from unlimproxy.models import Proxy, SourceStats
from unlimproxy.scoring import (
    client_failure_penalty,
    latency_factor,
    score,
    source_score,
    uptime_ratio,
)


def proxy(**kwargs) -> Proxy:
    base = {"id": 1, "host": "1.2.3.4", "port": 1080, "protocol": "socks5"}
    return Proxy(**(base | kwargs))


def ago(seconds: int) -> str:
    return (datetime.now(UTC) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── uptime ────────────────────────────────────────────────────────────────


def test_uptime_of_unproven_proxy_is_zero():
    assert uptime_ratio("") == 0.0


def test_uptime_all_ok_and_all_fail():
    assert uptime_ratio("1" * 20) == 1.0
    assert uptime_ratio("0" * 20) == 0.0


def test_uptime_weighs_recent_checks_more():
    """Same 50 % success rate; the one that succeeded most recently scores higher."""
    recent_good = uptime_ratio("0000011111")
    recent_bad = uptime_ratio("1111100000")
    assert recent_good > 0.5 > recent_bad
    assert recent_good + recent_bad == pytest.approx(1.0)


def test_uptime_is_bounded():
    for history in ["1", "0", "10", "01", "1" * 20, "0" * 19 + "1"]:
        assert 0.0 <= uptime_ratio(history) <= 1.0


# ─── latency ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("latency", "expected"),
    [(None, 0.0), (0, 1.0), (999, 1.0), (1000, 1.0), (3000, 0.5), (5000, 0.0), (9000, 0.0)],
)
def test_latency_factor(latency, expected):
    assert latency_factor(latency) == pytest.approx(expected)


# ─── client feedback ───────────────────────────────────────────────────────


def test_client_failure_penalty_decays_over_an_hour():
    assert client_failure_penalty(0, ago(10)) == 0.0
    assert client_failure_penalty(3, None) == 0.0
    fresh = client_failure_penalty(3, ago(1))
    half = client_failure_penalty(3, ago(1800))
    assert fresh == pytest.approx(1.0, abs=0.01)
    assert half == pytest.approx(0.5, abs=0.02)
    assert client_failure_penalty(3, ago(3600)) == 0.0
    assert client_failure_penalty(3, ago(7200)) == 0.0


def test_client_failure_penalty_saturates():
    assert client_failure_penalty(3, ago(1)) == client_failure_penalty(99, ago(1))


# ─── score ─────────────────────────────────────────────────────────────────


def test_perfect_proxy_scores_100():
    best = proxy(
        google_clean=1,
        history="1" * 20,
        latency_ms=500,
        protocol="socks5",
        anonymity="elite",
        asn_type="residential",
    )
    assert score(best) == 100.0


def test_worst_proxy_scores_zero():
    assert score(proxy(protocol="http", latency_ms=9000, anonymity="transparent")) == 2.0
    assert score(proxy(protocol="unknown", latency_ms=9000)) == 0.0


def test_google_clean_is_worth_40_points():
    kwargs = {"history": "1" * 20, "latency_ms": 500, "anonymity": "elite"}
    assert score(proxy(google_clean=1, **kwargs)) - score(proxy(google_clean=0, **kwargs)) == 40.0


def test_protocol_weight_ordering():
    kwargs = {"history": "1" * 5, "latency_ms": 2000}
    socks5 = score(proxy(protocol="socks5", **kwargs))
    socks4 = score(proxy(protocol="socks4", **kwargs))
    http = score(proxy(protocol="http", **kwargs))
    assert socks5 > socks4 > http
    assert socks5 - http == pytest.approx(8.0)


def test_anonymity_and_asn_weights():
    kwargs = {"history": "1" * 5, "latency_ms": 2000}
    assert score(proxy(anonymity="elite", **kwargs)) - score(
        proxy(anonymity="transparent", **kwargs)
    ) == pytest.approx(5.0)
    # 5 * (1.0 - 0.3), within the 0.1 granularity the published score is rounded to
    assert score(proxy(asn_type="residential", **kwargs)) - score(
        proxy(asn_type="datacenter", **kwargs)
    ) == pytest.approx(3.5, abs=0.1)


def test_client_failures_subtract_up_to_20():
    kwargs = {"google_clean": 1, "history": "1" * 20, "latency_ms": 500, "anonymity": "elite"}
    clean = score(proxy(**kwargs))
    reported = score(proxy(client_reports_fail=3, last_report_fail_at=ago(1), **kwargs))
    assert clean - reported == pytest.approx(20.0, abs=0.2)


def test_score_is_clamped_to_0_100():
    ugly = proxy(client_reports_fail=5, last_report_fail_at=ago(1), protocol="http")
    assert 0.0 <= score(ugly) <= 100.0
    assert score(ugly) == 0.0


def test_score_accepts_a_precomputed_ratio():
    p = proxy(history="0" * 20)
    assert score(p, ratio=1.0) - score(p) == pytest.approx(25.0)


# ─── source scoring ────────────────────────────────────────────────────────


def test_source_score_is_alive_over_fetched():
    assert source_score(SourceStats("x", fetched_total=2500, alive_total=168)) == pytest.approx(
        0.0672
    )
    assert source_score(SourceStats("empty")) == 0.0
