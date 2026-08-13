"""The score that orders every API response, and the per-source hit rate.

    score = 40 * google_clean
          + 25 * uptime_ratio
          + 15 * latency_factor
          + 10 * protocol_weight
          +  5 * anonymity_weight
          +  5 * asn_weight
          - 20 * recent_client_failures
"""

from __future__ import annotations

from .models import ANONYMITY_WEIGHT, ASN_WEIGHT, PROTOCOL_WEIGHT, Proxy, SourceStats
from .storage import age_sec

LATENCY_BEST_MS = 1000
LATENCY_WORST_MS = 5000
CLIENT_FAILURE_DECAY_SEC = 3600
DECAY = 0.9
"""Per-step decay of the sliding uptime window: the newest check weighs ~8x the oldest."""



def uptime_ratio(history: str) -> float:
    """Exponentially weighted success ratio over the stored window of checks.

    `history` is oldest-first, '1' = ok. An empty history is 0.0, not 1.0 — an
    unproven proxy must not outrank a proven one.
    """
    if not history:
        return 0.0
    weighted = 0.0
    total = 0.0
    weight = 1.0
    for mark in reversed(history):  # newest first, each older step worth less
        weighted += weight * (mark == "1")
        total += weight
        weight *= DECAY
    return weighted / total


def latency_factor(latency_ms: int | None) -> float:
    """1.0 below 1 s, 0.0 at 5 s and above, linear in between."""
    if latency_ms is None:
        return 0.0
    if latency_ms <= LATENCY_BEST_MS:
        return 1.0
    if latency_ms >= LATENCY_WORST_MS:
        return 0.0
    return (LATENCY_WORST_MS - latency_ms) / (LATENCY_WORST_MS - LATENCY_BEST_MS)


def client_failure_penalty(fails: int, last_fail_at: str | None) -> float:
    """A client-reported failure costs the full 20 points and fades out over an hour."""
    if fails <= 0:
        return 0.0
    age = age_sec(last_fail_at)
    if age is None:
        return 0.0
    if age >= CLIENT_FAILURE_DECAY_SEC:
        return 0.0
    return min(fails, 3) / 3 * (1 - age / CLIENT_FAILURE_DECAY_SEC)


def score(proxy: Proxy, ratio: float | None = None) -> float:
    ratio = uptime_ratio(proxy.history) if ratio is None else ratio
    value = (
        40 * bool(proxy.google_clean)
        + 25 * ratio
        + 15 * latency_factor(proxy.latency_ms)
        + 10 * PROTOCOL_WEIGHT.get(proxy.protocol, 0.0)
        + 5 * ANONYMITY_WEIGHT.get(proxy.anonymity or "", 0.0)
        + 5 * ASN_WEIGHT.get(proxy.asn_type or "", 0.0)
        - 20 * client_failure_penalty(proxy.client_reports_fail, proxy.last_report_fail_at)
    )
    return round(max(0.0, min(100.0, value)), 1)


def source_score(stats: SourceStats) -> float:
    return stats.alive_total / max(stats.fetched_total, 1)


