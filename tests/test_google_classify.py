"""All four L2 outcomes, against HTML actually returned by Google through a proxy."""

from pathlib import Path

import pytest

from unlimproxy.checker import CAPTCHA_MARKERS, classify_google
from unlimproxy.config import CheckerCfg

FIXTURES = Path(__file__).parent / "fixtures"
CFG = CheckerCfg()


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(errors="replace")


def test_search_ok_real_page():
    body = fixture("google_search_ok.html")
    assert len(body) >= CFG.l2_ok_min_bytes
    assert classify_google(200, body, CFG) == "SEARCH_OK"


def test_captcha_real_sorry_page():
    body = fixture("google_captcha.html")
    assert classify_google(429, body, CFG) == "CAPTCHA"


def test_partial_real_truncated_page():
    body = fixture("google_partial.html")
    assert CFG.l2_partial_min_bytes <= len(body) < CFG.l2_ok_min_bytes
    assert classify_google(200, body, CFG) == "PARTIAL"


def test_fail_on_no_response():
    assert classify_google(None, "", CFG) == "FAIL"
    assert classify_google(None, "whatever came back", CFG) == "FAIL"


def test_fail_on_empty_body():
    assert classify_google(200, "", CFG) == "FAIL"


def test_fail_on_tiny_body():
    assert classify_google(200, "x" * 99, CFG) == "FAIL"


@pytest.mark.parametrize("marker", CAPTCHA_MARKERS)
def test_captcha_marker_beats_size(marker):
    """A big page that still contains a captcha marker is CAPTCHA, not SEARCH_OK."""
    body = "x" * 50_000 + marker.upper()
    assert classify_google(200, body, CFG) == "CAPTCHA"


def test_captcha_wins_over_partial():
    assert classify_google(429, "unusual traffic from your network", CFG) == "CAPTCHA"


def test_size_boundaries_are_inclusive():
    assert classify_google(200, "x" * CFG.l2_ok_min_bytes, CFG) == "SEARCH_OK"
    assert classify_google(200, "x" * (CFG.l2_ok_min_bytes - 1), CFG) == "PARTIAL"
    assert classify_google(200, "x" * CFG.l2_partial_min_bytes, CFG) == "PARTIAL"
    assert classify_google(200, "x" * (CFG.l2_partial_min_bytes - 1), CFG) == "FAIL"


def test_size_is_measured_in_bytes_not_characters():
    """20 000 multi-byte characters are well over 20 000 bytes; 10 000 are not."""
    assert classify_google(200, "中" * 10_000, CFG) == "SEARCH_OK"
    assert classify_google(200, "中" * 500, CFG) == "PARTIAL"


# ─── YouTube reachability ──────────────────────────────────────────────────


def test_google_captcha_markers_would_reject_a_healthy_youtube_page():
    """Regression: the YouTube probe reused CAPTCHA_MARKERS, and a healthy YouTube
    page ships a reCAPTCHA script of its own — so every probe came back negative and
    `?target=` could never match anything."""
    from unlimproxy.checker import CAPTCHA_MARKERS

    healthy_youtube = "<html><script src='/recaptcha/api.js'></script>var ytInitialData = {};"
    assert any(m in healthy_youtube.lower() for m in CAPTCHA_MARKERS)

    cfg = CheckerCfg()
    assert cfg.yt_required_marker in healthy_youtube
