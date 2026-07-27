from pathlib import Path

import pytest

from unlimproxy.config import SourceCfg
from unlimproxy.parsers import normalize_protocol, parse

FIXTURES = Path(__file__).parent / "fixtures"


def src(**kwargs) -> SourceCfg:
    base = {"name": "test", "url": "http://x", "parser": "plain"}
    return SourceCfg(**(base | kwargs))


# ─── prefixed ──────────────────────────────────────────────────────────────


def test_prefixed_reads_scheme_as_protocol():
    body = "socks5://1.2.3.4:1080\nsocks4://5.6.7.8:4145\nhttp://9.9.9.9:8080\n"
    got = parse(src(parser="prefixed"), body)
    assert [(c.protocol, c.host, c.port) for c in got] == [
        ("socks5", "1.2.3.4", 1080),
        ("socks4", "5.6.7.8", 4145),
        ("http", "9.9.9.9", 8080),
    ]


def test_prefixed_maps_scheme_aliases():
    body = "https://1.2.3.4:8080\nsocks5h://5.6.7.8:1080\nsocks4a://9.9.9.9:4145\n"
    assert [c.protocol for c in parse(src(parser="prefixed"), body)] == [
        "http",
        "socks5",
        "socks4",
    ]


def test_prefixed_without_trust_drops_the_protocol():
    body = "socks5://1.2.3.4:1080\n"
    assert parse(src(parser="prefixed", trust_protocol=False), body)[0].protocol is None


def test_prefixed_real_fixture():
    body = (FIXTURES / "proxifly.txt").read_text()
    got = parse(src(name="proxifly", parser="prefixed"), body)
    assert len(got) == 50
    assert all(c.protocol in {"http", "socks4", "socks5"} for c in got)
    assert all(c.source == "proxifly" for c in got)


# ─── plain ─────────────────────────────────────────────────────────────────


def test_plain_uses_hint_when_trusted():
    got = parse(src(protocol_hint="socks5", trust_protocol=True), "1.2.3.4:1080\n")
    assert got[0].protocol == "socks5"


def test_plain_drops_hint_when_untrusted():
    got = parse(src(protocol_hint="socks5", trust_protocol=False), "1.2.3.4:1080\n")
    assert got[0].protocol is None


def test_plain_ignores_comments_blank_lines_and_trailing_fields():
    body = "# comment\n\n1.2.3.4:1080 US\n// another\n5.6.7.8:8080\n"
    got = parse(src(protocol_hint="http"), body)
    assert [(c.host, c.port) for c in got] == [("1.2.3.4", 1080), ("5.6.7.8", 8080)]


def test_plain_real_fixture_untrusted_protocol():
    body = (FIXTURES / "speedx_socks5.txt").read_text()
    got = parse(
        src(name="speedx_socks5", protocol_hint="socks5", trust_protocol=False), body
    )
    assert len(got) == 50
    assert all(c.protocol is None for c in got)


# ─── hideip ────────────────────────────────────────────────────────────────


def test_hideip_strips_trailing_country_name():
    body = "1.2.3.4:1080:United States\n5.6.7.8:8080:Russian Federation\n"
    got = parse(src(parser="hideip", protocol_hint="socks5"), body)
    assert [(c.host, c.port, c.protocol) for c in got] == [
        ("1.2.3.4", 1080, "socks5"),
        ("5.6.7.8", 8080, "socks5"),
    ]


def test_hideip_real_fixture():
    body = (FIXTURES / "hideip_socks5.txt").read_text()
    got = parse(
        src(name="zloi_socks5", parser="hideip", protocol_hint="socks5", trust_protocol=False),
        body,
    )
    assert len(got) == 50
    assert all(c.protocol is None for c in got)


# ─── geonode ───────────────────────────────────────────────────────────────


def test_geonode_real_fixture_carries_metadata():
    body = (FIXTURES / "geonode.json").read_text()
    got = parse(src(name="geonode", parser="geonode"), body)
    assert got
    first = got[0]
    assert first.host and 0 < first.port < 65536
    assert first.protocol in {"http", "socks4", "socks5"}
    assert first.country is None or len(first.country) == 2
    assert first.anonymity in {None, "elite", "anonymous", "transparent"}
    assert first.google_hint in {True, False}


def test_geonode_emits_one_candidate_per_protocol():
    body = """{"data": [{"ip": "1.2.3.4", "port": "8080",
        "protocols": ["socks4", "socks5"], "anonymityLevel": "elite",
        "asn": "AS123", "org": "Acme", "city": "Berlin", "country": "de",
        "google": true}]}"""
    got = parse(src(parser="geonode"), body)
    assert {c.protocol for c in got} == {"socks4", "socks5"}
    assert got[0].country == "DE"
    assert got[0].city == "Berlin"
    assert got[0].asn == "AS123"
    assert got[0].asn_org == "Acme"
    assert got[0].anonymity == "elite"
    assert got[0].google_hint is True


def test_geonode_survives_garbage():
    assert parse(src(parser="geonode"), "not json at all") == []
    assert parse(src(parser="geonode"), '{"data": "nope"}') == []
    assert parse(src(parser="geonode"), '{"data": [{"ip": "x", "port": "y"}]}') == []


# ─── validation, shared across parsers ─────────────────────────────────────


@pytest.mark.parametrize(
    "line",
    [
        "999.1.1.1:8080",  # not an IPv4 address
        "1.2.3.4:0",  # port out of range
        "1.2.3.4:70000",  # port out of range
        "127.0.0.1:8080",  # loopback
        "10.0.0.1:8080",  # private
        "192.168.1.1:3128",  # private
        "2001:db8::1:8080",  # IPv6 is a non-goal
        "garbage",
    ],
)
def test_invalid_entries_are_dropped(line):
    assert parse(src(protocol_hint="http"), line + "\n") == []


def test_normalize_protocol():
    assert normalize_protocol("SOCKS5") == "socks5"
    assert normalize_protocol("https") == "http"
    assert normalize_protocol("ftp") is None
    assert normalize_protocol(None) is None


# ─── scan: layout-agnostic extraction ──────────────────────────────────────


def scan_source(**kwargs) -> SourceCfg:
    return SourceCfg(name="s", url="u", parser="scan", **kwargs)


def test_scan_reads_a_csv_row_and_takes_the_leading_scheme():
    body = "protocol,proxy,country\nsocks5,1.2.3.4:1080,DE\nhttp,5.6.7.8:8080,US\n"
    got = parse(scan_source(trust_protocol=True), body)
    assert [(c.host, c.port, c.protocol) for c in got] == [
        ("1.2.3.4", 1080, "socks5"),
        ("5.6.7.8", 8080, "http"),
    ]


def test_scan_reads_json_objects():
    body = '[{"ip": "9.9.9.9", "port": "3128", "protocols": ["http"]}]'
    got = parse(scan_source(protocol_hint="http", trust_protocol=True), body)
    assert [(c.host, c.port, c.protocol) for c in got] == [("9.9.9.9", 3128, "http")]


def test_scan_reads_a_pipe_delimited_table():
    body = "1.2.3.4:1080 | SOCKS5 | DE | elite\n5.6.7.8:4145 | SOCKS4 | US | anonymous\n"
    got = parse(scan_source(protocol_hint="socks5", trust_protocol=True), body)
    assert [(c.host, c.port) for c in got] == [("1.2.3.4", 1080), ("5.6.7.8", 4145)]


def test_scan_falls_back_to_the_hint_when_no_scheme_is_present():
    got = parse(scan_source(protocol_hint="socks4", trust_protocol=True), "1.2.3.4:1080\n")
    assert got[0].protocol == "socks4"


def test_scan_ignores_labels_when_the_protocol_is_not_trusted():
    got = parse(scan_source(protocol_hint="http", trust_protocol=False), "socks5://1.2.3.4:1080")
    assert got[0].protocol is None


def test_scan_drops_invalid_addresses():
    body = "0.0.0.0:80\n127.0.0.1:8080\n10.0.0.1:3128\n999.1.1.1:80\n8.8.8.8:0\n8.8.8.8:3128\n"
    got = parse(scan_source(), body)
    assert [(c.host, c.port) for c in got] == [("8.8.8.8", 3128)]


def test_scan_deduplicates_within_one_body():
    got = parse(scan_source(protocol_hint="http", trust_protocol=True), "1.2.3.4:80\n1.2.3.4:80\n")
    assert len(got) == 1


def test_scan_reads_json_that_keeps_host_and_port_apart():
    body = (
        '{"data": [{"ip": "9.9.9.9", "port": 3128, "protocols": ["socks5"]},'
        ' {"host": "8.8.8.8", "port": "1080", "protocol": "http"}]}'
    )
    got = parse(scan_source(trust_protocol=True), body)
    assert [(c.host, c.port, c.protocol) for c in got] == [
        ("9.9.9.9", 3128, "socks5"),
        ("8.8.8.8", 1080, "http"),
    ]
