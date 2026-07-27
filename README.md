# Unlim Proxy

A self-hosted, self-updating pool of free proxies, validated against Google and served
over an HTTP API with rotation.

It continuously scrapes 84 public proxy lists, verifies every candidate twice — once for
liveness, once by actually loading a Google search results page — enriches the survivors
with offline GeoIP and ASN data, and hands them out sorted by a quality score.

One Python process, one SQLite file. No Redis, no Postgres, no API keys, no registration.

```bash
git clone https://github.com/<you>/unlim-proxy.git
cd unlim-proxy
docker compose up -d
```

Give it about 15 minutes to fill the pool, then:

```bash
curl -s "localhost:8000/v1/proxy?google_clean=true" | jq
```

Interactive API docs are at <http://localhost:8000/docs>.

---

## Why two levels of validation

A proxy that answers `google.com/generate_204` is alive. That does not mean it can load
Google. Measured on a live sample of proxies that passed the liveness check:

| Result on a real `google.com/search` request | Share |
|---|---:|
| `SEARCH_OK` — full results page, > 20 KB | **21 %** |
| `CAPTCHA` — redirected to `/sorry/`, a few hundred bytes | 34–49 % |
| `FAIL` — died between the two checks | 28–45 % |

So roughly four out of five "working" proxies are useless against Google. Only proxies
that returned a real results page are marked `google_clean: true`.

The second thing worth knowing: **protocol labels lie.** Several large sources dump the
same list into `http.txt`, `socks4.txt` and `socks5.txt`. Unlim Proxy treats the source's
label as a hypothesis and settles the protocol by handshake — SOCKS5, then SOCKS4, then
HTTP, keeping whichever one works.

---

## Expect a few hundred proxies, not thousands

Honest numbers, so nothing here surprises you later:

```
~150 000 unique host:port from 30 sources
      ↓  liveness check, ~6–8 % pass
   ~5 000 – 8 000 alive
      ↓  Google check, ~21 % pass
   ~1 000 – 1 700 google-clean at any instant
      ↓  half-life of a clean proxy: about 5 minutes
   ~200 – 800 simultaneously usable, with continuous re-checking
```

"Unlimited" here means rotation, not volume. A few hundred Google-capable proxies are
alive at once and each one lives for minutes. That is fine for low-rate scraping. For
hundreds of requests per second, free proxies will not carry the load.

This is why every response carries `last_verified_at` and `age_sec`, and why the default
`max_age_sec` is 300. Anything older is not worth handing out.

A full pass over all candidates takes roughly an hour, so the pool keeps growing for the
first hour after a cold start. The queues are prioritised, though — SOCKS5 first, best
sources first — so useful proxies appear within the first minutes.

---

## API

Base prefix `/v1`. If the `API_KEY` environment variable is set, every `/v1/*` request
must carry an `X-API-Key` header. If it is unset the API is open. `/healthz` is always
open.

### `GET /v1/proxy`

One proxy, rotated. Takes the same filters as `/v1/proxies`. Picks at random from the top
20 by score and will not return the same proxy twice within `rotation_cooldown_sec`
(default 30) as long as an alternative exists.

```bash
curl -s "localhost:8000/v1/proxy?google_clean=true&country=US" | jq
```

```json
{
  "proxy": "socks5://47.252.47.39:1080",
  "protocol": "socks5",
  "host": "47.252.47.39",
  "port": 1080,
  "country": "US",
  "country_name": "United States",
  "city": "Henrico",
  "asn": "AS45102",
  "asn_org": "Alibaba (US) Technology Co., Ltd.",
  "asn_type": "datacenter",
  "anonymity": "elite",
  "latency_ms": 942,
  "google_clean": true,
  "score": 91.5,
  "uptime_ratio": 1.0,
  "last_verified_at": "2026-07-25T12:02:46Z",
  "age_sec": 60
}
```

Returns `404` when no proxy matches the filters.

### `GET /v1/proxies`

A filtered list, best score first.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit` | int 1..100000 | 20 | how many to return |
| `protocol` | `http` \| `socks4` \| `socks5` | all | repeatable: `?protocol=socks5&protocol=socks4` |
| `country` | ISO-2 | all | repeatable |
| `exclude_country` | ISO-2 | — | repeatable |
| `max_latency_ms` | int | 5000 | upper bound |
| `google_clean` | bool | `false` | `true` returns only proxies that passed the Google check |
| `target` | `parser` \| `search` \| `aiohttp` \| `youtube` | — | only proxies that passed the YouTube probe (see below) |
| `anonymity` | `elite` \| `anonymous` \| `transparent` | all | |
| `asn_type` | `residential` \| `datacenter` | all | |
| `min_score` | float 0..100 | 0 | |
| `max_age_sec` | int | 300 | how stale the last verification may be |
| `format` | `json` \| `txt` \| `csv` | `json` | `txt` is one `protocol://host:port` per line |

```bash
# plain list, ready to paste into another tool
curl -s "localhost:8000/v1/proxies?protocol=socks5&country=US&limit=10&format=txt"

# residential, elite, verified within the last minute
curl -s "localhost:8000/v1/proxies?asn_type=residential&anonymity=elite&max_age_sec=60" | jq

# everything except two countries, as CSV
curl -s "localhost:8000/v1/proxies?exclude_country=CN&exclude_country=RU&format=csv"

# only proxies that loaded both YouTube pages on their last probe
curl -s "localhost:8000/v1/proxies?target=youtube&limit=50&format=txt"
```

`target` is separate from `google_clean` because loading Google and loading YouTube are
different tests and a proxy routinely passes one and fails the other. `parser` and
`search` mean the search results page, `aiohttp` means channel HTML fetched directly,
`youtube` means both. A proxy that has not been probed yet matches none of them — the
columns start at 0 and only a completed probe sets them.

### `POST /v1/report`

Feedback from your client. A real failure under real load is a better signal than any
synthetic probe, so it is weighted more heavily than the service's own checks: `ok: false`
costs up to 20 score points (decaying over an hour) and triggers an immediate re-check.

```bash
curl -s -X POST localhost:8000/v1/report \
  -H 'content-type: application/json' \
  -d '{"proxy": "socks5://1.2.3.4:1080", "ok": false, "reason": "timeout"}'
```

```json
{"status": "accepted"}
```

### `GET /v1/stats`

Pool composition and per-source hit rates. The `sources` block tells you which entries in
`config.toml` are earning their keep.

```bash
curl -s localhost:8000/v1/stats | jq '.pool, .by_protocol, (.sources | .[0:5])'
```

```json
{
  "pool": {"total": 150193, "alive": 6412, "google_clean": 743, "quarantine": 2103},
  "by_protocol": {"socks5": 4102, "socks4": 1980, "http": 330},
  "by_country": {"US": 812, "CN": 640},
  "by_anonymity": {"elite": 3900, "anonymous": 210, "transparent": 40},
  "by_asn_type": {"residential": 4300, "datacenter": 2100},
  "checks": {"l1_per_min": 4200, "l2_per_min": 180},
  "sources": [{"name": "proxifly", "fetched": 2500, "alive": 168,
               "google_clean": 34, "score": 0.0672,
               "last_fetch": "2026-07-25T11:40:00Z"}],
  "uptime_sec": 3600,
  "last_scrape_at": "2026-07-25T11:40:00Z"
}
```

### `GET /healthz`

```bash
curl -s localhost:8000/healthz
```

```json
{"status": "ok", "pool_alive": 6412}
```

Returns `503` if the pool has been empty for more than 10 minutes after startup.

---

## How a proxy is scored

Every proxy carries a score from 0 to 100, and every list is sorted by it.

```
score = 40 * google_clean          # passed the real Google search check
      + 25 * uptime_ratio          # last 20 checks, exponentially weighted toward recent
      + 15 * latency_factor        # 1.0 under 1 s, 0 at 5 s and above, linear between
      + 10 * protocol_weight       # socks5 = 1.0, socks4 = 0.6, http = 0.2
      +  5 * anonymity_weight      # elite = 1.0, anonymous = 0.6, transparent = 0
      +  5 * asn_weight            # residential = 1.0, datacenter = 0.3
      - 20 * recent_client_failures  # from POST /v1/report, decays over an hour
```

The protocol weights are not arbitrary. Measured hit rates by protocol: SOCKS5 **32 %**,
SOCKS4 **14.5 %**, HTTP **1.0 %**. Not one HTTP proxy in the sample passed the full Google
check. HTTP lists are still scraped — they are cheap — but they are checked last.

Residential and mobile ASNs hit Google's captcha far less often than datacenter ranges,
which is what `asn_type` is for.

---

## Check queues

| Queue | Contents | Interval | Concurrency |
|---|---|---|---|
| `cold` | new candidates from scraping | continuous | 1000 |
| `hot` | confirmed alive | 90 s | 100 |
| `warm` | were alive, failed up to 3 times in a row | 5 min | 200 |
| `l2` | hot proxies whose Google check is over 10 min old | 10 min per proxy | 30 |
| `quarantine` | 3+ consecutive failures | 30 min, one more chance | 50 |
| `youtube` | hot proxies, for the `?target=` filter | 30 min per proxy | 20 |

Ten consecutive failures deletes the proxy. So does being absent from every source for
seven days while dead.

A given proxy is never Google-checked more than once per 10 minutes — hammering
`/search` is itself what triggers the captcha.

The cold queue hands out slots in rounds: one candidate from every source, then the next
from every source, and only within a round does protocol and source hit rate decide the
order. Straight rank ordering does not survive a large backlog — on a 664 000-row
database a 20 000-candidate window went entirely to two sources, and one of them spent
15 668 checks to return nothing. A source with no measured hit rate yet falls back to its
configured priority and ties with a dozen others, so ranking alone cannot break that up.
Rounds sample every source early enough for the scoring to learn what each one is worth.

The cold queue is also the only queue that TCP-pre-probes candidates whose protocol is
already labelled. That is worth about +61 % throughput and costs a few live proxies whose
SYN-ACK is slower than `tcp_probe_timeout_sec`; acceptable when triaging half a million
addresses that are mostly dead, and not acceptable on the queues that re-verify proxies
already in the pool, where a false negative evicts something good.

---

## Configuration

Everything lives in [`config.toml`](config.toml): the source list, queue intervals,
concurrency, timeouts, check URLs, ASN keywords. Any value can be overridden by an
environment variable named `UNLIMPROXY_<SECTION>__<KEY>`:

```bash
UNLIMPROXY_APP__LOG_LEVEL=DEBUG
UNLIMPROXY_QUEUES__COLD_CONCURRENCY=200      # lower this behind consumer NAT
UNLIMPROXY_APP__ROTATION_COOLDOWN_SEC=60
API_KEY=your-secret-here                     # enables X-API-Key on /v1/*
```

Adding a source means adding a block:

```toml
[[sources]]
name = "example"
url = "https://example.com/proxies.txt"
parser = "scan"            # scan | prefixed | plain | geonode | hideip
protocol_hint = "socks5"   # for the plain parser
trust_protocol = false     # false = ignore the label, detect by handshake
priority = 2               # 1 is checked first
```

| Parser | Format |
|---|---|
| `prefixed` | `socks5://1.2.3.4:1080` |
| `plain` | `1.2.3.4:8080` |
| `geonode` | geonode's JSON API, with country/ASN/anonymity metadata |
| `hideip` | `1.2.3.4:8080:CountryName` |
| `scan` | anything — see below |

`scan` is the one to reach for with a new source. Public lists ship the same data as CSV
rows, JSON documents, pipe-delimited tables and bare lines, and they reshuffle their
columns without warning. Rather than a parser per layout, `scan` pulls every address out
of the body wherever it sits, taking a scheme only when it is directly in front of the
address and falling back to `protocol_hint` otherwise. JSON gets a separate walk, because
a payload that keeps the host and the port in different fields has nothing for a
positional regex to match.

Sources are polled with `If-None-Match`, so an unchanged list costs one 304 and no
parsing.

---

## TLS verification is not optional

Certificate verification is on in every check and there is no flag to turn it off.

Free proxies do intercept traffic. A proxy that cannot complete an honest TLS handshake
to Google is discarded, not admitted. Disabling verification would grow the pool and
quietly fill it with man-in-the-middle nodes — please do not add a switch for it.

---

## A warning about Docker on macOS

Run this on Linux. On a Mac, Docker runs inside a VM whose userspace NAT cannot carry
hundreds of concurrent outbound connections to arbitrary ports — which is exactly the
workload here.

Measured on the same machine, same 60 candidates, same minute:

| Where | TCP reachable | Passed the liveness check |
|---|---:|---:|
| macOS directly | 28/60 | 4 |
| Inside the Docker VM | 22/60 | 1 |

Under sustained load the gap widens until it is total: a 15-minute run inside Docker
Desktop / colima checked 34 000 candidates and found **zero** live proxies, while the
identical build running natively on the same Mac found thousands.

This is not a limit of the service. On a Linux VPS the container talks to the network
directly and behaves like the native column. For local development on a Mac, run it
natively (below), or lower the concurrency a lot:

Where the network is not the constraint, concurrency is the one setting that matters.
Measured on 6000 dead candidates:

| `cold_concurrency` | checks/s | process CPU |
|---|---|---|
| 200 | 81 | 10 % |
| 400 | 140 | 9 % |
| 800 | 198 | 8 % |
| 1600 | 268 | 5 % |
| 3000 | 297 | 4 % |

CPU never became the constraint, which is also why there is no uvloop here — at 4-10 %
there is nothing for it to reclaim. Accuracy does not pay for the speed either: a
crossover run over one live set recovered 53.4 % at 400 and 56.0 % at 1600. Raise it as
far as the host's conntrack table and file descriptor limit allow.

```bash
COLD_CONCURRENCY=50 docker compose up -d
```

## Running without Docker

```bash
pip install -e ".[dev]"
python -m unlimproxy
```

Raise the file descriptor limit first — 1000 concurrent checks will exhaust the default
1024:

```bash
ulimit -n 65535
```

The Docker setup already sets `nofile: 65535`.

### Concurrency and the network in front of you

The defaults open up to ~760 sockets at once across the queues, most of them half-open
connections to hosts that will never answer. A VPS with a real public IP handles that
fine. A home or office connection behind consumer NAT usually does not: the NAT table
fills with pending entries, and then *everything* starts failing — including proxies that
are perfectly healthy. It looks exactly like a broken pool.

The signature is a pool that is healthy for the first few minutes and then collapses
toward zero while the cold queue keeps reporting hits. If you see that, cut the
concurrency:

```bash
UNLIMPROXY_QUEUES__COLD_CONCURRENCY=100 \
UNLIMPROXY_QUEUES__WARM_CONCURRENCY=60 \
UNLIMPROXY_QUEUES__HOT_CONCURRENCY=60 \
UNLIMPROXY_QUEUES__L2_CONCURRENCY=15 \
python -m unlimproxy
```

The path recovers within seconds once the load stops, so it is easy to confirm: stop the
service and time a plain `curl https://www.google.com/generate_204`.

### GeoIP databases

Three MaxMind-format databases are downloaded to `data/geo/` on first start and refreshed
daily. No account or key is needed:

- IPLocate IP-to-country and IP-to-ASN (CC BY-SA 4.0)
- DB-IP City Lite (CC BY 4.0)

Lookups are local and take microseconds. If a download fails the service still runs, just
without geo fields.

---

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

Tests cover all four source parsers against real captured samples, the Google response
classifier against real Google HTML (a genuine results page and a genuine `/sorry/`
captcha page), the scoring formula, and every API filter and output format.

```
src/unlimproxy/
├── __main__.py   # API and background loops in one event loop
├── config.py     # config.toml + env overrides, JSON logging
├── models.py
├── storage.py    # SQLite, WAL
├── scraper.py    # concurrent source fetch with ETag revalidation
├── parsers.py
├── checker.py    # L1 liveness, L2 Google, anonymity
├── geo.py        # mmdb download and offline lookup
├── scoring.py
├── scheduler.py  # the five queues and the in-memory hot pool
└── api.py
```

---

## Not included

No web UI or dashboard — `/v1/stats` and FastAPI's `/docs` cover it. No built-in forward
proxy: the service hands out proxy addresses, it does not tunnel your traffic through
them. No paid provider support, no proxy authentication, no IPv6.

## License

MIT — see [LICENSE](LICENSE).
