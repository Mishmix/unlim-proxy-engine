# Unlim Proxy

## What it is

A self-hosted service that keeps a pool of free public proxies continuously verified
and hands them out over an HTTP API. One Python process, one SQLite file, no external
services.

## The mechanism nobody else has

It scrapes 84 public proxy lists into roughly 590 000 distinct addresses, then triages
that backlog against Google twice: once for liveness (`generate_204`), once by actually
loading a search results page and classifying the answer as SEARCH_OK, CAPTCHA, PARTIAL
or FAIL. Only SEARCH_OK counts as usable. A third probe checks whether the proxy can
load YouTube's search results and channel HTML, because passing Google does not imply
passing YouTube.

The number that governs everything: a working free proxy has a half-life of about five
minutes. Pool size is not a function of how many addresses you collected, it is

    steady-state pool ≈ discovery rate (alive/sec) × average lifetime (sec)

So the surface's real job is to show a flow, not a stock. Measured on the reference
host: 684 579 candidate rows, ~115 checks/sec, ~84 alive at any instant, ~17 of those
Google-clean.

## Who uses it and where

One developer, running their own scraper or checker against YouTube or Google. The
service runs on their VPS. The dashboard sits open in a background tab or on a second
monitor for hours; they glance at it between other work. They are technical, they read
`socks5://62.84.100.21:61080` as a single token, and they are not impressed by
decoration.

## What they come to the dashboard to do

1. Answer "is it healthy right now" in under two seconds from across the room.
2. Build and copy an API URL with the filters they need (protocol, target, format,
   count) and paste it into their own code.
3. Spot-check what is actually in the pool: country, latency, score, freshness.
4. See who is calling the API and whether those calls are succeeding.

## Facts the surface must respect

- Numbers move constantly and most of them are small. 84 alive is a normal, healthy
  reading, not an error state.
- Freshness is the whole product. `age_sec` and `last_verified_at` matter more than
  any total.
- The API is key-protected; the dashboard is behind the same key.
- Everything the dashboard shows comes from `/v1/stats`, `/v1/proxies`, `/v1/logs`.
- It must work offline from any CDN: the server ships the HTML from disk and the
  container may have no outbound access for the browser's benefit.

## Brand commitments

None inherited. The existing look was a five-minute draft and is explicitly an
anti-reference, not authority.

## Language

Interface copy is Russian; identifiers, protocol names, URLs and code stay English.
