# Design system — Unlim Proxy control panel

The surface is a **single-line mimic panel**, the diagram a substation or plant operator
reads: the process is drawn once, left to right, and every live value sits on the
topology at the point where it is measured. Nothing is a card. The discipline behind it
is high-performance HMI (ISA-101): the chassis is achromatic, and **colour is reserved
for state**. A screen that a developer leaves open for eight hours must be silent until
something is worth looking at.

## Colour

Colour is a signal, never decoration. Anything that is merely structure is grey.

| Token | Value | Meaning |
|---|---|---|
| `--ground` | `#16181b` | chassis behind everything |
| `--panel` | `#1c1f22` | an instrument face set into the chassis |
| `--panel-lift` | `#23272b` | a raised element: input, active tab, table header |
| `--groove` | `#2c3136` | engraved hairline, 1px, the default separator |
| `--groove-lit` | `#3b4249` | a groove catching light: focus ring, active edge |
| `--ink` | `#e2e6e9` | readings and primary text |
| `--ink-2` | `#9aa1a7` | labels, secondary text |
| `--ink-3` | `#868e94` | de-energised, unavailable, placeholder — the floor for legible text |
| `--live` | `#57c98a` | energised, flowing, passing |
| `--signal` | `#74b6d6` | a measured quantity in flight — rates, throughput |
| `--warn` | `#d7a441` | degraded but working: stale, partial, quarantined |
| `--fault` | `#d9564c` | failed, unreachable, rejected |

Rules:

- The three state colours never appear on a surface that is not reporting that state.
  No amber dividers, no green headings.
- De-energised is grey, not a dim tint of the live colour. A stopped process reads as
  absent, not as a faded version of running.
- Contrast floor 4.5:1 for every text token against the darkest surface it can sit on.
  `--ink-3` is the floor; nothing lighter-on-dark than it carries words.

## Type

System stacks. The container may have no outbound network, so there is no webfont, and
Operate surfaces are well served by workhorse faces set precisely.

- **Readings and any address, rate, count, latency, timestamp:** `ui-monospace,
  SFMono-Regular, Menlo, Consolas, monospace` with `font-variant-numeric: tabular-nums`.
  Monospace here is for measurement, which is what it is for.
- **Legend and prose:** the platform UI stack.
- **Engraved legend:** 10–11px, uppercase, `letter-spacing: .09em`, `--ink-2`. This is
  the only uppercase in the system; it labels instruments and nothing else.
- Scale steps: 10 / 11 / 12 / 13 / 15 / 20 / 30 / 44. A reading is large because it is
  the primary reading, not because a section wants a hero.

## Geometry

- Radius 2px, and 0 on anything that reads as machined metal. There are no pills and no
  soft cards.
- 1px grooves at every boundary. Depth comes from an inset highlight over a dark rule
  (`box-shadow: inset 0 1px 0 rgba(255,255,255,.03)`), the way a panel edge catches
  light — never from a coloured halo.
- Spacing scale 4 / 8 / 12 / 16 / 24 / 32 / 48. Instruments sit tight inside their
  frame and are separated generously from other instruments.

## Motion

One authored idea: **flow**. A process link animates its stripe only while its rate is
above zero, so motion on the page means throughput in the service. Value changes tick
to their new reading rather than tweening, the way a counter steps. Everything else is
still. `prefers-reduced-motion` stops the stripe and leaves the link statically
energised.

## Composition

1. **Chassis header** — nameplate, connection lamp, uptime, last scrape.
2. **Mimic** — the whole pipeline on one line: sources → backlog → L1 → alive → L2 →
   Google-clean → YouTube → API. Vessels carry counts and fill levels, links carry
   rates. This is the thesis and it is the first thing on screen.
3. **Instruments** — throughput trace, protocol and country breakdown, source ranking.
4. **Work area** — the pool and request-log tables on the left, the URL builder as a
   control panel on the right.

On narrow screens the mimic rotates to a vertical line and keeps every value; it is
never replaced by a summary.

## Prohibitions

- No card grid as page structure, no metric tiles.
- No gradient text, no glass, no glow, no coloured left borders.
- Nothing invented: every number on screen comes from `/v1/stats`, `/v1/proxies` or
  `/v1/logs`. A history the panel has not observed yet says so rather than drawing a
  plausible curve.
