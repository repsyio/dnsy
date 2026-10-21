# Branding and the mascot

![Nox, the DNSY mascot](../branding/mascot/nox-idle.svg)

DNSY has a Tron: Ares look, modernised: black, white hairlines and one strong red, with no neon halo
and no grid. Depth comes from 0.5px hairlines and spacing, never from shadows. Its mascot is
**Nox**, a faceted owl head drawn in thin geometric lines that watches the network at night.

## Assets

Everything lives in `branding/` in the repository; the web UI, the docs and the landing page
consume those files and nothing is duplicated.

| Path | Use |
| --- | --- |
| `logo.svg` | small mark plus the "DNSY" wordmark in Michroma (text with a system fallback) |
| `mark.svg` | the small Nox mark alone (header) |
| `favicon.svg` | the small mark on a near-black square |
| `mascot/nox-{idle,loading,empty,error,success,offline,404}.svg` | Nox poses for UI states |
| `tokens.css` | the design tokens (`--dnsy-*`): the palette, font families and `@font-face` rules |
| `fonts/` | Michroma, Geist and Geist Mono, self-hosted woff2 Latin subsets (SIL OFL 1.1) |

All SVGs are self-contained (no external references, no embedded fonts) and under 20 KB;
`just check-svg` enforces that.

## Palette

Dark only. Red is the brand and nothing else: danger and DNSSEC bogus are amber, always together
with the word, never colour alone.

| Token | Value | Role |
| --- | --- | --- |
| `--dnsy-bg` | `#050505` | page ground |
| `--dnsy-surface` | `#0d0d0d` | panels, sidebar, header |
| `--dnsy-text` | `#f2f2f2` | text and hairlines |
| `--dnsy-muted` | `#8c8c8c` | labels, hints, inactive nav, form field borders, offline Nox |
| `--dnsy-line` | `#2a2a2a` | dividers and table rules |
| `--dnsy-red` | `#ff2e2e` | brand: Nox eyes and beak, primary buttons, links, focus ring, active nav, login pulses |
| `--dnsy-amber` | `#ffb020` | danger, destructive actions, field errors, warnings, DNSSEC bogus and blocked, error Nox |
| `--dnsy-secure` | `#3ddc97` | DNSSEC secure, OK, success Nox |

Corners stay near-square (2 to 4px). The focus ring is a solid red outline.

### Contrast

WCAG 2.1 contrast ratios, measured from the token values. Targets: at least 4.5:1 for text, at
least 3:1 for the focus ring, interactive borders and icons.

| Foreground | on `--dnsy-bg` | on `--dnsy-surface` | Use and target |
| --- | --- | --- | --- |
| `--dnsy-text` | 18.21:1 | 17.36:1 | body text (4.5:1) |
| `--dnsy-muted` | 6.06:1 | 5.78:1 | labels and hints (4.5:1); form field borders (3:1) |
| `--dnsy-red` | 5.51:1 | 5.26:1 | small link and button text (4.5:1); focus ring (3:1) |
| `--dnsy-amber` | 11.14:1 | 10.63:1 | errors, warnings, bogus badges (4.5:1) |
| `--dnsy-secure` | 11.53:1 | 11.00:1 | secure and OK badges (4.5:1) |
| `--dnsy-line` | 1.42:1 | 1.35:1 | decorative dividers and table rules only (exempt) |

The active navigation link (red text on a 10% red fill over the surface) measures 4.90:1. Because
`--dnsy-line` is too faint to identify a control, form fields take their border from
`--dnsy-muted` (5.78:1 on the surface) and turn red when focused.

## Typography

| Family | Weights | Use |
| --- | --- | --- |
| Michroma | 400 | wordmark, page and section titles, buttons and badges |
| Geist | 400, 500, 600 | body text, tables, forms, navigation |
| Geist Mono | 400, 500 | record data, IP addresses, configuration, tokens, the query log |

Michroma is always uppercase with open tracking: about 0.08em for titles, 0.12em for controls and
0.22em for the wordmark. Titles stay modest (about 21px for a page title) so the wide capitals do
not turn retro; Michroma is never used for paragraphs or below about 10px.

The fonts ship as woff2 Latin subsets from Fontsource 5.3.0 in `branding/fonts/`:
`michroma-latin-400-normal.woff2`, `geist-latin-{400,500,600}-normal.woff2` and
`geist-mono-latin-{400,500}-normal.woff2`, with their licences in `OFL-Michroma.txt`,
`OFL-Geist.txt` and `OFL-GeistMono.txt` (SIL Open Font License 1.1).

## Nox

A faceted, helmet-shaped owl head: sharp ear corners, a chevron brow, light-slit eyes, a small
chevron beak and a dashed inner outline, with nothing on the lower face. Lines are 0.5px
`--dnsy-text`; eyes and beak are `--dnsy-red`. The geometry is drawn in a 200 by 200 design space;
the files keep `viewBox="0 0 64 64"` and scale it with one group transform, and every stroke uses
`vector-effect: non-scaling-stroke` so the hairlines stay 0.5px at any size.

```text
outline   M100 34 L146 20 L162 70 L152 140 L100 178 L48 140 L38 70 L54 20 Z   (0.5px)
inner     M100 46 L138 34 L150 72 L141 133 L100 163 L59 133 L50 72 L62 34 Z   (0.5px, dash 2 4, 45%)
brow      M44 80 L100 98 L156 80                                               (0.5px)
eyes      M62 101.5 H88  M112 101.5 H138                                       (1px, red, round caps)
beak      M93 108 L100 116 L107 108                                            (0.5px, red)
```

The head stays the same in every pose; the eyes act.

| Pose | Look | Motion | Where you see it |
| --- | --- | --- | --- |
| idle | as above | none | the landing page, the book header |
| loading | eyes at 25%, a 9 by 2 red point sweeps across them | 1.6s loop | while a page waits for data |
| empty | relaxed brow, short eyes looking down, beak 6px lower | none | lists with nothing in them |
| error | amber eyes slanted in, lowered brow, amber beak | flicker, 1.4s | failed requests, beside Retry |
| success | green chevron eyes, green beak | a short hop | confirmations |
| offline | grey dashed eyes, head at 50% | none | the browser lost its connection |
| 404 | head tilted -9°, one slit eye and one round eye | none | unknown pages |

The **small mark** (header 32px, favicon 24px, `mark.svg`, `favicon.svg`, `logo.svg`) keeps only
the outline, brow and eyes: lines 1px, eyes 1.5px, no inner dashes and no beak.

All motion stops under `prefers-reduced-motion: reduce`, and every pose has a text alternative for
screen readers. The implementation is described under *Mascot components* in [Web UI](web-ui.md).

## Using the tokens

```css
@import "branding/tokens.css";
body { background: var(--dnsy-bg); color: var(--dnsy-text); font-family: var(--dnsy-font-body); }
h1 { font-family: var(--dnsy-font-display); text-transform: uppercase; letter-spacing: 0.08em; }
.card { background: var(--dnsy-surface); border: 0.5px solid var(--dnsy-line); }
```

This book uses the same tokens through `docs/book/theme/dnsy.css`.
