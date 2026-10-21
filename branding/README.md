# DNSY branding

Brand assets and design tokens. The web UI, the docs site and the landing page consume these files; nothing is duplicated elsewhere.

The look is Tron: Ares, modernised: black, white 0.5px hairlines and one strong red. Depth comes from hairlines and spacing, never from halos, shadows or a background grid. Dark only. The full guide, with the contrast measurements, is `docs/book/src/branding.md`.

## Contents

| Path | Use |
| --- | --- |
| `logo.svg` | small mark plus "DNSY" wordmark in Michroma (text with a system fallback, no embedded font) |
| `mark.svg` | the small Nox mark alone (header) |
| `favicon.svg` | the small mark on a near-black square |
| `mascot/nox-{idle,loading,empty,error,success,offline,404}.svg` | Nox poses for UI states and error pages |
| `tokens.css` | CSS custom properties (`--dnsy-*`): the palette, font families and `@font-face` rules |
| `fonts/` | Michroma, Geist and Geist Mono, self-hosted woff2 Latin subsets, with their SIL OFL 1.1 licence texts |

## Palette

| Token | Value | Role |
| --- | --- | --- |
| `--dnsy-bg` | `#050505` | page ground |
| `--dnsy-surface` | `#0d0d0d` | panels, sidebar, header |
| `--dnsy-text` | `#f2f2f2` | text and hairlines |
| `--dnsy-muted` | `#8c8c8c` | labels, hints, inactive nav, form field borders, offline Nox |
| `--dnsy-line` | `#2a2a2a` | dividers and table rules (decorative) |
| `--dnsy-red` | `#ff2e2e` | brand only: Nox eyes and beak, primary buttons, links, focus ring, active nav, login pulses |
| `--dnsy-amber` | `#ffb020` | danger, destructive actions, field errors, warnings, DNSSEC bogus and blocked, error Nox |
| `--dnsy-secure` | `#3ddc97` | DNSSEC secure, OK, success Nox |

Red never means danger; danger and bogus are amber, always with the word. Corners stay near-square (2 to 4px).

## Type

| Family | Weights | File | Use |
| --- | --- | --- | --- |
| Michroma | 400 | `michroma-latin-400-normal.woff2` | wordmark, page and section titles, buttons, badges; always uppercase, tracking about 0.08em (titles), 0.12em (controls), 0.22em (wordmark); never paragraphs or below about 10px |
| Geist | 400, 500, 600 | `geist-latin-{400,500,600}-normal.woff2` | body, tables, forms, navigation |
| Geist Mono | 400, 500 | `geist-mono-latin-{400,500}-normal.woff2` | record data, IPs, configuration, tokens, query log |

The woff2 files are the Latin subsets from Fontsource 5.3.0. Licences: `fonts/OFL-Michroma.txt`, `fonts/OFL-Geist.txt`, `fonts/OFL-GeistMono.txt`.

## Nox

A faceted, helmet-shaped owl head in thin lines (outline, dashed inner outline, chevron brow, light-slit eyes, chevron beak). Lines are 0.5px `--dnsy-text`, eyes and beak `--dnsy-red`; the head stays the same in every pose and the eyes act. The art is drawn in a 200 by 200 design space; each file keeps `viewBox="0 0 64 64"` and scales it with one `scale(0.32)` group, and every stroke uses `vector-effect="non-scaling-stroke"`, so hairlines stay 0.5px at any rendered size. The small mark (`mark.svg`, `favicon.svg`, `logo.svg`) keeps only the outline, brow and eyes at 1px (eyes 1.5px). Geometry and the pose table are in `docs/book/src/branding.md`.

## Usage

Import `tokens.css` once (relative `url(fonts/...)` paths resolve against it, so keep the folder layout or copy `fonts/` with it), then use the variables:

```css
@import "branding/tokens.css";
body { background: var(--dnsy-bg); color: var(--dnsy-text); font-family: var(--dnsy-font-body); }
.card { background: var(--dnsy-surface); border: 0.5px solid var(--dnsy-line); }
code { font-family: var(--dnsy-font-mono); }
```

SVGs are self-contained (no external references, no `<style>`, system font fallbacks for text) and must stay under 20 KB.

## Check

`just check-svg` verifies every SVG is well-formed XML, has a `viewBox`, has no external references and fits the size budget.
