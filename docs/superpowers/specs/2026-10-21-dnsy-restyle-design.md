# DNSY restyle: Ares red, new Nox, Michroma/Geist and the login page

- Story: [DNSY-108](https://repsyio.atlassian.net/browse/DNSY-108)
- Date: 2026-10-21
- Related: DNSY-67 (GitHub Pages, blocked by this story), DNSY-91 (resolved by this story: login
  scene re-implemented without three), DNSY-105 (login scene idle pause, adapted here)

This document holds the approved design: the story's specification and acceptance criteria, the
mockups from the brainstorm and the login prototype. The mockups and the prototype are copied
here verbatim (they were throwaway HTML fragments rendered in a review frame, so they reference
Google Fonts and a few frame classes; the product self-hosts its fonts).

## Why

The previous Tron Legacy look (cyan neon, a 48px background grid, Orbitron, the thick-outlined
placeholder owl, the three.js light-grid login scene) reads as dated, like an 80s computer drew
it. The new direction is Tron: Ares, modernised: black, white hairlines, one strong red, no neon
halo. This is a restyle: layouts, pages, routes and behaviour stay as they are, with one
exception, the login page.

## Scope

Every surface takes the new look from the single source in `branding/`:

- `branding/` tokens, fonts, logo, mark, favicon and the 7 Nox poses
- Web panel (Angular): `web/src/styles.css`, mascot components in `web/src/app/shared/mascot/`,
  and the login page in `web/src/app/features/login/` (new layout and animation)
- Docs book theme `docs/book/theme/dnsy.css` (renamed from the old theme) and the screenshots in
  `docs/book/src/images/`
- Landing page `docs/landing/index.html` (dnsy.dev)
- `docs/book/src/branding.md`, `docs/book/src/web-ui.md` and `branding/README.md`
- This design spec
- The DNSY Design System artifact (tokens, fonts, marks, component cards, cover), re-synced
  afterwards

Non-goals: no layout or navigation changes outside the login page, no new pages or components, no
light theme.

Wave: post-1.0, landing before DNSY-67 so dnsy.dev and the docs go live with the new look. It
blocks DNSY-67 only; DNSY-64 to 66 do not wait for it.

## Palette (Ares red, dark only)

Starting values from the approved mockups, tuned only to meet contrast, roles kept. They met every
target unchanged (see `docs/book/src/branding.md` for the measured ratios).

| Token | Value | Role |
| --- | --- | --- |
| `--dnsy-bg` | `#050505` | page ground (no grid) |
| `--dnsy-surface` | `#0d0d0d` | panels, sidebar, header |
| `--dnsy-text` | `#f2f2f2` | text and hairlines |
| `--dnsy-muted` | `#8c8c8c` | labels, hints, inactive nav, offline Nox |
| `--dnsy-line` | `#2a2a2a` | dividers and table rules |
| `--dnsy-red` | `#ff2e2e` | brand: Nox eyes and beak, primary buttons, links, focus ring, active nav, login pulses |
| `--dnsy-amber` | `#ffb020` | danger, destructive actions, field errors, warnings, DNSSEC bogus and blocked, error Nox |
| `--dnsy-secure` | `#3ddc97` | DNSSEC secure, OK, success Nox |

- The old cyan, orange, grid and bogus tokens and every halo shadow token are removed. Depth comes
  from 0.5px hairlines and spacing, never halos or drop shadows.
- Red is only for the brand. Danger and bogus are amber, always with the word, never colour alone.
- Corners stay near-square (2 to 4px). Focus ring: solid red outline, at least 3:1 on every surface.
- Contrast: text at least 4.5:1 on bg and surface. Check small red text on surface and amber badges.

## Typography

- Michroma (one weight, 400) for the wordmark, page and section titles, buttons and badges. Always
  uppercase with open tracking (about 0.08em titles, 0.12em controls, 0.22em wordmark). Titles stay
  modest (about 21px page title) so the wide caps don't turn retro. No paragraphs and nothing under
  about 10px.
- Geist (400/500/600) for body, tables, forms and nav.
- Geist Mono (400/500) for record data, IPs, config, tokens and the query log.
- All OFL, self-hosted woff2 Latin subsets in `branding/fonts/` with licence texts. The previous
  display and mono families are removed.

## Nox mascot

A faceted, helmet-shaped owl head in thin geometric lines: sharp ear corners, chevron brow,
light-slit eyes, small chevron beak, dashed inner outline, nothing on the lower face. Lines 0.5px
`--dnsy-text`; eyes and beak `--dnsy-red`. Keep the file names and `viewBox`; SVGs stay
self-contained and under 20 KB (`just check-svg`).

Geometry from the approved mockup (200×200 space; scaled to the files' viewBox):

```
outline   M100 34 L146 20 L162 70 L152 140 L100 178 L48 140 L38 70 L54 20 Z        (0.5px)
inner     M100 46 L138 34 L150 72 L141 133 L100 163 L59 133 L50 72 L62 34 Z        (0.5px, dash 2 4, 45%)
brow      M44 80 L100 98 L156 80                                                    (0.5px)
eyes      M62 101.5 H88  M112 101.5 H138                                            (1px, red, round caps)
beak      M93 108 L100 116 L107 108                                                 (0.5px, red)
```

Poses: the head stays the same and the eyes act.

| Pose | Look | Motion |
| --- | --- | --- |
| idle | as above | none |
| loading | eyes at 25% opacity, a 9×2 red point sweeps 62→129→62 across them | 1.6s loop |
| empty | brow M44 86 L100 96 L156 86; short eyes M68 108 H84, M116 108 H132; beak 6px lower | none |
| error | amber eyes slanted in: M62 97 L88 105, M112 105 L138 97; brow M44 74 L100 100 L156 74 | flicker (opacity dip to 0.2), 1.4s |
| success | green chevron eyes M62 105 L75 98 L88 105, M112 105 L125 98 L138 105 | none (optional short hop) |
| offline | grey (`--dnsy-muted`) eyes dashed 2 3, outline at 50% | none |
| 404 | whole head rotated −9°, left eye slit, right eye a circle r=6 at (125,101) | none |

Small mark (header 32px, favicon 24px, `mark.svg`, `favicon.svg`): outline, brow and eyes only,
lines 1px, eyes 1.5px, no inner dashes and no beak. `logo.svg` = small mark + "DNSY" in Michroma
(text with a system fallback, no embedded font). All motion stops under `prefers-reduced-motion`;
every pose keeps its text alternative.

## Login page (layout change)

Replaces the three.js light-grid scene (grid floor, light cycles, sun, Nox hologram) entirely.
`three` and `@types/three` are removed; this resolves DNSY-91 in favour of re-implementing without
three.

**Desktop and tablet (two columns):** the sign-in block on the left in a column of about 380px:
small Nox mark + DNSY wordmark, one intro line in `--dnsy-muted`, username and password fields, a
red hairline Sign in button, the first-run link. A 0.5px `--dnsy-line` divider separates it from
the right side, which holds the blob canvas.

**The blob:** a wireframe sphere drawn on a plain 2D canvas (no library), white hairlines at 0.5px,
huge and cropped so only its left part shows. Values from the approved prototype:

- Mesh: icosphere, 2 subdivisions (low density), unique edges only.
- Size and position: radius 0.9 × the canvas height, centre at x = 95% of the canvas width,
  y = 55% of its height; simple perspective (camera distance 3.2 radii).
- Morph (strong): radius per vertex `1 + 0.34 × Σ sin(dot(v, dᵢ) × fᵢ + φᵢ) / 2.2` over 5 lobes;
  fᵢ random in 1.5–4, φᵢ advancing at 0.25–0.75 rad/s; each direction dᵢ eases toward a random
  target at 0.15/s and picks a new target at random (about every 12 s), so the shape never
  repeats.
- Motion: rotates 0.12 rad/s around y; x tilt 0.35 ± 0.15 rad, slow.
- Depth: edges bucketed by depth into 5 opacity steps from 0.12 (far) to 0.80 (near).
- Red pulses ("More"): new pulses start at random, on average 1.2 per second, and several run at
  once (usually 2 to 3 on screen). Each pulse picks its own random axis on the unit sphere and
  sweeps a band of edges (|dot(v, axis) − band| < 0.08, band moving from 1.1 to −1.1) across the
  front-facing surface at 0.45–0.8 units/s (about 3 to 5 s per sweep), drawn in `--dnsy-red` at
  85%, like queries passing through. Pulses are discarded once past the far side.

**Phone (narrow, below `md`):** one column; the blob canvas fills the background behind the
sign-in block, dimmed to about half opacity; the block sits on a solid `--dnsy-surface` panel so
fields stay readable.

**Kept behaviour:** pauses on hidden tabs, pixel ratio capped (existing `cappedPixelRatio`),
disposes on leave. With reduced motion or no canvas: one still frame, no pulses. The canvas is
decorative (`aria-hidden`). DNSY-105's idle-pause ask is kept in adapted form (see
Implementation decisions).

## Surfaces

- Web panel: no body grid and no halo shadows. Borders become 0.5px hairlines in `--dnsy-line`
  (interactive borders `--dnsy-red`). `.btn` outline red, `.btn-danger` amber, `.badge-warn`
  amber, `.nav-link-active` a red left rule with a faint red fill. The inline pose SVGs in
  `mascot-frame.ts` and the animations in `mascot.css` are rewritten.
- Docs book: the renamed theme maps mdBook variables to the new tokens; inline code in Geist Mono,
  not orange. The screenshots in `docs/book/src/images/` are retaken.
- dnsy.dev landing: the idle Nox with its float and look-around, wordmark in Michroma (no halo),
  the three links as red hairline buttons.

## Acceptance criteria

- No cyan, orange, halo or grid left anywhere: `grep -rniE "19e6ff|ff8a1f|cyan|glow|orbitron|jetbrains" branding web/src docs/book/theme docs/landing`
  returns nothing (the old names may stay in CHANGELOG).
- `branding/tokens.css` holds exactly the palette above; `web/src/styles.css` `@theme inline` maps
  it; no hex literal outside `branding/tokens.css` except in the SVGs.
- All 7 poses, mark, logo and favicon redrawn as specified, under 20 KB, `just check-svg` green.
- Login page matches the layout and blob above on desktop and phone, including several concurrent
  red pulses; `three` and `@types/three` removed from `web/package.json`; the login Playwright
  specs (and the `responsive` spec) pass, updated for the new page; the canvas stops when the tab
  is hidden and draws one frame under reduced motion (unit-tested).
- Reduced motion freezes every pose (existing `mascot` Playwright spec passes, updated for the new
  markup).
- axe accessibility spec (`web/e2e/a11y.spec.ts`) passes; every text and token pair named above
  meets 4.5:1 (3:1 for focus, borders and icons), recorded in `docs/book/src/branding.md`.
- `docs/book/src/branding.md`, `docs/book/src/web-ui.md` and `branding/README.md` describe the new
  palette, type, Nox and login page; docs screenshots retaken.
- `just docs` output (landing, book) uses the new look, ready for the first GitHub Pages deploy in
  DNSY-67.
- `just ci` green.

## Implementation decisions

- **Field borders use `--dnsy-muted`.** Dividers in `--dnsy-line` are decorative and measure
  1.42:1 on bg (1.35:1 on surface), too faint to identify a control, so form field borders take
  `--dnsy-muted` (5.78:1 on surface, above the 3:1 non-text target) and turn red on focus.
  Buttons keep their red hairline.
- **Beaks follow the eye colour** in the error (amber), success (green) and offline (grey) poses,
  as in the approved pose mockup; idle, loading, empty and 404 keep the red beak. Error, success
  and offline beaks sit at y 110 like the mockup, so the lowered brow does not crowd them.
- **SVG construction.** The standalone files keep `viewBox="0 0 64 64"` (logo `0 0 260 64`) and
  draw the 200×200 geometry inside one `scale(0.32)` group, with
  `vector-effect="non-scaling-stroke"` on every stroke so hairlines stay 0.5px at any rendered
  size. Animated files (loading, error) use SMIL, since `<style>` is banned by `check-svg`.
- **Small mark eyes at y 103**, as in the small-mark mockup and the login prototype (the full
  poses keep y 101.5).
- **DNSY-105 idle pause, adapted.** The canvas also stops after 30 s without pointer or keyboard
  activity and while the password field has focus, and resumes on the next activity or blur. The
  pixel ratio cap stays at 2 (not 1.5) so the 0.5px hairlines stay crisp on high-density screens;
  2D line drawing is cheap. The dashboard request-batching half of DNSY-105 is out of scope (it
  changes the API).

## Approved mockups

The brainstorm's mockups are copied below verbatim.

### Colour direction (card 1, "Ares red", was chosen)

```html
<h2>Colour direction</h2>
<p class="subtitle">Nox at 0.5px hairlines in four palettes, with an outline button and the two DNSSEC badges (secure / bogus) so you see how each palette works in the UI. No glow on any of them.</p>

<style>
  .pal { display:flex; align-items:center; gap:32px; padding:24px 28px; border-radius:6px; background:var(--bg); }
  .pal svg { width:150px; height:150px; flex:none; }
  .ui { display:grid; gap:14px; font-family: ui-sans-serif, system-ui, sans-serif; }
  .ui h4 { margin:0; color:var(--line); font-weight:500; letter-spacing:.14em; font-size:13px; text-transform:uppercase; }
  .ui .txt { margin:0; color:var(--muted); font-size:13px; line-height:1.5; max-width:260px; }
  .ui .row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
  .b { border:0.5px solid var(--primary); color:var(--primary); background:transparent; padding:7px 14px; font-size:12px; letter-spacing:.14em; text-transform:uppercase; border-radius:2px; font-family:inherit; }
  .bd { border:0.5px solid; padding:2px 8px; font-size:10px; letter-spacing:.14em; text-transform:uppercase; border-radius:2px; }
  .sec { color:var(--secure); border-color:var(--secure); }
  .bog { color:var(--bogus); border-color:var(--bogus); }
  .sw { display:flex; gap:6px; } .sw i { width:22px; height:22px; border-radius:2px; border:0.5px solid #ffffff33; }
  .nx-ln { fill:none; stroke:var(--line); stroke-width:.5px; stroke-linejoin:round; vector-effect:non-scaling-stroke; }
  .nx-faint { opacity:.35; } .nx-dash { stroke-dasharray:2 4; opacity:.45; }
  .nx-acl { fill:none; stroke:var(--eye); stroke-width:.5px; vector-effect:non-scaling-stroke; }
  .nx-slit { stroke:var(--eye); stroke-width:1px; vector-effect:non-scaling-stroke; stroke-linecap:round; }
  .p1 { --bg:#050505; --line:#f2f2f2; --muted:#8c8c8c; --eye:#ff2e2e; --primary:#ff2e2e; --secure:#3ddc97; --bogus:#ffb020; }
  .p2 { --bg:#060708; --line:#eef1f4; --muted:#8a939c; --eye:#ff3b3b; --primary:#4fdcff; --secure:#3ddc97; --bogus:#ff3b3b; }
  .p3 { --bg:#070a0d; --line:#e6edf3; --muted:#7f8e99; --eye:#4fd8ff; --primary:#4fd8ff; --secure:#3ddc97; --bogus:#ff5a6a; }
  .p4 { --bg:#0a0a0a; --line:#ffffff; --muted:#8f8f8f; --eye:#ff3030; --primary:#ffffff; --secure:#ffffff; --bogus:#ff3030; }
</style>

<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <symbol id="nox" viewBox="0 0 200 200">
    <path class="nx-ln" d="M100 34 L146 20 L162 70 L152 140 L100 178 L48 140 L38 70 L54 20 Z"/>
    <path class="nx-ln nx-dash" d="M100 46 L138 34 L150 72 L141 133 L100 163 L59 133 L50 72 L62 34 Z"/>
    <path class="nx-ln" d="M44 80 L100 98 L156 80"/>
    <path class="nx-ln nx-faint" d="M100 112 V178 M100 112 L48 140 M100 112 L152 140"/>
    <path class="nx-slit" d="M62 101.5 H88 M112 101.5 H138"/>
    <path class="nx-acl" d="M93 108 L100 116 L107 108"/>
  </symbol>
</svg>

<div class="cards">
  <div class="card" data-choice="ares-red" onclick="toggleSelect(this)">
    <div class="card-image"><div class="pal p1"><svg><use href="#nox"/></svg>
      <div class="ui"><h4>Zones</h4><p class="txt">Red is the brand. Danger moves to amber so it never clashes with the brand red.</p>
      <div class="row"><button class="b">Create zone</button><span class="bd sec">Secure</span><span class="bd bog">Bogus</span></div>
      <div class="sw"><i style="background:#050505"></i><i style="background:#f2f2f2"></i><i style="background:#ff2e2e"></i><i style="background:#3ddc97"></i><i style="background:#ffb020"></i></div></div></div></div>
    <div class="card-body"><h3>1 · Ares red</h3><p>Black, white hairlines, one strong red. The most Tron: Ares, and a clean break from the old cyan.</p></div>
  </div>
  <div class="card" data-choice="red-cyan" onclick="toggleSelect(this)">
    <div class="card-image"><div class="pal p2"><svg><use href="#nox"/></svg>
      <div class="ui"><h4>Zones</h4><p class="txt">Red is Nox's eyes and danger; cyan is links and actions. Two lights, like the film's two sides.</p>
      <div class="row"><button class="b">Create zone</button><span class="bd sec">Secure</span><span class="bd bog">Bogus</span></div>
      <div class="sw"><i style="background:#060708"></i><i style="background:#eef1f4"></i><i style="background:#ff3b3b"></i><i style="background:#4fdcff"></i><i style="background:#3ddc97"></i></div></div></div></div>
    <div class="card-body"><h3>2 · Red + cyan</h3><p>Keeps a thread to today's cyan while red takes over Nox. Richer, but two accents to manage.</p></div>
  </div>
  <div class="card" data-choice="modern-cyan" onclick="toggleSelect(this)">
    <div class="card-image"><div class="pal p3"><svg><use href="#nox"/></svg>
      <div class="ui"><h4>Zones</h4><p class="txt">Today's cyan, calmer and without the glow. The least change; the hairlines and shape do the modernising.</p>
      <div class="row"><button class="b">Create zone</button><span class="bd sec">Secure</span><span class="bd bog">Bogus</span></div>
      <div class="sw"><i style="background:#070a0d"></i><i style="background:#e6edf3"></i><i style="background:#4fd8ff"></i><i style="background:#3ddc97"></i><i style="background:#ff5a6a"></i></div></div></div></div>
    <div class="card-body"><h3>3 · Modern cyan</h3><p>Evolution, not revolution. Recognisably DNSY, but quieter.</p></div>
  </div>
  <div class="card" data-choice="mono-red-signal" onclick="toggleSelect(this)">
    <div class="card-image"><div class="pal p4"><svg><use href="#nox"/></svg>
      <div class="ui"><h4>Zones</h4><p class="txt">Pure white on black. Red appears only for Nox's eyes and real problems, so it always means something.</p>
      <div class="row"><button class="b">Create zone</button><span class="bd sec">Secure</span><span class="bd bog">Bogus</span></div>
      <div class="sw"><i style="background:#0a0a0a"></i><i style="background:#ffffff"></i><i style="background:#8f8f8f"></i><i style="background:#ff3030"></i></div></div></div></div>
    <div class="card-body"><h3>4 · Monochrome + red signal</h3><p>The most minimal and editorial. Secure becomes white (with the word), not green.</p></div>
  </div>
</div>
```

### Typography (option D, "Michroma + Geist", was chosen)

```html
<h2>Typography: which pairing?</h2>
<p class="subtitle">The same panel slice in Ares red; only the fonts change. All are open-licence (OFL) and can be self-hosted like today's fonts.</p>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600&family=Geist+Mono:wght@400;500&family=Chakra+Petch:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono:wght@400;500&family=Space+Grotesk:wght@400;500;600&family=JetBrains+Mono:wght@400;500&family=Michroma&display=swap" rel="stylesheet">

<style>
  .slice { background:#050505; color:#f2f2f2; border-radius:6px; padding:22px 24px; display:grid; gap:16px; font-family:var(--body); }
  .top { display:flex; align-items:center; gap:10px; padding-bottom:14px; border-bottom:.5px solid #2a2a2a; }
  .top svg { width:28px; height:28px; }
  .wm { font-family:var(--head); font-weight:var(--hw); letter-spacing:var(--wmls); font-size:17px; }
  .top .user { margin-left:auto; color:#8c8c8c; font-size:12px; }
  h1.t { margin:0; font-family:var(--head); font-weight:var(--hw); font-size:26px; letter-spacing:var(--hls); text-transform:var(--htt); color:#f2f2f2; }
  .lead { margin:-6px 0 0; color:#8c8c8c; font-size:14px; line-height:1.55; max-width:520px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { text-align:left; font-weight:500; color:#8c8c8c; font-size:11px; letter-spacing:.1em; text-transform:uppercase; padding:6px 10px 6px 0; border-bottom:.5px solid #2a2a2a; }
  td { padding:8px 10px 8px 0; border-bottom:.5px solid #1a1a1a; }
  td.m { font-family:var(--mono); font-size:12.5px; }
  .row { display:flex; gap:10px; align-items:center; }
  .b { border:.5px solid #ff2e2e; color:#ff2e2e; background:transparent; padding:8px 14px; font-family:var(--head); font-weight:500; font-size:12px; letter-spacing:.12em; text-transform:uppercase; border-radius:2px; }
  .bd { border:.5px solid; padding:2px 7px; font-family:var(--head); font-size:10px; letter-spacing:.12em; text-transform:uppercase; border-radius:2px; }
  .sec { color:#3ddc97; } .bog { color:#ffb020; }
  .nx-ln { fill:none; stroke:#f2f2f2; stroke-width:1px; stroke-linejoin:round; vector-effect:non-scaling-stroke; }
  .nx-slit { stroke:#ff2e2e; stroke-width:1.5px; stroke-linecap:round; vector-effect:non-scaling-stroke; }
  .f1 { --head:'Geist', sans-serif; --body:'Geist', sans-serif; --mono:'Geist Mono', monospace; --hw:500; --hls:-.01em; --htt:none; --wmls:.18em; }
  .f2 { --head:'Chakra Petch', sans-serif; --body:'IBM Plex Sans', sans-serif; --mono:'IBM Plex Mono', monospace; --hw:600; --hls:.04em; --htt:uppercase; --wmls:.16em; }
  .f3 { --head:'Space Grotesk', sans-serif; --body:'Space Grotesk', sans-serif; --mono:'JetBrains Mono', monospace; --hw:500; --hls:-.01em; --htt:none; --wmls:.16em; }
  .f4 { --head:'Michroma', sans-serif; --body:'Geist', sans-serif; --mono:'Geist Mono', monospace; --hw:400; --hls:.08em; --htt:uppercase; --wmls:.22em; }
  .f4 h1.t { font-size:21px; }
</style>

<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <symbol id="mini" viewBox="0 0 200 200">
    <path class="nx-ln" d="M100 34 L146 20 L162 70 L152 140 L100 178 L48 140 L38 70 L54 20 Z"/>
    <path class="nx-ln" d="M44 80 L100 98 L156 80"/>
    <path class="nx-slit" d="M62 103 H88 M112 103 H138"/>
  </symbol>
</svg>

<template id="tpl">
  <div class="top"><svg><use href="#mini"/></svg><span class="wm">DNSY</span><span class="user">admin · admin</span></div>
  <h1 class="t">Zones</h1>
  <p class="lead">Authoritative zones served by this node. Signed zones are re-signed automatically before their signatures expire.</p>
  <table><thead><tr><th>Name</th><th>Record</th><th>DNSSEC</th></tr></thead>
  <tbody><tr><td>example.com.</td><td class="m">300 IN A 93.184.216.34</td><td><span class="bd sec">Secure</span></td></tr>
  <tr><td>lab.internal.</td><td class="m">60 IN AAAA 2001:db8::10</td><td><span class="bd bog">Bogus</span></td></tr></tbody></table>
  <div class="row"><button class="b">Create zone</button></div>
</template>

<div class="cards">
  <div class="card" data-choice="geist" onclick="toggleSelect(this)">
    <div class="card-image"><div class="slice f1"></div></div>
    <div class="card-body"><h3>A · Geist + Geist Mono</h3><p>Clean, current and neutral, from the team behind Vercel. Lets Nox carry the character. Headings in normal case.</p></div>
  </div>
  <div class="card" data-choice="chakra-plex" onclick="toggleSelect(this)">
    <div class="card-image"><div class="slice f2"></div></div>
    <div class="card-body"><h3>B · Chakra Petch + IBM Plex</h3><p>Headings with cut corners that echo Nox's facets; Plex Sans and Plex Mono underneath. The most "techy".</p></div>
  </div>
  <div class="card" data-choice="space-grotesk-jbmono" onclick="toggleSelect(this)">
    <div class="card-image"><div class="slice f3"></div></div>
    <div class="card-body"><h3>C · Space Grotesk + JetBrains Mono</h3><p>Geometric with a little quirk; keeps today's mono for record data, so the change is gentler.</p></div>
  </div>
  <div class="card" data-choice="michroma-geist" onclick="toggleSelect(this)">
    <div class="card-image"><div class="slice f4"></div></div>
    <div class="card-body"><h3>D · Michroma + Geist</h3><p>Wide, film-title capitals for headings, like a movie poster, with Geist for reading. Closest to the Tron: Ares title, but the wide caps could start to feel retro again.</p></div>
  </div>
</div>

<script>
  const tpl = document.getElementById('tpl');
  document.querySelectorAll('.slice').forEach(s => s.appendChild(tpl.content.cloneNode(true)));
</script>
```

### Nox: the seven poses and the small mark

```html
<h2>Nox: the seven poses</h2>
<p class="subtitle">A first take: the head stays the same and the eyes do the acting. Loading and error are animated here as they would be in the panel. The bottom row is the simplified small version for the header.</p>

<style>
  .grid7 { display:grid; grid-template-columns:repeat(auto-fill, minmax(170px, 1fr)); gap:12px; }
  .pose { background:#050505; border-radius:6px; padding:18px 8px 14px; display:grid; justify-items:center; gap:10px; }
  .pose svg { width:128px; height:128px; }
  .pose b { font:500 11px/1 ui-sans-serif, system-ui, sans-serif; letter-spacing:.14em; text-transform:uppercase; color:#f2f2f2; }
  .pose span { font:12px/1.4 ui-sans-serif, system-ui, sans-serif; color:#8c8c8c; text-align:center; padding:0 6px; }
  .nx-ln { fill:none; stroke:#f2f2f2; stroke-width:.5px; stroke-linejoin:round; stroke-linecap:round; vector-effect:non-scaling-stroke; }
  .nx-dash { stroke-dasharray:2 4; opacity:.45; }
  .nx-red { fill:none; stroke:#ff2e2e; stroke-width:.5px; stroke-linejoin:round; stroke-linecap:round; vector-effect:non-scaling-stroke; }
  .nx-slit { fill:none; stroke:#ff2e2e; stroke-width:1px; stroke-linecap:round; stroke-linejoin:round; vector-effect:non-scaling-stroke; }
  .amber .nx-slit, .amber .nx-red { stroke:#ffb020; }
  .green .nx-slit, .green .nx-red { stroke:#3ddc97; }
  .grey .nx-slit, .grey .nx-red { stroke:#8c8c8c; }
  .grey .nx-ln { opacity:.5; }
  .dim { opacity:.25; }
  .flicker { animation: flick 1.4s steps(2, jump-none) infinite; }
  @keyframes flick { 0%,70% { opacity:1 } 85% { opacity:.2 } }
  .small { display:flex; gap:28px; align-items:center; justify-content:center; background:#050505; border-radius:6px; padding:22px; margin-top:16px; }
  .small svg.s32 { width:32px; height:32px; } .small svg.s24 { width:24px; height:24px; } .small svg.s64 { width:64px; height:64px; }
  .small .nx-ln, .small .nx-red { stroke-width:1px; }
  .small .nx-slit { stroke-width:1.5px; }
  .small span { font:12px/1.4 ui-sans-serif, system-ui, sans-serif; color:#8c8c8c; }
</style>

<svg width="0" height="0" style="position:absolute" aria-hidden="true">
  <symbol id="shell" viewBox="0 0 200 200">
    <path class="nx-ln" d="M100 34 L146 20 L162 70 L152 140 L100 178 L48 140 L38 70 L54 20 Z"/>
    <path class="nx-ln nx-dash" d="M100 46 L138 34 L150 72 L141 133 L100 163 L59 133 L50 72 L62 34 Z"/>
  </symbol>
  <symbol id="small" viewBox="0 0 200 200">
    <path class="nx-ln" d="M100 34 L146 20 L162 70 L152 140 L100 178 L48 140 L38 70 L54 20 Z"/>
    <path class="nx-ln" d="M44 80 L100 98 L156 80"/>
    <path class="nx-slit" d="M62 103 H88 M112 103 H138"/>
  </symbol>
</svg>

<div class="grid7">
  <div class="pose"><svg viewBox="0 0 200 200"><use href="#shell"/>
    <path class="nx-ln" d="M44 80 L100 98 L156 80"/><path class="nx-slit" d="M62 101.5 H88 M112 101.5 H138"/><path class="nx-red" d="M93 108 L100 116 L107 108"/></svg>
    <b>Idle</b><span>Steady eyes. Login, header.</span></div>

  <div class="pose"><svg viewBox="0 0 200 200"><use href="#shell"/>
    <path class="nx-ln" d="M44 80 L100 98 L156 80"/><path class="nx-slit dim" d="M62 101.5 H88 M112 101.5 H138"/>
    <rect x="62" y="100.5" width="9" height="2" fill="#ff2e2e"><animate attributeName="x" values="62;129;62" dur="1.6s" repeatCount="indefinite"/></rect>
    <path class="nx-red" d="M93 108 L100 116 L107 108"/></svg>
    <b>Loading</b><span>A point of light scans across the eyes.</span></div>

  <div class="pose"><svg viewBox="0 0 200 200"><use href="#shell"/>
    <path class="nx-ln" d="M44 86 L100 96 L156 86"/><path class="nx-slit" d="M68 108 H84 M116 108 H132"/><path class="nx-red" d="M94 114 L100 120 L106 114"/></svg>
    <b>Empty</b><span>Brow relaxed, short eyes looking down. Nothing here yet.</span></div>

  <div class="pose amber"><svg viewBox="0 0 200 200"><use href="#shell"/>
    <path class="nx-ln" d="M44 74 L100 100 L156 74"/><g class="flicker"><path class="nx-slit" d="M62 97 L88 105 M112 105 L138 97"/></g><path class="nx-red" d="M93 110 L100 118 L107 110"/></svg>
    <b>Error</b><span>Eyes slant in, amber, a short flicker. Sits beside Retry.</span></div>

  <div class="pose green"><svg viewBox="0 0 200 200"><use href="#shell"/>
    <path class="nx-ln" d="M44 80 L100 98 L156 80"/><path class="nx-slit" d="M62 105 L75 98 L88 105 M112 105 L125 98 L138 105"/><path class="nx-red" d="M93 110 L100 118 L107 110"/></svg>
    <b>Success</b><span>Eyes turn up into smiling chevrons, green.</span></div>

  <div class="pose grey"><svg viewBox="0 0 200 200"><use href="#shell"/>
    <path class="nx-ln" d="M44 80 L100 98 L156 80"/><path class="nx-slit" stroke-dasharray="2 3" d="M62 101.5 H88 M112 101.5 H138"/><path class="nx-red" d="M93 108 L100 116 L107 108"/></svg>
    <b>Offline</b><span>Grey, eyes broken into dashes. Signal lost.</span></div>

  <div class="pose"><svg viewBox="0 0 200 200"><g transform="rotate(-9 100 100)"><use href="#shell"/>
    <path class="nx-ln" d="M44 80 L100 98 L156 80"/><path class="nx-slit" d="M62 101.5 H88"/><circle class="nx-slit" cx="125" cy="101" r="6"/><path class="nx-red" d="M93 108 L100 116 L107 108"/></g></svg>
    <b>404</b><span>Head tilted, one eye wide. Confused.</span></div>
</div>

<div class="small">
  <svg class="s64" viewBox="0 0 200 200"><use href="#small"/></svg>
  <svg class="s32" viewBox="0 0 200 200"><use href="#small"/></svg>
  <svg class="s24" viewBox="0 0 200 200"><use href="#small"/></svg>
  <span>Small version (64 / 32 / 24px): outline, brow and eyes only; lines thicken to 1px so it survives at header and favicon sizes.</span>
</div>
```

### Login prototype (login-blob-v3, approved settings: white + red pulse, low density, "More" pulses, huge, strong morph)

```html
<h2>Login: more red pulses (live sketch v3)</h2>
<p class="subtitle">Throwaway prototype in plain canvas, no libraries. Use the switches under it to try colour, density and how much it morphs.</p>

<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500&family=Michroma&display=swap" rel="stylesheet">

<style>
  .lg { display:grid; grid-template-columns: 380px 1fr; min-height:600px; background:#050505; border-radius:6px; overflow:hidden; font-family:'Geist', sans-serif; color:#f2f2f2; }
  .lg-left { padding:56px 44px; display:flex; flex-direction:column; justify-content:center; gap:18px; border-right:.5px solid #1c1c1c; }
  .lg-brand { display:flex; align-items:center; gap:12px; }
  .lg-brand svg { width:34px; height:34px; }
  .lg-wm { font-family:'Michroma', sans-serif; letter-spacing:.22em; font-size:18px; }
  .lg-lead { margin:0 0 6px; color:#8c8c8c; font-size:13px; line-height:1.5; }
  .lg label { display:block; font-size:11px; letter-spacing:.1em; text-transform:uppercase; color:#8c8c8c; margin-bottom:6px; }
  .lg input { width:100%; box-sizing:border-box; background:#050505; border:.5px solid #2a2a2a; border-radius:2px; padding:10px 12px; color:#f2f2f2; font:inherit; font-size:14px; }
  .lg input:focus { outline:none; border-color:#ff2e2e; }
  .lg button.go { margin-top:6px; width:100%; border:.5px solid #ff2e2e; background:transparent; color:#ff2e2e; padding:11px; font-family:'Michroma', sans-serif; font-size:11px; letter-spacing:.16em; text-transform:uppercase; border-radius:2px; cursor:pointer; }
  .lg-link { font-size:12px; color:#8c8c8c; text-align:center; }
  .lg-right { position:relative; }
  .lg-right canvas { position:absolute; inset:0; width:100%; height:100%; display:block; }
  .nx-ln { fill:none; stroke:#f2f2f2; stroke-width:1px; stroke-linejoin:round; vector-effect:non-scaling-stroke; }
  .nx-slit { stroke:#ff2e2e; stroke-width:1.5px; stroke-linecap:round; vector-effect:non-scaling-stroke; }
  .ctl { display:flex; flex-wrap:wrap; gap:18px; margin-top:12px; font-size:13px; }
  .ctl fieldset { border:1px solid var(--border, #444); border-radius:6px; padding:6px 10px; display:flex; gap:10px; }
  .ctl legend { font-size:11px; opacity:.7; padding:0 4px; }
  .ctl label { cursor:pointer; }
</style>

<div class="lg">
  <div class="lg-left">
    <div class="lg-brand">
      <svg viewBox="0 0 200 200"><path class="nx-ln" d="M100 34 L146 20 L162 70 L152 140 L100 178 L48 140 L38 70 L54 20 Z"/><path class="nx-ln" d="M44 80 L100 98 L156 80"/><path class="nx-slit" d="M62 103 H88 M112 103 H138"/></svg>
      <span class="lg-wm">DNSY</span>
    </div>
    <p class="lg-lead">Sign in to manage zones, filtering and DNSSEC on this node.</p>
    <div><label for="u">Username</label><input id="u" autocomplete="off"></div>
    <div><label for="p">Password</label><input id="p" type="password" autocomplete="off"></div>
    <button class="go" type="button">Sign in</button>
    <div class="lg-link">First run? Set up the admin account</div>
  </div>
  <div class="lg-right"><canvas id="blob"></canvas></div>
</div>

<div class="ctl">
  <fieldset><legend>Colour</legend>
    <label><input type="radio" name="col" value="white"> White</label>
    <label><input type="radio" name="col" value="red"> Red</label>
    <label><input type="radio" name="col" value="mix" checked> White + red pulse</label>
  </fieldset>
  <fieldset><legend>Density</legend>
    <label><input type="radio" name="den" value="2" checked> Low</label>
    <label><input type="radio" name="den" value="3"> Medium</label>
    <label><input type="radio" name="den" value="4"> High</label>
  </fieldset>
  <fieldset><legend>Pulses</legend>
    <label><input type="radio" name="pul" value="0.4"> As before</label>
    <label><input type="radio" name="pul" value="1.2" checked> More</label>
    <label><input type="radio" name="pul" value="2.5"> Lots</label>
  </fieldset>
  <fieldset><legend>Size</legend>
    <label><input type="radio" name="size" value="0.6,0.75"> Large</label>
    <label><input type="radio" name="size" value="0.9,0.95" checked> Huge</label>
    <label><input type="radio" name="size" value="1.3,1.15"> Massive</label>
  </fieldset>
  <fieldset><legend>Morph</legend>
    <label><input type="radio" name="amp" value="0.1"> Subtle</label>
    <label><input type="radio" name="amp" value="0.2"> Medium</label>
    <label><input type="radio" name="amp" value="0.34" checked> Strong</label>
  </fieldset>
</div>

<script>
(() => {
  const canvas = document.getElementById('blob');
  const ctx = canvas.getContext('2d');
  let verts = [], edges = [];

  function icosphere(level) {
    const p = (1 + Math.sqrt(5)) / 2;
    let v = [[-1,p,0],[1,p,0],[-1,-p,0],[1,-p,0],[0,-1,p],[0,1,p],[0,-1,-p],[0,1,-p],[p,0,-1],[p,0,1],[-p,0,-1],[-p,0,1]];
    let f = [[0,11,5],[0,5,1],[0,1,7],[0,7,10],[0,10,11],[1,5,9],[5,11,4],[11,10,2],[10,7,6],[7,1,8],[3,9,4],[3,4,2],[3,2,6],[3,6,8],[3,8,9],[4,9,5],[2,4,11],[6,2,10],[8,6,7],[9,8,1]];
    const norm = a => { const l = Math.hypot(...a); return a.map(x => x / l); };
    v = v.map(norm);
    for (let s = 0; s < level; s++) {
      const cache = new Map(), nf = [];
      const mid = (a, b) => {
        const k = a < b ? a + '_' + b : b + '_' + a;
        if (!cache.has(k)) { v.push(norm([0,1,2].map(i => (v[a][i] + v[b][i]) / 2))); cache.set(k, v.length - 1); }
        return cache.get(k);
      };
      for (const [a, b, c] of f) { const ab = mid(a,b), bc = mid(b,c), ca = mid(c,a); nf.push([a,ab,ca],[b,bc,ab],[c,ca,bc],[ab,bc,ca]); }
      f = nf;
    }
    const es = new Set();
    for (const [a, b, c] of f) for (const [x, y] of [[a,b],[b,c],[c,a]]) es.add(x < y ? x + '_' + y : y + '_' + x);
    verts = v; edges = [...es].map(k => k.split('_').map(Number));
  }

  // a few random lobes whose directions and phases drift, so the shape never repeats
  const rnd = () => { const t = Math.random() * 2 * Math.PI, z = Math.random() * 2 - 1, r = Math.sqrt(1 - z*z); return [r*Math.cos(t), r*Math.sin(t), z]; };
  const lobes = Array.from({ length: 5 }, () => ({ d: rnd(), target: rnd(), f: 1.5 + Math.random() * 2.5, ph: Math.random() * 6.28, sp: 0.25 + Math.random() * 0.5 }));

  let colour = 'mix', amp = 0.34, scale = 0.9, offx = 0.95;
  icosphere(2);
  document.querySelectorAll('.ctl input').forEach(i => i.addEventListener('change', () => {
    if (i.name === 'col') colour = i.value;
    if (i.name === 'den') icosphere(+i.value);
    if (i.name === 'amp') amp = +i.value;
    if (i.name === 'pul') rate = +i.value;
    if (i.name === 'size') { const [a, b] = i.value.split(',').map(Number); scale = a; offx = b; }
  }));

  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let t = 0, last = performance.now(), rate = 1.2; const pulses = [];

  function frame(now) {
    const dt = Math.min((now - last) / 1000, 0.1); last = now; t += dt;
    const dpr = Math.min(devicePixelRatio || 1, 2);
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (canvas.width !== w * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    for (const L of lobes) {
      L.ph += L.sp * dt;
      for (let i = 0; i < 3; i++) L.d[i] += (L.target[i] - L.d[i]) * dt * 0.15;
      if (Math.random() < dt * 0.08) L.target = rnd();
    }
    const ry = t * 0.12, rx = 0.35 + Math.sin(t * 0.07) * 0.15;
    const cy = Math.cos(ry), sy = Math.sin(ry), cx = Math.cos(rx), sx = Math.sin(rx);
    const R = h * scale, ox = w * offx, oy = h * 0.55, cam = 3.2;

    const P = verts.map(v => {
      let d = 0;
      for (const L of lobes) d += Math.sin((v[0]*L.d[0] + v[1]*L.d[1] + v[2]*L.d[2]) * L.f + L.ph);
      const r = 1 + amp * d / 2.2;
      let x = v[0]*r, y = v[1]*r, z = v[2]*r;
      [x, z] = [x*cy + z*sy, -x*sy + z*cy];
      [y, z] = [y*cx - z*sx, y*sx + z*cx];
      const s = cam / (cam - z);
      return [ox + x * R * s, oy + y * R * s, z];
    });

    // pulses: each sweeps a band across the surface along its own random axis
    if (colour === 'mix' && Math.random() < dt * rate) pulses.push({ axis: rnd(), p: 0, speed: 0.45 + Math.random() * 0.35 });
    for (const q of pulses) q.p += dt * q.speed;
    while (pulses.length && pulses[0].p > 2.2) pulses.shift();
    const buckets = [[], [], [], [], []];
    for (const [a, b] of edges) {
      const z = (P[a][2] + P[b][2]) / 2;
      buckets[Math.max(0, Math.min(4, Math.floor((z + 1.3) / 2.6 * 5)))].push(a, b);
    }
    ctx.lineWidth = 0.5;
    buckets.forEach((list, i) => {
      const alpha = 0.12 + i * 0.17;
      const base = colour === 'red' ? '255,46,46' : '242,242,242';
      ctx.strokeStyle = `rgba(${base},${alpha})`;
      ctx.beginPath();
      for (let k = 0; k < list.length; k += 2) { const p = P[list[k]], q = P[list[k+1]]; ctx.moveTo(p[0], p[1]); ctx.lineTo(q[0], q[1]); }
      ctx.stroke();
    });
    if (colour === 'mix' && pulses.length) {
      ctx.strokeStyle = 'rgba(255,46,46,.85)';
      ctx.beginPath();
      for (const q of pulses) {
        const band = 1.1 - q.p;
        for (const [a, b] of edges) {
          const va = verts[a], k = va[0]*q.axis[0] + va[1]*q.axis[1] + va[2]*q.axis[2];
          if (Math.abs(k - band) < 0.08 && P[a][2] > -0.2) { ctx.moveTo(P[a][0], P[a][1]); ctx.lineTo(P[b][0], P[b][1]); }
        }
      }
      ctx.stroke();
    }
    if (!reduce) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
})();
</script>
```
