# DNSY branding

Brand assets and design tokens. The web UI, the docs site and the landing page consume these files; nothing is duplicated elsewhere.

**The logo and the Nox mascot art are temporary.** They are geometric placeholders to be replaced by final artwork; keep the file names and the `viewBox` so the swap is drop-in.

## Contents

| Path | Use |
| --- | --- |
| `logo.svg` | mark plus "DNSY" wordmark lockup |
| `mark.svg` | the Nox owl mark alone |
| `favicon.svg` | app icon on a dark rounded square |
| `mascot/nox-{idle,loading,empty,error,success,offline,404}.svg` | Nox poses for UI states and error pages |
| `tokens.css` | CSS custom properties (`--dnsy-*`): colours, font families, glow shadows, `@font-face` |
| `fonts/` | Orbitron (display) and JetBrains Mono (body/code), self-hosted woff2 subsets, with their SIL OFL 1.1 licence texts |

## Usage

Import `tokens.css` once (relative `url(fonts/...)` paths resolve against it, so keep the folder layout or copy `fonts/` with it), then use the variables:

```css
@import "branding/tokens.css";
body { background: var(--dnsy-bg); color: var(--dnsy-text); font-family: var(--dnsy-font-body); }
.card { background: var(--dnsy-surface); box-shadow: var(--dnsy-glow-md); }
```

`--dnsy-secure` marks DNSSEC-validated answers, `--dnsy-bogus` marks validation failures, `--dnsy-orange` is the accent.

SVGs are self-contained (no external references, system font fallbacks for text) and must stay under 20 KB.

## Check

`just check-svg` verifies every SVG is well-formed XML, has a `viewBox`, has no external references and fits the size budget.
