# Branding and the mascot

![Nox, the DNSY mascot](../branding/mascot/nox-idle.svg)

DNSY has a Tron Legacy look: a near-black background, a cyan grid and glow, orange for danger and
accents, Orbitron headings and JetBrains Mono text. Its mascot is **Nox**, a small owl that watches
the network at night.

**The logo and the Nox art are temporary geometric placeholders.** Keep the file names and
`viewBox` when replacing them, so the swap is drop-in.

## Assets

Everything lives in `branding/` in the repository; the web UI, the docs and the landing page
consume those files and nothing is duplicated.

| Path | Use |
| --- | --- |
| `logo.svg` | mark plus "DNSY" wordmark |
| `mark.svg` | the owl alone |
| `favicon.svg` | app icon on a dark rounded square |
| `mascot/nox-{idle,loading,empty,error,success,offline,404}.svg` | Nox poses for UI states |
| `tokens.css` | the design tokens (`--dnsy-*`): colours, fonts, glows |
| `fonts/` | Orbitron and JetBrains Mono, self-hosted woff2 subsets (SIL OFL 1.1) |

All SVGs are self-contained (no external references) and under 20 KB; `just check-svg` enforces
that.

## Nox in the interface

| State | Where you see it |
| --- | --- |
| idle | the login scene, the header mark |
| loading | while a page waits for data and during route changes |
| empty | lists with nothing in them |
| error | failed requests, with a Retry button |
| success | confirmations |
| offline | the browser lost its connection |
| 404 | unknown pages |

Animations stop under `prefers-reduced-motion: reduce`, and every pose has a text alternative for
screen readers. The implementation is described under *Mascot components* in [Web UI](web-ui.md).

## Colours

| Token | Meaning |
| --- | --- |
| cyan | primary accent, links, focus |
| orange | danger and destructive actions |
| green (`--dnsy-secure`) | DNSSEC-validated answers |
| red (`--dnsy-bogus`) | validation failures and blocked answers |

## Using the tokens

```css
@import "branding/tokens.css";
body { background: var(--dnsy-bg); color: var(--dnsy-text); font-family: var(--dnsy-font-body); }
```

This book uses the same tokens through `docs/book/theme/tron.css`.
