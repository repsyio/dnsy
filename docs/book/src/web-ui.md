# Web UI

The web interface is an Angular single-page app in `web/`. It is built to `web/dist/dnsy/browser`
and embedded into the binary by `dnsy-api` (feature `embed-ui`), which serves it from `/` with a
single-page-app fallback.

This page covers the shell; the pages themselves (dashboard, zones, filtering, upstreams, query
log, users, settings) arrive with later stories and are placeholders for now.

## Stack

- Angular (standalone components, signals, zoneless change detection, esbuild `application` builder),
  strict TypeScript and strict templates.
- Tailwind CSS, configured with the DNSY design tokens (`branding/tokens.css`) in `src/styles.css`.
- angular-eslint and Prettier for linting, Vitest through `ng test` for unit tests, Playwright
  (`web/playwright.config.ts`, tests in `web/e2e/`) for browser tests.
- pnpm, with the lockfile checked in.

## Tron Legacy theme

Near-black background with a cyan grid, cyan glow as the primary accent, orange for danger,
glowing panels, Orbitron headings and JetBrains Mono body text. Colours, fonts and glows come from
`branding/tokens.css`; the build bundles the self-hosted woff2 fonts (no CDN). The mark and Nox
mascot SVGs are copied from `branding/` into `web/public/` by `pnpm sync:branding` (run by
`pnpm build` and `pnpm start`; `public/` is generated and not committed).

## Strict CSP

The API sends `default-src 'self'` with no inline styles or scripts, so the build must not emit
any. `angular.json` sets `optimization.styles.inlineCritical: false` (no inline critical CSS and no
`onload` handlers) and fonts are not inlined. Rules for UI code:

- Do not use component `styles`/`styleUrl`; Angular would inject `<style>` elements at runtime,
  which the CSP blocks. Style with Tailwind classes or the global stylesheet.
- No inline `style="..."` attributes, no `data:` URIs, no inline event handler attributes.

## Routing and auth

All pages are lazy-loaded (`loadComponent`). `/login` is public; everything else lives under the
layout shell (sidebar navigation, header with the mascot mark) behind `authGuard`, which asks
`GET /api/v1/auth/me` once and redirects to `/login?redirect=<url>` when unauthenticated. Unknown
paths render the 404 page.

The session is an HttpOnly cookie. `apiInterceptor` (same-origin `/api/` calls only):

- adds `X-CSRF-Token` from the `dnsy_csrf` cookie on unsafe methods (double submit);
- maps failures to a typed `ApiError`, carrying the RFC 9457 problem document when the body is
  `application/problem+json`;
- on a 401 clears the session and navigates to `/login`.

`ApiService` is a thin `HttpClient` wrapper rooted at `/api/v1`.

## API types

`web/src/app/api/schema.d.ts` is generated from `openapi/dnsy.json` with `openapi-typescript` and
checked in. Regenerate after an API change with `just openapi` followed by `just web-types`;
`just web` fails when the file is stale.

## Commands

| Command | What it does |
| --- | --- |
| `just web` | `pnpm install --frozen-lockfile`, lint (`ng lint` and Prettier), unit tests with coverage (>= 80%), production build, types drift check. Skipped when node or pnpm is missing. |
| `just web-types` | regenerate the API types |
| `cd web && pnpm start` | dev server on `http://localhost:4200` (proxy API calls to a running dnsy yourself) |

The production build enforces an initial bundle budget of 300 kB (warning) and 400 kB (error), raw.
The three.js login scene (DNSY-46) must stay in a lazy chunk.
