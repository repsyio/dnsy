# Changelog

All notable changes to DNSY are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to follow
[Semantic Versioning](https://semver.org/) once it has a first release.

## [Unreleased]

### Added

- DNS over UDP and TCP with EDNS0, Extended DNS Errors, truncation, TCP pipelining and bounded
  connection handling.
- DNS over TLS with optional or required mTLS (client CA plus a certificate allowlist) and DNS over
  HTTPS (GET and POST, HTTP/2) with header or path tokens, both with certificate hot reload.
- A caching, forwarding resolver: upstream groups with load balancing, health and routing, a cache
  with negative caching, serve-stale, prefetch, TTL clamping and flush by name or subtree.
- DNSSEC validation (chain of trust, NSEC and NSEC3 proofs, strict, permissive and off modes,
  negative trust anchors, work limits, a clock-safety guard) and zone signing (ECDSA P-256 and
  Ed25519, NSEC or NSEC3, automatic re-signing, key states and rollover, DS export).
- Authoritative JSON zones with hot reload, validation, BIND export (plain and signed) and
  optimistic concurrency through the API.
- Filtering: blocklist sources (hosts, domain and adblock formats) with scheduled refresh and
  atomic swap, custom allow and block rules, client ACL, per-client rate limiting and a
  response-IP policy.
- A query log and statistics in SQLite: batched writer, retention, per-minute and per-hour
  rollups, search with keyset pagination and a live tail.
- Users, roles (admin, operator, viewer), scoped API tokens, server-side sessions, login throttling
  and a one-time bootstrap code for the first admin.
- A REST API under `/api/v1` with an OpenAPI 3.1 document (`openapi/dnsy.json`, `dnsy openapi`).
- A Tron-styled Angular web UI embedded in the binary: a three.js login scene, dashboard, zone
  editor with a DNSSEC tab, query log with live tail, filtering, upstreams, ACL, client
  certificates, cache, DNSSEC, settings, users, tokens and profile pages, and the Nox mascot states.
- A command line: `serve`, `config check`, `migrate`, `user`, `token`, `zone export`, `dnssec keys`,
  `cache flush`, `openapi` and `version`.
- A TOML configuration with `DNSY_SECTION__KEY` environment overrides and an annotated example
  (`examples/dnsy.toml`).
- Documentation: an mdBook (install, quickstart, configuration reference, zones, resolver and
  cache, DNSSEC and its operator guide, filtering, DoT, DoH, auth, query log, web UI, REST API,
  operations, logging and metrics, backup and restore, upgrade, troubleshooting, FAQ, glossary,
  architecture, security, branding), a README with screenshots, a landing page and branding assets.
- Test tooling: unit tests with coverage gates, Rust end-to-end suites against the real binary and
  Playwright browser suites; scripts to run a seeded demo and capture the documentation
  screenshots (`scripts/demo/`).

### Known limitations

- The query log does not store answer records or Extended DNS Error codes, and the web UI has no
  one-click block or allow buttons on log rows.
- Settings changed through `PATCH /api/v1/settings*` apply at once but are runtime-only, except the
  per-client rate limit.
- No Prometheus `/metrics` endpoint.
- No release binaries or hosted documentation site yet (planned with the pipelines).
