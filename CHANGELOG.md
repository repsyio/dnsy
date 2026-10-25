# Changelog

All notable changes to DNSY are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project aims to follow
[Semantic Versioning](https://semver.org/) once it has a first release.

## [Unreleased]

## [0.1.1] - 2026-10-25

### Added

- `dnsy config init` writes a commented starter configuration to the `--config` path; `--dev`
  writes one that runs without root (DNS on 127.0.0.1:5353, state in `./dnsy-data`, public
  upstreams). It refuses to overwrite an existing file without `--force`. The archives also carry
  the sample config as `dnsy.toml`.
- `dnsy serve` and `dnsy config check` warn when `resolver.upstreams` is empty, since every
  forwarded query would then answer SERVFAIL.
- Installers for more platforms: a `.pkg` for macOS (x86_64 and aarch64), an `.msi` for Windows
  and `.deb` and `.rpm` packages for Linux (x86_64 and aarch64). The packages are unsigned; see
  `docs/book/src/release.md`. The Linux packages install the config as `/etc/dnsy/dnsy.toml`,
  the unit and a `dnsy` service user, and never enable or start the service.
- A hardened systemd unit (`examples/dnsy.service`) and a headless and service install page in the
  book.
- `dnsy.dev/install.sh` and `dnsy.dev/install.ps1` ask where to install (system-wide, just you,
  or a local folder; Windows offers just you or a local folder) and whether to write a starter
  config. Flags and environment variables skip the questions; see the release page.
- The landing page shows the install command with a copy button.
- The Linux packages are listed in the release's `sha256.sum`.

### Changed

- **Behaviour change:** `install.sh` run without a terminal now installs to `~/.local/bin`
  instead of `~/.cargo/bin`.
- Bind failures name the protocol, the address and the likely cause (systemd-resolved on port 53,
  needing root or `CAP_NET_BIND_SERVICE`, the config key and `DNSY_*` override). Data, zones and
  database path errors name the path and suggest a writable one.
- The one-time bootstrap code is printed only after every listener has bound, so a failed start
  never shows or burns it.
- The gnu Linux builds are made in `manylinux_2_28` containers and need glibc 2.28 or newer
  (RHEL, Rocky and Alma 8+, Debian 10+, Ubuntu 20.04+); the aarch64 build previously needed 2.39.
- Quickstart and troubleshooting docs cover port 53 and systemd-resolved, running without root,
  setting upstreams and testing with `dig -p`.

## [0.1.0] - 2026-10-23

### Changed

- **Behaviour change:** the default client ACL is private-only. Only loopback, RFC 1918,
  100.64.0.0/10, ULA and link-local clients are answered; other sources get REFUSED. Set
  `[limits] open_resolver = true` to restore the previous allow-all behaviour. `per_client_qps`
  now defaults to 50 (0 still disables the limit). `dnsy serve` and `dnsy config check` warn when
  a non-loopback listener combines `open_resolver = true` with `per_client_qps = 0`.

### Added

- Blocklist matching on CNAME targets: a response whose CNAME chain reaches a blocked name is
  blocked, and the check runs again on every cache hit.
- With Secure cookies the session and CSRF cookies use the `__Host-` prefix
  (`__Host-dnsy_session`, `__Host-dnsy_csrf`); plain-HTTP setups keep the old names.
- During an algorithm rollover the zone is signed with both the old and the new algorithm.
- Release pipeline: pushing a `v*` tag builds `dnsy` with the web UI embedded for Linux (gnu and musl,
  x86_64 and aarch64), macOS (x86_64 and aarch64) and Windows (x86_64) with cargo-dist, and publishes
  archives, SHA-256 checksums and shell and PowerShell installers to a GitHub Release. See
  `docs/book/src/release.md`.
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
- The documentation site is published at dnsy.dev; release binaries appear with the first `v*` tag.
