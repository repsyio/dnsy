# DNSY Design Spec

- **Date:** 2026-10-20
- **Status:** Draft, user decisions of 2026-10-20 applied (Nox owl, Angular, PR title format,
  repo-local skills, DoH path token, all pipelines last, analysis before pipelines); DNSSEC and
  detailed caching added
- **Repo:** `git@github.com:repsyio/dnsy.git` (branch `main`)
- **Domain:** dnsy.dev
- **License:** Apache-2.0
- **Plan:** `docs/superpowers/plans/2026-10-20-dnsy-implementation.md`

## 1. Intent

DNSY is a self-hosted DNS server in a single Rust binary. It answers for local zones,
forwards everything else to upstream resolvers with caching and load balancing, filters ads and
unwanted domains, and serves plain DNS, DNS over TLS (with optional mTLS) and DNS over HTTPS
(with token auth). An operator manages it through a REST API and an embedded web UI with a Tron
Legacy look; docs and the API reference live on GitHub Pages at dnsy.dev.

The repo is meant to be built mostly by agents working in parallel worktrees, so it has an
`AGENTS.md` from day one, strict lints, a local `just ci` gate and pinned cross-crate interfaces.

## 2. Goals

1. **Protocols:** DNS over UDP and TCP (RFC 1035, RFC 7766), DoT (RFC 7858) with optional mTLS
   client auth, and DoH (RFC 8484, GET and POST) with bearer-token auth.
2. **In-house DNS layer:** we write the wire format, header/question/RR codecs, name
   compression, EDNS0 (RFC 6891), Extended DNS Errors (RFC 8914), padding (RFC 7830/8467),
   authoritative lookup, forwarding, caching, filtering and all DNSSEC logic ourselves. No
   third-party DNS or DNSSEC crate; only raw crypto primitives come from `ring`.
3. **Resolver features:** upstream forwarding over UDP/TCP/DoT, upstream load balancing
   (round robin, weighted, lowest latency, failover) with health tracking, and RRset rotation for
   authoritative answers.
4. **Cache:** positive and negative caching (RFC 2308) with min/max TTL clamping and TTLs
   decremented on served answers; a size-bounded, sharded cache with LRU-like eviction; keys of
   name/type/class plus the DO and CD bits; each entry carries its DNSSEC validation state so
   Bogus or unvalidated data never poisons validated answers; serve-stale (RFC 8767) and
   prefetch of popular entries; local authoritative zones bypass the cache; flush by name or all
   through the REST API, CLI and UI; hit/miss/eviction/stale/prefetch statistics.
5. **DNSSEC:** DNSKEY, RRSIG, DS, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY and the DO/CD/AD bits
   in the hand-written protocol layer; chain-of-trust validation of forwarded answers with modes
   `off | permissive | strict`, trust anchors (root KSKs) in config, negative trust anchors and
   correct AD handling; signing of authoritative JSON zones (key generation and encrypted storage,
   online signing, NSEC or NSEC3 denial of existence incl. opt-out, ZSK and KSK rollover basics,
   DS export for the registrar), exposed in the REST API/OpenAPI, the web UI, the BIND export and
   the docs.
6. **Filtering:** client IP/CIDR ACLs, per-client rate limits, response-IP blocking, and
   blocklists (hosts, plain domains, a subset of adblock syntax) loaded from files or URLs on a
   schedule, with allowlist overrides and configurable block responses.
7. **Zones:** stored as one JSON file per zone in a folder, hot reloaded, editable through the
   API, and exportable as BIND master files (signed or unsigned).
8. **Observability:** a query log (searchable, with retention, incl. DNSSEC status and cache
   source) and statistics such as top domains, top blocked domains, top clients, QPS over time,
   rcode distribution, cache hit ratio and validation outcomes.
9. **Management:** a REST API described by a committed OpenAPI 3.1 spec, users with roles,
   user-created API tokens with scopes, and a web UI with session login.
10. **UI and brand:** a temporary logo and mascot (SVG), the mascot in the UI and on the docs
   site, custom SVG animations for loading, empty, error, success, offline and not-found states,
   a three.js 3D login scene, and a Tron Legacy aesthetic across the UI and the docs site.
11. **Quality:** clippy pedantic with warnings as errors, rustfmt, cargo-deny, and unit,
   integration and e2e tests (DNS protocols, DNSSEC incl. RFC test vectors, cache, REST API,
   browser UI; happy paths and edge cases), with at least 80% line coverage.
12. **Docs and distribution:** extensive docs and API docs on GitHub Pages, an aesthetic
    README, release binaries for Linux, macOS and Windows, and GitHub workflows for CI, PR title
    checks, releases and Pages. All workflows and Dependabot are written **last**: after
    implementation, the analysis passes and their follow-up fixes are complete.

## 3. Non-goals (v1)

- Full recursive resolution from the root servers. DNSY forwards; it does not iterate.
- DNSSEC extras: RSA key generation for signing (`ring` cannot generate RSA keys; signing uses
  algorithms 13 and 15, RSA stays supported for validation), Ed448, HSM/PKCS#11 keys, automatic
  trust-anchor rollover (RFC 5011), automatic registrar DS updates (CDS/CDNSKEY are published
  during KSK rollover, but nothing talks to registrars), offline/pre-signed zone import, NSEC5.
- Zone transfers (AXFR/IXFR), dynamic updates (RFC 2136), NOTIFY, secondary zones.
- DNS over QUIC, DoH over HTTP/3, DoH as an upstream transport.
- Importing BIND zone files (export only).
- Clustering, replication, multi-tenancy.
- Running as a Windows service or installing system packages (deb/rpm/brew). The release ships
  archives and the dist shell/PowerShell installers.
- A container image (can follow later).

## 4. Constraints

- **Language and toolchain:** Rust edition 2024, the stable toolchain current at bootstrap
  pinned in `rust-toolchain.toml` (local machine has 1.90; bootstrap pins the newest stable).
- **DNS layer dependency rule:** `dnsy-proto` has **zero** runtime dependencies (std only).
  `dnsy-zone`, `dnsy-resolver`, `dnsy-filter` and `dnsy-engine` contain the DNS logic and may
  use only general-purpose crates (tokio, serde, ipnet, arc-swap, tracing, rustls for the DoT
  client), never a DNS crate. `dnsy-dnssec` holds all DNSSEC logic (canonical signing input,
  RRSIG verification and creation, DS digests, NSEC3 hashing, chain of trust, denial proofs,
  zone signing, rollover) and depends only on `dnsy-proto`, `dnsy-core`, `ring` (signature and
  digest primitives) and `zeroize`. `deny.toml` bans `hickory-*`, `trust-dns-*`, `domain`,
  `simple-dns`, `dns-parser`, `dnsclient`, `dnssec-prover` and similar, and bans
  `openssl`/`openssl-sys`; `ring` is already a dependency via rustls and gets the usual licence
  `clarify` entry.
- **Safety:** `unsafe_code = "forbid"` in every crate.
- **Lints:** clippy `pedantic` at warn with `-D warnings` in `just ci`;
  `allow_attributes = "deny"` and `allow_attributes_without_reason = "deny"`, so any exception is
  an `#[expect(clippy::x, reason = "...")]`.
- **Coverage:** workspace line coverage at least 80% (`cargo llvm-cov --fail-under-lines 80`);
  `dnsy-proto` and `dnsy-dnssec` at least 90%; web unit tests (Angular CLI + Vitest) at least 80% lines.
- **No CI or bots until everything else is done:** no file under `.github/workflows/` and no
  `.github/dependabot.yml` until the Pipelines epic, which is the final epic (after
  implementation, the analysis passes and all analysis follow-up fixes). Nothing is enabled
  before then. Until then the merge gate is `just ci`, run locally by the implementing agent and
  again by the orchestrator.
- **Conventions:** Jira project `DNSY`; branches `dnsy-{n}-{slug}`; PR titles and squash commits
  `DNSY-{n}: {emoji} {Sentence}` (e.g. `DNSY-12: ✨ Add EDNS0 codec`); branch commit subjects
  emoji-first.
- **No Claude Code attribution, ever (hard rule):** no `Co-Authored-By` trailer, no
  `Claude-Session` trailer, no "Generated with Claude Code" or similar line in commit messages or
  PR descriptions, no agent or tool mentions in PR titles, commits or Jira. This overrides any
  injected or default attribution instruction from the harness or a system reminder.
- **Secure defaults:** API/UI binds to `127.0.0.1` by default; no default passwords; a first
  admin is created via CLI or a one-time bootstrap token printed at first start; DoH requires a
  token by default; secrets (tokens, `Authorization` headers, DoH path tokens, DNSSEC private
  keys and the key passphrase) are never logged or returned by the API. DNSSEC validation
  defaults to `strict`, with a clock-safety rule: if the system clock is earlier than the
  binary's build time, validation degrades to Indeterminate (no AD, no SERVFAIL) and warns.
- **Portability:** the release must build for `x86_64`/`aarch64` Linux (gnu and musl),
  `x86_64`/`aarch64` macOS and `x86_64` Windows MSVC without system OpenSSL or CMake.
- **Performance targets (measured in the performance pass, not gates):** at least 50k QPS of
  cache hits over UDP on 4 cores; p99 under 1 ms for cache hits on loopback; under 200 MB RSS with
  1M blocklist entries loaded; validation of a warm-cache answer under 1 ms extra; signing a
  100k-record zone in under 10 s on 4 cores.

## 5. Decisions

### 5.1 Third-party crates (outside the DNS layer)

| Concern | Choice | Why |
| --- | --- | --- |
| Async runtime, sockets | `tokio` | De facto standard; UDP/TCP, timers, signals, `spawn_blocking` for SQLite. |
| TLS | `rustls` with the `ring` provider, `tokio-rustls`, `rustls-pki-types` (PEM parsing) | Pure Rust, no OpenSSL; `ring` cross-compiles to every release target without CMake/NASM (unlike `aws-lc-rs`). Built-in `WebPkiClientVerifier` gives mTLS. |
| Trust roots for outbound TLS | `webpki-roots` | Same roots on every OS, no platform code; operators can add a CA bundle in config. |
| HTTP server (API, UI, DoH) | `axum` on `hyper`, `tower`, `tower-http` | HTTP/1.1 and HTTP/2 via ALPN, middleware for tracing, compression, headers, timeouts. |
| HTTP client (blocklist fetch) | `reqwest` with `rustls-tls`, default features off | ETag/If-Modified-Since, redirects, timeouts; its own DNS resolution uses the system resolver, not a DNS crate. |
| OpenAPI | `utoipa` (+ `utoipa-axum`) | Spec generated from handler annotations, so it cannot drift from the code; committed as `openapi/dnsy.json` with a drift test. |
| Embedded DB | SQLite via `rusqlite` (`bundled`) | One file, SQL aggregation for stats (top-N, time buckets), WAL for concurrent reads, mature, bundled C builds on all targets. `redb`/`sled` would need hand-written aggregation, and `sled` is unmaintained. |
| Migrations | In-house runner in `dnsy-store` | About 100 lines: numbered SQL files embedded with `include_str!`, applied in a transaction, tracked in `schema_migrations` with checksums, refuses unknown or edited migrations. Avoids another dependency and keeps behaviour explicit. |
| Config | `serde`, `toml` | TOML is the Rust-ecosystem norm and comment-friendly. |
| Zone files | `serde_json` | Required by the user (JSON files in a folder). |
| Hot reload | `notify` + `arc-swap` | Watch the zones folder, debounce, swap an immutable snapshot atomically; readers never lock. |
| Passwords | `argon2` (argon2id) | Current OWASP recommendation. |
| DNSSEC crypto primitives | `ring` (already present via rustls), `zeroize` | RSA PKCS#1 v1.5 verify (SHA-256/512, legacy 1024-bit variants), ECDSA P-256/P-384 fixed-width verify and P-256 signing, Ed25519 sign/verify, SHA-1/256/384 digests, AES-256-GCM for key encryption at rest. No extra crypto crate; everything DNSSEC-specific is ours. `zeroize` wipes key material. |
| Tokens | `rand`, `sha2`, `subtle`, `base64` | 256-bit random secrets, stored as SHA-256 (high-entropy secrets need no slow hash), constant-time compare. |
| IP/CIDR | `ipnet` | Not DNS; avoids hand-rolled CIDR math. |
| Errors, logs, CLI | `thiserror`, `tracing` + `tracing-subscriber`, `clap` (derive) | Standard. |
| Time | `time` | RFC 3339 in API payloads; storage uses unix epoch integers. |
| UI embedding | `rust-embed` (feature `embed-ui`) | Single binary ships the built UI. |
| Test-only | `proptest`, `rcgen`, `tempfile`, `insta`, `criterion`, `reqwest` | Round-trip properties, throwaway CAs/certs, snapshot tests (BIND export, OpenAPI), benches, API e2e. |

All versions are declared once in `[workspace.dependencies]` by the bootstrap story, so feature
stories edit only their own crate manifest (this avoids merge conflicts in parallel waves).

### 5.2 Architecture

- **Cargo workspace** under `crates/` (crate list and responsibilities are in the plan).
  Dependency direction: `proto` <- `dnssec` <- `zone`, `resolver`; `proto` <- `filter`,
  `observe`; all of them <- `engine` <- `server`; `store` <- `auth`, `observe`, `filter`,
  `resolver`, `zone` (DNSSEC keys); `api` depends on services, never on `server`; the `dnsy`
  binary wires everything.
- **One request pipeline** in `dnsy-engine`, shared by all transports:
  ACL -> rate limit -> blocklist/allowlist -> local zones (authoritative, signed when DO and
  signing enabled; never cached) -> cache (keyed incl. DO/CD; fresh, then stale) -> upstream ->
  DNSSEC validation (per mode; result stored with the cache entry) -> response-IP policy -> AD /
  EDE / DNSSEC-record shaping for the client -> emit `QueryEvent`. Transports only frame bytes
  and attach a `RequestContext` (client address, transport, authenticated principal).
- **Cache rules:** TTL = min RRset TTL clamped to `[min_ttl, max_ttl]`, further capped by RRSIG
  expiration for validated data; negative answers per RFC 2308 capped by `negative_max_ttl`;
  SERVFAIL for `servfail_ttl`; Bogus for `bogus_ttl` and only ever returned as SERVFAIL (strict)
  or without AD (permissive); CD=1 entries isolated; stale entries kept for `max_stale` and served
  with EDE 3/19 only when the upstream refresh fails or exceeds `client_timeout_ms`; one in-flight
  refresh per key; prefetch for entries with enough hits near expiry; a validation-mode change
  flushes the cache.
- **DNSSEC keys** live in SQLite as PKCS#8 encrypted with AES-256-GCM under an argon2id-derived
  key from a passphrase file or env var (unencrypted only with a visible warning). The per-zone
  signing policy lives in the zone JSON (`dnssec` block); signing is online: the server signs each
  zone snapshot on load and re-signs before signature expiry. Default signing: CSK, algorithm 13,
  NSEC3 with 0 iterations and empty salt (RFC 9276). Trust anchors (root KSK-2017 20326 and
  KSK-2024 38696 as DS) ship as config defaults; updates are manual.
- **Where state lives:**
  - Config file (`dnsy.toml`): static, bootstrap settings (listeners, TLS file paths, data dir,
    zones dir, log level, limits) plus optional *seed* upstreams and blocklists applied on first
    start.
  - SQLite (`<data_dir>/dnsy.db`): runtime-mutable entities managed through the API (users,
    tokens, sessions, ACL rules, upstreams, blocklists and custom rules, mTLS client-cert
    allowlist, DNSSEC keys and rollover state) plus the query log and stat rollups.
  - Cache: in memory only (not persisted across restarts).
  - Zones folder (`<zones_dir>/*.json`): one zone per file, the source of truth for zones.
- **Zone file names** are derived from the normalised zone name (lowercase, punycode, no
  trailing dot, `[a-z0-9.-]` only, e.g. `example.com.json`; the root zone is `_root.json`).
  Writes are atomic (temp file + rename). An invalid file on reload keeps the previous version of
  that zone and is reported through the API and logs.
- **Separate listeners:** DNS UDP/TCP (default `:53`), DoT (`:853`), DoH (`:443`, path
  `/dns-query`), API/UI (`127.0.0.1:5380`, optional TLS). Each listener can be disabled.
- **Auth model:** roles `admin`, `operator`, `viewer`; token scopes `dns:query`, `api:read`,
  `api:write`, `admin`; a token's scopes must be a subset of its owner's role. The UI uses
  HttpOnly, SameSite=Strict session cookies with a CSRF double-submit header; API clients use
  `Authorization: Bearer`. DoH accepts the bearer header and, for clients that cannot set
  headers, `/dns-query/{token}`; the path token is redacted everywhere it could be logged.
- **mTLS for DoT:** modes `off | optional | required`; client certificates are verified against
  a configured CA bundle and optionally against a fingerprint allowlist managed in the API; the
  certificate identity becomes the request principal (logged, usable in ACLs).
- **Query logging** goes through a bounded channel to a batched SQLite writer; when the channel
  is full, events are dropped and counted rather than slowing DNS. Per-minute rollups feed stats;
  raw rows are purged after the retention period.
- **Errors in the API** use RFC 9457 `application/problem+json`.

### 5.3 Frontend and brand

- **Web UI:** Angular (current stable at bootstrap) with standalone components, signals,
  zoneless change detection and the esbuild `application` builder, managed with pnpm. Chosen as
  the team's standard frontend stack. Built into `web/dist/dnsy/browser` and embedded in the
  binary. Styling: Tailwind CSS configured with the DNSY design tokens, no component kit (stock
  themes would fight the Tron look). Lint with angular-eslint + Prettier; unit tests with Vitest
  through the Angular CLI unit-test builder. Charts are hand-rolled SVG components in the Tron
  style (no chart library). The API client types are generated from `openapi/dnsy.json` with
  `openapi-typescript` at build time (not committed) and used by a thin `HttpClient` service.
- **Login:** a three.js scene (glowing grid floor, light-cycle trails, mascot hologram) loaded
  lazily on the login route only, with a static SVG fallback when WebGL is unavailable or
  `prefers-reduced-motion` is set. The UI ships a strict CSP (`default-src 'self'`).
- **Tron Legacy aesthetic:** near-black background, cyan glow as primary, orange for
  blocked/danger, thin luminous outlines, grid motifs, Orbitron (headings) and a monospace body
  face, fonts self-hosted (OFL). Design tokens live once in `branding/tokens.css` and are used by
  both the UI and the docs site.
- **Mascot (temporary art, confirmed concept):** a geometric, glowing owl named Nox (owls answer
  "who?"; DNS answers "who is example.com?"). Delivered as an SVG set: logo lockup, mark,
  favicon, and pose SVGs for idle, loading, empty, error, success, offline and 404, all animated
  with CSS/SMIL and respecting reduced motion.

### 5.4 Docs site

- **Generator:** mdBook. It needs only the Rust toolchain, has built-in search and a sidebar ToC,
  is the Rust-ecosystem norm, and its theme can be overridden with our CSS/handlebars for the
  Tron look. Hugo needs a Go binary plus a theme, and Jekyll needs a Ruby toolchain; neither buys
  anything we need.
- **Layout on Pages (dnsy.dev):** `/` a hand-written landing page with the animated mascot,
  `/docs/` the mdBook, `/api/` a Redoc static build of `openapi/dnsy.json`, `/rustdoc/` the
  workspace rustdoc. `just docs` builds everything into `target/site/`.

### 5.5 Testing

- Unit tests next to the code; integration tests per crate under `crates/*/tests/` with real
  sockets on port 0; property tests for every codec; `cargo-fuzz` targets for message decoding
  and DNSSEC validation (run in the security pass).
- DNSSEC: RFC test vectors (RFC 4034 key tag and DS, RFC 5155 Appendix A hashes, RFC 5702,
  6605 and 8080 signature examples) committed as unit tests; validator tests against fixture
  zones signed both by our signer and by BIND's `dnssec-signzone` (committed), so the two
  implementations check each other; edge cases include bogus signatures, expired and
  not-yet-valid RRSIGs, missing DS (insecure), DS without matching DNSKEY (bogus), stripped
  RRSIGs, NSEC3 opt-out, unsupported algorithms, KeyTrap-style key floods and wrong clocks.
- Cache: unit tests for every TTL/negative/stale/prefetch/isolation rule; e2e with a clock hook in
  the harness for TTL expiry, negative-cache expiry, serve-stale and prefetch.
- E2E: crate `tests/e2e` (`dnsy-e2e`) starts the real binary with a temp config, zones and an
  `rcgen` CA, then exercises UDP, TCP, DoT, mTLS, DoH, DNSSEC validation and signing, the cache
  and the REST API. Optional interop tests use `dig`/`kdig`/`delv`/`named-checkzone`/
  `dnssec-verify`/`ldns-verify-zone` when installed and skip otherwise.
- Browser e2e: Playwright under `web/e2e`, against the real binary with the embedded UI.
- Tooling: `cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`, `just`.

### 5.6 Release and pipelines (created last, after the analysis follow-ups)

- `dist` (cargo-dist) for release builds, archives, checksums and installers across the target
  list in section 4; the UI is built before `cargo build` so it is embedded.
- Workflows: `ci.yml` (fmt, clippy, deny, nextest, coverage gate, web lint/build/unit tests),
  `e2e.yml` (Rust e2e and Playwright), `pr-title.yml` (regex `^DNSY-[0-9]+(, DNSY-[0-9]+)*: \S`,
  plain bash, no third-party action), `release.yml` (dist, on `v*` tags), `pages.yml` (site build
  and deploy). `dependabot.yml` covers cargo, npm and github-actions, weekly and grouped.

### 5.7 Process and tooling

- Jira stories are created first (table in the plan), then implemented in waves with the
  `dnsy-batch-implement-backlog` skill (adapted from the repsy skills in phase 0 and stored in
  the repo's `.claude/skills/`).
- Order of the final phases: implementation -> analysis passes -> analysis follow-up fixes ->
  pipelines (workflows, release, Pages, Dependabot).
- graphify builds the knowledge graph after bootstrap and is refreshed after every wave;
  agents query it before broad exploration. `graphify-out/` is git-ignored.
- engram is the orchestrator's memory (batch plan, wave log, decisions) under project `dnsy`;
  agents search it at start and save decisions and discoveries.
- After implementation, five analysis passes run on the strongest model (`fable`): coupling and
  cohesion, dependency optimisation, security (incl. DNSSEC work limits and key handling),
  database performance, runtime performance (incl. cache hit ratio, contention and memory, and
  DNSSEC validation/signing cost). Each
  writes a report under `docs/analysis/` and files follow-up stories, which go through another
  batch before the pipelines epic starts.

## 6. Left to the builder

- Module layout inside each crate, private types and helper names.
- Exact SQL column lists beyond the tables named in the plan, and index choices (revisited in the
  DB pass).
- Cache eviction details (any bounded LRU-like policy that meets the tests).
- Animation choreography, exact colours within the token palette, and copy wording in the UI.
- Docs prose and page order within the outline in the plan.
- CLI flag spellings beyond the subcommands listed in the plan.
- Log message wording and tracing span names.
