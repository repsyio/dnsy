# DNSY Hardening Wave Plan

> **For agentic workers:** this plan is executed by `dnsy-batch-implement-backlog` wave by wave (per-story driver `dnsy-implement-story`), exactly like `2026-10-20-dnsy-implementation.md`. The Jira story text is the contract for each story; this document holds the inventory, the scope decisions, the waves and the file ownership. Steps use checkbox syntax where the orchestrator tracks progress.

- **Date:** 2026-10-21, against `main` at `9effe1c` (DNSY-1..63, 69, 70 merged)
- **Jira story:** DNSY-71 (`Plan the hardening wave`)
- **Inputs:** `docs/analysis/2026-10-21-{coupling-cohesion, dependency-optimisation, security-analysis, database-performance, performance-analysis}.md`, the six DNSY-68 comments, the "not fixed / not verified / follow-up" notes of every merged PR (`gh pr list --state merged --limit 80`), `AGENTS.md`, the implementation plan.
- **Verification:** every item kept as must-fix was re-checked on `main` with a targeted read or grep (no `set_nodelay`, no `[profile.release]`, unbounded cursor clause in `dnsy-observe/src/query.rs:109-111`, `hour + 3600` in `retention.rs:15`, `per_client_qps: 0`, `table.clear()` in `doh/throttle.rs:45`, `rcode & 0xF` in `message.rs:235`, `#[serde(flatten)]` in `routes/zones.rs:126`, `x509-parser`/`tower-http`/`criterion`/`time` in `Cargo.toml`, unused `rustls-pki-types` in `dnsy-resolver`, `into_owned()` in `ui.rs:118`, 300 kB budget, `cookie_secure = config.tls`, no AUTOINCREMENT in `0008_client_certs.sql`, `signs_dnskeys` requires `Published | Active`, generation-only mTLS re-check, `MAX_IN_FLIGHT = 1024`, round-robin readers in `store.rs:102`, no pragma tuning, `validate_at` writes per request, no `stats_minute` purge, no argon2 bound, ANY served in full in `lookup.rs:204`, no timer in `http.rs`, no file mode on `dnsy.db`, `fuzz_decode` not wired into any recipe). Two DNSY-68 items are already fixed on `main` (sessions invalidated on credential change; bearer role re-check) and are not re-filed.

## Goal

Close every critical, high and medium finding, every DNSY-68 item still present, the measured big performance and database wins, and the five "before 1.0" coupling refactors, in 18 bounded stories that one agent each can finish in about 150 tool calls, without touching CI (no `.github/workflows/*`, no Dependabot until wave F). Everything else becomes a `post-1.0` story (18 of them) or is dropped with a reason.

## Rules that still hold

All Global Constraints of the implementation plan: hand-written DNS and DNSSEC layer (`deny.toml` ban list), `dnsy-proto` with zero runtime dependencies, clippy pedantic `-D warnings`, `unsafe_code = "forbid"`, `#[expect]` with reasons only, coverage workspace >= 80 % with `dnsy-proto`/`dnsy-dnssec` >= 90 % and web >= 80 %, no coverage exclusions, port 0 in tests, secrets never logged, migration numbers pre-assigned (table below), `just ci` as the local merge gate, every story updates its book page, TDD with flip-and-fail proofs for every bug fix, emoji-first commits, PR titles `DNSY-{n}: {emoji} {Sentence}`, and the hard rule: never any Claude Code attribution anywhere (commits, PRs, Jira, docs).

New dependencies a story may add are named in its Jira text and its PR: `socket2` (DNSY-81). Nothing else is expected; a story that needs another crate says so in its PR.

## Scope decisions

**Must-fix (blocks DNSY-64 to DNSY-67):**

1. Security: all High and Medium findings (SEC-01 to SEC-06); every Low that is a correctness or fail-open issue (SEC-07, 08, 09, 11, 12 cookie part, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 25, 27, 29) and the three Info items that are documentation only (SEC-22, 36, 40); the one-hour fuzz runs the security story originally asked for.
2. DNSY-68: every item still present on `main`.
3. Measured big wins: TCP_NODELAY (41 ms per TCP/DoT answer), query-log drop accounting, sampling and size cap (-30 % capacity, 5.4 GB in 30 minutes), keyset cursor bound and the two query-log indexes (5000x and 170 000x), batched sargable retention, daily rollups (1.8 s -> 50 ms), pragmas and reader pool, release profile (-50 % binary), UDP receive tuning and per-client admission, pooled upstream sockets on the miss path (90k -> 180k misses/s), precompressed UI assets (850 kB -> 220 kB cold login).
4. Coupling: the five "before 1.0" refactors (F1 Services, F2 ApiState/LivePolicy, F3 config enums, F6 one failure throttle, F7 zone mutation in `dnsy-zone`) plus the S-effort F13 (web shared folders) and F14 (`serve.rs` complexity), because they shape the wiring, config and API contracts that 1.0 freezes.
5. Dependencies: everything low-risk (release profile, `x509-parser` removal, unused deps, feature trimming, `deny.toml`, web hygiene, budget), the `libsqlite3-sys` opt-level as a measured experiment.
6. Docs corrections that the above touch.

**Deferred (`post-1.0`, filed, not blocking, not in the sprint):** Info-level security items with no exploitable path, big or risky rewrites (reqwest replacement, codec allocation rewrite, keystore crate split, one Clock, filter narrowing, compact log rows), performance polish on paths already far above the spec targets, product decisions (three.js), and feature gaps noted in PRs (response-IP policy configuration).

**Decisions the orchestrator or user must confirm** (recommendation in bold):

| # | Decision | Recommendation |
| --- | --- | --- |
| D1 | `panic` in `[profile.release]` (DNSY-73) | **Keep `"unwind"`.** The server has no `catch_unwind`; with `abort` any hostile input that reaches a panic takes the whole resolver down instead of one connection task. Panics are bugs and the fuzz corpus (DNSY-75) is the defence; revisit after 1.0 once the corpus has run for longer. |
| D2 | Default ACL private-only and `per_client_qps = 50` (DNSY-74) | **Yes.** It is a behaviour change for anyone relying on the open default; `open_resolver = true` restores it and the quickstart says so. |
| D3 | Query-log `sample` default (DNSY-85) | **1 (unchanged behaviour)**; the size cap default stays 0. Sampling is opt-in for high-QPS deployments. |
| D4 | ANY handling (DNSY-78) | **RFC 8482 HINFO for local zones, REFUSED for forwarded names; AXFR/IXFR REFUSED.** |
| D5 | `[server] udp_sockets_per_address` default (DNSY-81) | **`available_parallelism` on Linux, 1 elsewhere**; measured +7-15 % and no receive drops. |
| D6 | `libsqlite3-sys` `opt-level = 2` (DNSY-73) | **Keep only if measured** (>= 10 s faster clean build, writer throughput within 5 %). |
| D7 | Dependabot comment placement | The orchestrator asked for DNSY-67; the plan and DNSY-64's own acceptance criteria put `.github/dependabot.yml` in DNSY-64, so the comment is on **DNSY-64**. Move it if the split between 64 and 67 changes. |
| D8 | DNSY-68 itself | Every item is mapped to a new story (comment on DNSY-68). **Close DNSY-68 as superseded** once the orchestrator agrees; it still counts as a "follow-up Done" for the pipelines gate. |
| D9 | `Handler::admit` (DNSY-78) | Adds one default method to the pinned `Handler` trait (`fn admit(&self, client: SocketAddr, transport: Transport) -> Admission`). **Accept** as an addition; no existing implementor breaks. |

## Pinned interface changes

Additions to the implementation plan's "Pinned cross-crate interfaces" made by this wave (append-only; nothing pinned is removed or renamed):

```rust
// dnsy-core (DNSY-74, DNSY-83)
pub mod net { pub struct ClientKey; pub fn client_key(ip: IpAddr) -> ClientKey; }   // IPv4 /32 (mapped canonicalised), IPv6 /64
pub enum Validation { Strict, Permissive, Off }          // moved from dnsy-config, serde strings unchanged
pub enum BlockMode { NxDomain, NullIp, Refused, CustomIp { v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr> } }  // defined once

// dnsy-auth (DNSY-77)
pub struct FailureThrottle;   // bounded, sharded, fixed-window; keyed by ClientKey (+ optional secondary key); never clears blocked entries

// dnsy-engine (DNSY-78, DNSY-86, DNSY-88)
pub enum Admission { Answer, Drop }
pub trait Handler { /* existing */ fn admit(&self, client: SocketAddr, transport: Transport) -> Admission { Admission::Answer } }
pub struct Services;  impl Services { pub fn open(cfg: &Config, store: &Store) -> Result<Services, BuildError>; pub async fn reload(&self); }
pub trait LivePolicy: Send + Sync { /* ACL, rate limit, block mode, response-IP policy, groups, DNSSEC mode/anchors, clock flag */ }

// dnsy-resolver (DNSY-83, DNSY-88)
pub struct CacheOptions;  impl Cache { pub fn new(opts: CacheOptions) -> Cache; }
impl GroupSet { pub fn from_specs(specs: Vec<GroupSpec>) -> GroupSet; }

// dnsy-zone (DNSY-84)
impl ZoneStore { pub fn update<T>(&self, origin: &Name, expected_serial: Option<u32>, f: impl FnOnce(&mut Zone) -> Result<T, ZoneError>) -> Result<(Arc<Zone>, T), ZoneError>; }
impl Zone { pub fn add_record(&mut self, r: Record) -> RecordId; pub fn replace_record(&mut self, id: RecordId, r: Record) -> Result<(), ZoneError>; pub fn remove_record(&mut self, id: RecordId) -> Result<(), ZoneError>; }
```

## Migration numbers (pre-assigned, continues the implementation plan's table)

| File | Story | Content |
| --- | --- | --- |
| `0010_querylog_client_index.sql` | DNSY-76 | `CREATE INDEX query_log_client ON query_log (client, ts_ms, id)` |
| `0011_querylog_rare_index.sql` | DNSY-76 | partial index `query_log (ts_ms, id) WHERE source IN ('blocked','refused','error') OR rcode NOT IN (0, 3)` |
| `0012_stats_top_day.sql` | DNSY-87 | `stats_top_day(day, kind, key, count)` WITHOUT ROWID |
| `0013_stats_day.sql` | DNSY-87 | `stats_day(day, dimension, key, count, latency_sum_us, latency_max_us)` WITHOUT ROWID |
| `0014_client_certs_autoincrement.sql` | DNSY-80 | rebuild `client_certs` with `INTEGER PRIMARY KEY AUTOINCREMENT` |

`migrate.rs` registration is append-only; the set-based runner makes merge order irrelevant (0014 may land before 0010). Each owning story also appends its rows to the table in `2026-10-20-dnsy-implementation.md`. Next free number for post-1.0 stories: 0015.

## Jira story table

Labels: `E11-hardening` plus `wave-Hn` (must-fix) or `post-1.0` (deferred). Issue type Story. Every must-fix story has a "Blocks" link to each of DNSY-64, 65, 66, 67, and "Blocks" links for the dependencies below. Score drives the model as in the implementation plan: 1-3 `haiku`, 4-8 `sonnet`, 9-10 `opus`.

| Key | Wave | Summary | Depends on | Score / model | Closes |
| --- | --- | --- | --- | --- | --- |
| DNSY-71 | H0 | Plan the hardening wave | 59-63, 68 | planner | this document |
| DNSY-72 | H1 | Set TCP_NODELAY with single-write framing and add the in-tree benchmark harness | 71 | 6 / sonnet | PERF 1 (Q1), PERF 14 |
| DNSY-73 | H1 | Release profile, dependency trimming and precompressed embedded UI | 71 | 7 / sonnet | DEP 1, 2, 3, 7, 8, 10; SEC-24; PERF 2 (Q2, Q9), PERF 8 (Q6) |
| DNSY-74 | H1 | Safe resolver defaults: private-only ACL, per-client QPS, open-resolver warning | 71 | 5 / sonnet | SEC-05; `client_key` in core |
| DNSY-75 | H1 | dnsy-proto polish and fuzzing: extended rcode fail-closed, canonical DNAME, OPT placement, padding, one-hour fuzz runs | 71 | 7 / sonnet | SEC-21, 22 (doc), 23, 27, 29; SEC F7 (fuzz), F9; DNSY-68 rcode |
| DNSY-76 | H1 | Store and query-log quick wins: cursor bound, client and rare-outcome indexes, batched retention, pragmas, reader pool, file modes | 71 | 6 / sonnet | DB S1, S2, S3, S4, S5, S7, S8, S9; SEC-13; migrations 0010, 0011 |
| DNSY-77 | H2 | Wire the client IP into the API server and unify login and DoH failure throttling | 74 | 8 / sonnet | SEC-01, SEC-03; DNSY-68 items 1, 2, DoH throttle; coupling F6 |
| DNSY-78 | H2 | Pipeline hardening: admission before error replies, minimal ANY, refused AXFR, coalesced cache misses, first-answer TTL clamp | 74 | 9 / opus | SEC-02 (coalescing), SEC-09, SEC-14; DNSY-68 (c) |
| DNSY-79 | H2 | DNSSEC hardening: retired KSK keeps signing DNSKEY, no implicit rollover, fail readiness on unopenable keys, export guard, validator fixes | 71 | 8 / sonnet | SEC-06, 07, 08, 15, 16, 17, 18, 19; SEC F4, F5 |
| DNSY-80 | H2 | API hardening and DNSY-68 leftovers: secure_cookies, input limits, per-principal live tail, route x role matrix, mTLS expiry, client-cert ids, blocklist first fetch, check-svg | 71 | 7 / sonnet | SEC-12 (cookie), 20, 25, 36, 40; SEC F8; DNSY-68 mTLS, (a), (d), check-svg; migration 0014 |
| DNSY-81 | H3 | Listener admission control: shared per-transport connection caps, per-client caps, UDP in-flight and socket tuning, API listener timeouts | 72, 74, 77 | 8 / sonnet | SEC-02 (caps), SEC-04, SEC-11; PERF 4 (Q4) |
| DNSY-82 | H3 | Web: UI fixes from the browser suite, dependency hygiene, bundle budget and shared folders | 76, 80 | 5 / sonnet | DNSY-68 UI (a), (b), (c); DEP 5, 6; coupling F13 |
| DNSY-83 | H3 | Move Validation and BlockMode to dnsy-core; drop dnsy-config from resolver and zone | 74, 78 | 6 / sonnet | coupling F3 |
| DNSY-84 | H3 | ZoneStore::update owns zone mutation, serial bump and If-Match; POST /zones rejects unknown fields | 80 | 6 / sonnet | coupling F7; DNSY-68 (b) |
| DNSY-85 | H3 | Query-log writer: sampling, size cap, disk-full readiness warning, per-batch string building | 76 | 6 / sonnet | PERF 3 (Q3, 5.6); DB S11 |
| DNSY-86 | H4 | Extract Services wiring and remove the service accessors from Engine | 74, 78, 81, 83, 85 | 8 / sonnet | coupling F1, F14 |
| DNSY-87 | H4 | Daily rollups for top-N and summary (migrations 0012 and 0013) with hourly compaction | 76, 85 | 7 / sonnet | DB S6 (F3, F8) |
| DNSY-88 | H5 | Collapse ApiState seams into a LivePolicy trait and grouped sub-states | 80, 83, 84, 86 | 7 / sonnet | coupling F2, F9 |
| DNSY-89 | H5 | Cache miss path: pooled upstream sockets, sized buffers, per-shard sampled eviction | 72, 78, 81 | 9 / opus | PERF 5 (5.1) |

## Waves

Concurrency up to 5. Stories in a wave share no files except the noted append-only points. After every merged wave: `/graphify` incremental update, engram wave log, compact (batch skill).

| Wave | Stories | Why this grouping |
| --- | --- | --- |
| H0 | DNSY-71 | This plan. Merged first so the batch skill has its wave table. |
| H1 | 72, 73, 74, 75, 76 | Small leaf fixes with the largest measured gains and no cross-cutting risk: transports (72), tooling and manifests (73), config defaults and the `client_key` primitive that H2/H3 need (74), the protocol crate (75), store and observe (76). Disjoint crates. Shared append-only files: root `Cargo.toml` (72 appends the bench member; 73 owns the rest), `justfile` (72 `bench`, 73 `check`, 75 `fuzz`), `crates/dnsy/src/serve.rs` (74 and 76 each add one warning function). |
| H2 | 77, 78, 79, 80 | Security features that each need H1's primitives and then own distinct crates: auth/http.rs/doh throttle (77), engine pipeline and listener FORMERR path (78, opus), DNSSEC crates and keystore (79), API lib/state/security plus the DNSY-68 leftovers in mTLS, client certs, blocklists and scripts (80). 77 and 80 both touch `crates/dnsy-api` but different files (77: `routes/auth.rs`, `tests_auth.rs`; 80: `lib.rs`, `security.rs`, `state.rs`, `routes/{tokens,users,querylog,blocklists}.rs`). 79 and 80 both append to `routes/meta.rs` (readyz) and `migrate.rs`. |
| H3 | 81, 82, 83, 84, 85 | Listener caps wait for 77 (both edit `http.rs`) and 72/74; the first cross-cutting refactor (83) runs here because it is mechanical and 86/88 build on it; zone mutation (84) waits for 80's `state.rs` hunk; the writer story (85) waits for 76 in the same files; web (82) is isolated. Shared file: `crates/dnsy-config/src/model.rs` (81 appends `[limits]`/`[server]`/`[api]` keys, 83 moves enum definitions, 85 appends `[querylog]` keys; separate hunks). |
| H4 | 86, 87 | The quiet refactor wave: `Services` (86) rewrites `builder.rs`, `engine.rs` accessors, `serve.rs` and `ApiState` construction, so nothing else may touch those files. 87 lives entirely in `dnsy-observe`, the store migrations and `routes/stats.rs`. |
| H5 | 88, 89 | Last: `ApiState`/`LivePolicy` (88) finishes the wiring on top of 86 and touches most API route files; the cache-miss work (89, opus) touches resolver internals and one call in `engine.rs`, and its numbers are measured on otherwise final code with the `just bench` harness from 72. |
| F | 64, 65, 66, 67 | Pipelines, unchanged: only after every H-story (and DNSY-68) is Done. |

Reasoning for the order: leaf fixes first because they are the highest value per risk and several later stories need their primitives (`client_key`, `just bench`, the counters); the big refactors in their own quiet waves (H4 for `Services`, H5 for `ApiState`) so they never race a feature-level change in `builder.rs`, `engine.rs`, `serve.rs` or `state.rs`; performance and database measurement work last (85 in H3 is writer-local, 87 and 89 after the refactors) so the recorded numbers describe the code that ships.

## Story details

The Jira text is authoritative; this section repeats the contract (goal, acceptance criteria, files owned) so the batch skill can expand TDD steps without opening Jira. All stories implicitly include `just ci` green, docs page updated, flip-and-fail proof for every bug fix, no new `#[expect]` without a reason.

### DNSY-72: TCP_NODELAY, single-write framing, benchmark harness (H1, 6 / sonnet)

Goal: 41 ms per answer on persistent TCP/DoT (Nagle + delayed ACK; two writes per frame, no `TCP_NODELAY`). Fix in `tcp::serve_with`, DoH, DoT and the upstream TCP/DoT client; check in the `fakeup`/`loadgen`/`microbench` tools as `tests/bench` (`dnsy-bench`, excluded from `just cov` like `dnsy-e2e`) with `just bench`.
AC: `persistent_tcp_connection_answers_fast` (200 sequential queries on one connection < 1 s; DoT variant) in `tests/e2e/tests/transports.rs`; one-write-per-frame unit test; pipelined answers coalesced via `try_recv`; PR records `tcp` p16 at 64 clients >= 200k QPS and persistent p50 < 1 ms; `operations.md` and `contributing.md` document `just bench`.
Files: `crates/dnsy-server/src/tcp.rs`, `doh/mod.rs` (nodelay only), `crates/dnsy-resolver/src/upstream/mod.rs` (socket options and framing only), `tests/e2e/tests/transports.rs`, `tests/bench/**`, `justfile` (`bench`), root `Cargo.toml` (member line only), docs.

### DNSY-73: Release profile, dependency trimming, precompressed UI (H1, 7 / sonnet)

AC: `[profile.release]` `lto = "fat"`, `codegen-units = 1`, `strip = true`, `overflow-checks = true`, `panic` per D1; binary < 18 MB with the UI; `libsqlite3-sys` `opt-level = 2` per D6 with numbers in `contributing.md`; `x509-parser` and `time` out (`subject()` becomes a DER walk or webpki, `tests/mtls.rs` unchanged); `cargo machete` clean (`rustls-pki-types`, `tower-http`, `dnsy-core` dev-dep in e2e); `deny.toml` without unused allowances; feature trimming for clap, tokio, proptest, insta (`cargo tree --workspace` at least 14 crates fewer; release tree <= 190); `.br`/`.gz` next to each hashed asset from a node post-build step, served with `Content-Encoding` + `Vary` and without `into_owned()` (`ui_serves_brotli_when_accepted`; cold login < 250 kB); `security.md` third-party crates section; `cargo audit` in `just check` (non-blocking).
Files: `Cargo.toml`, `deny.toml`, `crates/*/Cargo.toml`, `tests/e2e/Cargo.toml`, `crates/dnsy-server/src/dot/mtls.rs` (`subject` only), `crates/dnsy-api/src/ui.rs`, `web/package.json` (`postbuild`), `web/scripts/compress-dist.mjs`, `justfile` (`check`), `install.md`, `contributing.md`, `security.md`.

### DNSY-74: Safe resolver defaults (H1, 5 / sonnet)

AC: `[limits] open_resolver = false` -> base ACL allows loopback, RFC 1918, 100.64/10, ULA, link-local only (DB rules still win by longest prefix); `per_client_qps` default 50; startup and `config check` warning for a non-loopback listener with `open_resolver = true` and qps 0; `dnsy_core::net::client_key` (moved from `dnsy-filter`, re-exported there). Tests: `default_config_refuses_public_client`, `default_config_allows_private_and_loopback`, `open_resolver_allows_public_client`, `startup_warns_for_open_unlimited_listener`, `client_key_groups_ipv6_by_64`. Docs: `configuration.md`, `security.md`, `quickstart.md`, `examples/dnsy.toml`.
Files: `crates/dnsy-config/src/{model,validate}.rs`, `crates/dnsy-engine/src/builder.rs`, `crates/dnsy/src/serve.rs` (append), `crates/dnsy/src/cli.rs`, `crates/dnsy-core/src/lib.rs` (append `net`), `crates/dnsy-filter/src/ratelimit.rs`, examples, docs.

### DNSY-75: dnsy-proto polish and fuzzing (H1, 7 / sonnet)

AC: `EncodeError::BadRcode` for rcode > 15 without OPT (`extended_rcode_without_opt_is_an_error`); canonical lowercase for DNAME RDATA and NAPTR replacement without new `RData` variants (`canonical_lowercases_dname_rdata`); `DecodeError::BadOpt` for OPT outside additional or duplicated (`opt_outside_additional_rejected`); padding never evicts RRsets (`padding_never_evicts_answers`); SEC-22 documented; the 42 hand-crafted hostile inputs as a table test; `fuzz_validate` target, `just fuzz` (nightly, not in `ci`), one hour per target with 0 panics, minimised corpora committed; proto and dnssec coverage >= 90 %.
Files: `crates/dnsy-proto/src/{message.rs, message_tests.rs, canonical.rs}`, `crates/dnsy-proto/fuzz/**`, `crates/dnsy-dnssec/fuzz/**`, `justfile` (`fuzz`), `wire-protocol.md`, `contributing.md`.

### DNSY-76: Store and query-log quick wins (H1, 6 / sonnet)

AC: cursor also bounds `ts_ms` (`cursor_page_plan_uses_index_bound` via `EXPLAIN QUERY PLAN`); migrations 0010/0011 registered, partial-index predicate emitted verbatim for rare sources/rcodes, plan tests, startup log line while building; sargable `stats_top_hour` purge and 50k-row batches (test with 120k rows shows >= 3 commits with the writer interleaving); `stats_minute` purge at `max(retention, 400 d)` and expired-session purge; session touch only when `last_seen_at` older than 60 s (write-count test); failed flushes counted (`dropped`, `flush_errors`) and exposed in `GET /stats/summary`; `synchronous = NORMAL`, `journal_size_limit = 64 MiB`, `PRAGMA optimize` on shutdown and daily (pragma read-back test, WAL shrink test); free-list reader pool (one 500 ms read, eight fast reads < 50 ms); `data_dir` 0700, `dnsy.db` 0600, TLS key mode warning (`fresh_store_files_are_private`). Docs: `query-log.md`, `backup-restore.md`, `operations.md`; migration table rows 0010, 0011 appended to the implementation plan.
Files: `crates/dnsy-observe/src/{query,retention,writer,stats}.rs`, `crates/dnsy-store/src/{store,migrate}.rs`, `migrations/0010_*.sql`, `0011_*.sql`, `crates/dnsy-auth/src/sessions.rs` (validate path), `crates/dnsy-api/src/routes/stats.rs` (append), `openapi/dnsy.json`, `crates/dnsy/src/lib.rs`, `crates/dnsy/src/serve.rs` (append), docs.

### DNSY-77: Client IP wiring and unified failure throttling (H2, 8 / sonnet)

AC: `ConnectInfo(peer)` inserted in `http.rs` before `oneshot`; `client_ip` fails closed; `FailureThrottle` in `dnsy-auth` (bounded, sharded, fixed-window, keyed by `ClientKey` + optional secondary key, never clears blocked entries) replaces `doh/throttle.rs`; login attempt reserved atomically in one write transaction; per-`(username, client_key)` 5 per 15 min plus a per-username exponential backoff capped at 60 s (never a full lockout); argon2 bounded by a semaphore sized to `available_parallelism` (503 + `Retry-After` when exhausted); passwords > 1 KiB rejected before hashing. Tests: `login_attempts_record_peer_ip_through_real_listener`, `concurrent_attempts_cannot_exceed_limit`, `throttle_counts_ipv6_rotation_within_slash64`, `legitimate_user_logs_in_from_other_address_after_remote_lockout`, `argon2_concurrency_is_bounded`, `doh_throttle_saturation_keeps_blocked_ip_blocked`, `password_over_1_kib_rejected_before_hashing`; e2e `rest_auth.rs` two-address case; `auth.md`, `doh.md`.
Files: `crates/dnsy/src/http.rs`, `crates/dnsy-api/src/routes/auth.rs`, `tests_auth.rs`, `crates/dnsy-auth/src/{sessions,password,users,throttle,lib}.rs`, `crates/dnsy-server/src/doh/{throttle.rs (deleted), mod.rs}`, `tests/e2e/tests/rest_auth.rs`, docs.

### DNSY-78: Pipeline hardening (H2, 9 / opus)

AC: ACL and rate limit before FORMERR/NOTIMP/BADVERS; `Handler::admit` consulted by the listener-level FORMERR in `query.rs`; ANY on local zones -> RFC 8482 HINFO (TTL 3789), ANY elsewhere -> REFUSED, AXFR/IXFR -> REFUSED without upstream; concurrent identical misses share one exchange through `Refreshes::begin`; the first miss answer carries the TTL clamps. Tests: `acl_drop_suppresses_formerr_and_notimp`, `error_replies_consume_rate_limit`, `listener_formerr_respects_drop_acl`, `any_on_local_zone_answers_minimal_hinfo`, `any_for_forwarded_name_refused_without_upstream`, `axfr_refused_without_upstream_call`, `concurrent_identical_misses_share_one_upstream_exchange`, `first_miss_answer_is_ttl_clamped`; e2e `cache_ttl.rs` tightened, `protocol.rs` ANY/AXFR probes; `security.md`, `resolver.md`, `wire-protocol.md`.
Files: `crates/dnsy-engine/src/{engine,handler,response,tests}.rs`, `tests/**`, `crates/dnsy-server/src/query.rs` (udp.rs/tcp.rs only for a one-line call), `crates/dnsy-resolver/src/cache/stale.rs` (`Refreshes` reuse), `crates/dnsy-zone/src/lookup.rs` (ANY branch), e2e files, docs.

### DNSY-79: DNSSEC hardening (H2, 8 / sonnet)

AC: Retired SEP keys sign DNSKEY until Removed (`retired_ksk_still_signs_dnskey_rrset`, validator test with old-DS anchor); `generate_key` guarded by `RolloverInProgress` (`generate_key_twice_is_conflict`); unopenable keys -> zone SERVFAIL + `/readyz` not ready (`unopenable_keys_fail_readiness_instead_of_serving_unsigned`); bundle passphrase >= 12, KDF 64 MiB / t=3, export 403 on plaintext listener (`short_bundle_passphrase_rejected`, `key_export_refused_on_plaintext_listener`); validator fetches scrubbed before caching; fetch errors -> Indeterminate EDE 5 with `servfail_ttl` (`fetch_error_is_indeterminate_not_bogus`); opt-out NSEC3 wildcard proof -> Insecure (`wildcard_expansion_proof_nsec3_opt_out_is_insecure`); REVOKE bit honoured (`revoked_zsk_signature_is_bogus`); dnssec coverage >= 90 %; `dnssec-operator-guide.md`, `dnssec.md`.
Files: `crates/dnsy-dnssec/src/{keys.rs, sign/mod.rs, validate/chain.rs, validate/denial.rs, verify.rs}` + tests, `crates/dnsy-zone/src/{keystore,signed,store}.rs`, `crates/dnsy-resolver/src/forward.rs` (scrub call), `crates/dnsy-api/src/routes/{dnssec.rs, dnssec_tests.rs, meta.rs (append)}`, `crates/dnsy/src/admin.rs`, `tests/e2e/tests/{dnssec_lifecycle,dnssec_validation}.rs`, docs.

### DNSY-80: API hardening and DNSY-68 leftovers (H2, 7 / sonnet)

AC: `[api] secure_cookies = auto|true|false` drives `Secure` and HSTS (test with `tls: false, secure_cookies: true`); token name <= 128, username <= 64, <= 100 tokens per user; live-tail cap per principal with admin reservation; route x role matrix test over every OpenAPI operation with a committed expectation table; `auth.md` on flat scopes and anonymous `/version`; mTLS time-based re-verification with injectable clock (`expired_client_cert_closes_open_connection`) and a session-storage regression test; migration 0014 (`deleted_client_cert_id_is_not_reused`); blocklist fetch on create (`new_blocklist_is_populated_without_waiting_for_the_schedule`); `check-svg.sh` XML-parsing rejection list with negative fixtures.
Files: `crates/dnsy-config/src/model.rs` (append), `crates/dnsy-api/src/{lib,security,state (live tail), tests_matrix (new)}.rs`, `routes/{tokens,users,querylog,blocklists}.rs`, `crates/dnsy-server/src/dot/mtls.rs` (verification), `tests/mtls.rs`, `crates/dnsy-auth/src/client_certs.rs`, `migrations/0014_*.sql`, `migrate.rs` (append), `scripts/check-svg.sh`, `scripts/check-svg-fixtures/**`, docs (`security.md`, `auth.md`, `dot.md`, `filtering.md`), implementation plan migration table (append).

### DNSY-81: Listener admission control (H3, 8 / sonnet)

AC: one shared semaphore per transport in `Server::start`; `[limits] max_conns_per_client` (16, by `client_key`); `[limits] udp_in_flight` (4096) and `udp_in_flight_per_client` (64); `SO_RCVBUF` 4 MiB via `socket2`; `[server] udp_sockets_per_address` with `SO_REUSEPORT` on Linux (D5); API listener timer + `header_read_timeout` 30 s, h2 limits, `[api] max_conns` (256), `TimeoutLayer` 30 s except the SSE route. Tests: `tcp_cap_is_shared_across_listen_addresses`, `per_client_tcp_cap_leaves_room_for_other_clients`, `udp_per_client_in_flight_cap_keeps_other_clients_served`, `api_half_request_is_closed_within_timeout`, `api_idle_connections_do_not_block_healthz`, `udp_sockets_per_address_binds_n_sockets` (Linux); PR records zero `UdpRcvbufErrors` at 256 clients >= 450k QPS; `configuration.md`, `operations.md`, `security.md`.
Files: `crates/dnsy-server/src/{udp,tcp,lib}.rs`, `doh/mod.rs`, `dot/mod.rs`, `crates/dnsy/src/{http,serve}.rs`, `crates/dnsy-config/src/model.rs` (append), root `Cargo.toml` (append `socket2`), `examples/dnsy.toml`, docs.

### DNSY-82: Web fixes, hygiene, budget, shared folders (H3, 5 / sonnet)

AC: blocklist form sends `allow_private` (Playwright creates a file source through the form); "Invalid username or password" for 401, distinct texts for 429 and 503; `Validators.minLength(8)` on setup and new-password fields; dashboard badge for `querylog_dropped > 0`; `typescript-eslint` bump, `pnpm dedupe --check` in `just web`, `eslint-config-prettier` removed, `@angular/compiler` to devDependencies, `peerDependencyRules`, vite advisory gone; budgets 320 kB initial + `anyComponentStyle`, no build warning; `Dialog`/`ConfirmDialog`/`copy.ts`/`util.ts`/`password-strength.ts` under `shared/`, `testing.ts` under `src/testing/`, ESLint `no-restricted-imports` for cross-feature imports; web coverage >= 80 %.
Files: `web/**` (except the `postbuild` script and `web/scripts/compress-dist.mjs` from DNSY-73), `justfile` (`web`), `web-ui.md`.

### DNSY-83: Config enums to dnsy-core (H3, 6 / sonnet)

AC: `Validation`, `BlockMode` in `dnsy-core` (serde strings pinned by test), re-exported by config, defined once; `CacheOptions` owned by the resolver; `TrustAnchor::parse` in `dnsy_dnssec::anchors`, config shape-checks only, `from_config` and `config check` parse fully (`config_check_reports_bad_trust_anchor`); passphrase env name as a parameter; config fan-in 3; no `dnsy_config::` outside `builder.rs` in resolver, zone, engine; `openapi/dnsy.json` semantically unchanged; `architecture.md`.
Files: `crates/dnsy-core/src/lib.rs` (append), `crates/dnsy-config/src/{model (enum definitions), validate, lib}.rs`, `crates/dnsy-resolver/src/{forward.rs, cache/mod.rs}`, `crates/dnsy-dnssec/src` (anchors, append), `crates/dnsy-zone/src/keystore.rs` (env parameter), `crates/dnsy-engine/src/{builder,engine}.rs` (type renames), `crates/dnsy-api/src/{validation.rs, routes/settings.rs}`, `crates/dnsy/src/cli.rs`, docs.

### DNSY-84: ZoneStore::update and unknown-field rejection (H3, 6 / sonnet)

AC: `ZoneStore::update` owns lock, serial bump, atomic write and `SerialMismatch`; `Zone::{add,replace,remove}_record` and stable `Record::id()` (snapshot-pinned); API `mutate/bumped/records_mut/position` and `ApiState.zone_lock` removed; DNSSEC policy patch uses `update`; `POST`/`PUT /zones` reject unknown top-level fields with 422 (`create_zone_rejects_unknown_fields`); `update_bumps_serial_and_is_atomic`, `update_with_stale_serial_is_conflict`, `concurrent_updates_serialise`; route tests and `rest_zones.rs` pass; `zones.md`.
Files: `crates/dnsy-zone/src/{store,model}.rs` + tests, `crates/dnsy-api/src/routes/zones.rs`, `routes/dnssec.rs` (policy patch call), `state.rs` (`zone_lock` removal), `tests/e2e/tests/rest_zones.rs`, `openapi/dnsy.json`, docs.

### DNSY-85: Query-log writer: sampling, size cap, disk-full warning (H3, 6 / sonnet)

AC: `[querylog] sample` (raw rows only; rollups exact, `sampling_keeps_rollups_exact`; default per D3); `[querylog] max_size_mb` enforced after each retention pass by purging the oldest day; `querylog_disk_full` readiness warning on `SQLITE_FULL`, cleared on recovery; per-batch string building and capacity check before cloning (sink cost within 10 % of no-sink in the micro-benchmark); PR records sample 1/100 at 64 clients within 10 % of log-off and < 100 MB/h growth; `query-log.md`, `configuration.md`, `logging-and-metrics.md`.
Files: `crates/dnsy-observe/src/{writer,retention,event}.rs`, `crates/dnsy-config/src/model.rs` (append), `crates/dnsy-api/src/routes/meta.rs` (append), `crates/dnsy-engine/src/builder.rs` (one hunk), docs. Does not touch `engine.rs`.

### DNSY-86: Services wiring (H4, 8 / sonnet)

AC: `Services::open(&Config, &Store)` builds every store-backed service once; `EngineBuilder` takes handles from it, `from_config` remains as a shim; `Engine::{cache, zone_store, zone_signing, groups, list_manager}` removed; `ApiState` built from the same `Services`; `Services::reload()` and `spawn_background()`; `serve` and `reload` under cognitive complexity 25 without `#[expect]`; API tests build engines with `NoUp` through `Services` test constructors; all tests and `lifecycle.rs` e2e pass; `architecture.md`.
Files: `crates/dnsy-engine/src/{builder,engine,lib,services (new, if here)}.rs`, `crates/dnsy/src/{serve,lib,services (if here)}.rs`, `crates/dnsy-api/src/state.rs` (construction sites), `tests*.rs` (builders), docs.

### DNSY-87: Daily rollups (H4, 7 / sonnet)

AC: migrations 0012/0013 as drafted; hourly fold of days older than 48 h into `stats_top_day` (top 5000 per day and kind) and `stats_day`, one transaction per day, idempotent; `top`, `summary`, `timeseries` read daily rows for whole days; midnight-boundary correctness test against the raw log; benchmark test: 30-day top domains at 10 M rows < 50 ms, 30-day summary < 10 ms; hourly/minute retention 48 h after the fold; `query-log.md`, `backup-restore.md`; migration table rows 0012, 0013 appended.
Files: `crates/dnsy-observe/src/{stats,retention,query,testutil}.rs`, `migrations/0012_*.sql`, `0013_*.sql`, `migrate.rs` (append), `crates/dnsy-api/src/routes/stats.rs` (if needed), docs, implementation plan table (append).

### DNSY-88: ApiState and LivePolicy (H5, 7 / sonnet)

AC: `LivePolicy` trait in `dnsy-engine` implemented once in `policy.rs`; `engine`, `validation`, `dnssec_clock_untrusted` collapse into `Option<Arc<dyn LivePolicy>>`; `validation.rs` deleted or DTO-only; `routes/live.rs` uses `GroupSet::from_specs`; fields grouped into `AuthServices`, `PolicyStores`, `Zones`, `Observe`; at most 3 `Option`s; one builder; `RuntimeSettings` out of `routes`; `Engine<E>` not named in `dnsy-api`; all API tests and REST e2e pass; `openapi/dnsy.json` unchanged; `architecture.md`.
Files: `crates/dnsy-api/src/{state,validation,lib}.rs`, `routes/{acl,settings,live,upstreams,blocklists,dnssec,cache,zones,querylog}.rs` (call sites), `tests*.rs`, `crates/dnsy-engine/src/{policy (new), lib (append)}.rs`, `crates/dnsy-resolver/src/groups/mod.rs` (`from_specs`, append), `crates/dnsy/src/serve.rs` (construction), docs. Does not touch `engine.rs`.

### DNSY-89: Cache miss path (H5, 9 / opus)

AC: pooled connected upstream sockets (random port, rotation by count or 60 s; per-query CSPRNG id and full question match unchanged; `pooled_sockets_use_random_ports_and_rotate` plus existing spoof-resistance tests); reusable receive buffers sized to the EDNS size (no 64 KiB allocation per query); cached `SocketAddr` for IP-literal upstreams; `insert` by value; per-shard random-sample eviction, never all shards (`bounded_eviction_counts` and isolation tests unchanged, new older-entry preference test); PR records `miss_unique` at 64 clients >= 180k QPS, p99 < 1 ms, CPU per miss < 15 us, hits unchanged; `resolver.md` documents the pool invariants.
Files: `crates/dnsy-resolver/src/{upstream/mod.rs, upstream/tests.rs, cache/mod.rs, cache/tests.rs}`, `crates/dnsy-engine/src/engine.rs` (the `cache.insert` call only), `tests/bench` (scenario if needed), docs.

## Deferred stories (`post-1.0`; filed, not blocking, not in the sprint)

| Key | Summary | Source | Why not now |
| --- | --- | --- | --- |
| DNSY-90 | Replace reqwest with a hyper-based fetcher in dnsy-filter and cacheflush | DEP F3 / 4 | hand-written HTTP in the SSRF-sensitive fetch path for a size/build-time gain |
| DNSY-91 | Decide the fate of the three.js login scene | DEP F5 / 9 | product decision; lazy and cached |
| DNSY-92 | Rate limiter slip replies, amortised eviction, oldest-idle TCP recycling | SEC-10, SEC-04 rest | DNSY-81 removes the exploitable part |
| DNSY-93 | Anti-spoofing extras: 0x20, dot.client_crl, SPKI pins, loop guard | SEC-31, 32, 35 / F12 | informational; baseline sound |
| DNSY-94 | Info-level security polish incl. trusted-proxy client IP | SEC-12 proxy, 28, 30, 33, 34, 37, 38, 39, 41, 42 | no exploitable path; header-trust design needed |
| DNSY-95 | Compact query-log row encoding | DB F13 / S12 | rebuild migration with downtime for 20-27 % size |
| DNSY-96 | dnsy db check, vacuum, backup; read-only migrate --status | DB F12 / S10 | operational convenience; book already correct |
| DNSY-97 | Split keystore.rs into a dnsy-keys crate | coupling F4 / 6 | effort L, internal only |
| DNSY-98 | One Clock in dnsy-core | coupling F5 / 7 | mechanical, wide, no behaviour change |
| DNSY-99 | Narrow dnsy-filter; mTLS CertSource seam; dedupe hex and DS export | coupling F8, F10, F11 / 8, 9, 12 | internal cohesion |
| DNSY-100 | Move dnsy-api tests to tests/ and split the two largest route files | coupling F12 / 11, DEP F15 | placement and compile time |
| DNSY-101 | Cache lookup scaling; Handler takes the query by reference | PERF 6, 7 (5.2, Q5) | hits already 9x over target; pinned interface change |
| DNSY-102 | Codec allocation reduction | PERF 10 (5.4) | rewrite of the protocol layer for 2x on a fast path |
| DNSY-103 | DoH verified-token cache | PERF 9 (Q8) | introduces a revocation delay; needs a decision |
| DNSY-104 | Parallel zone signing and incremental NSEC3 re-sign | PERF 11 (5.10) | target met on one core |
| DNSY-105 | Web runtime polish: scene idle pause, dashboard batching | PERF 12 (Q7, 3.11) | comfort |
| DNSY-106 | Server performance polish: changed-zone reload, rotation counter, inline datagrams, lowercase once, blocklist memory, worker_threads | PERF 13, 5.3, 5.5, 5.7, 5.8, 5.9, 5.11 | small gains above target |
| DNSY-107 | Response-IP policy configuration and API | DNSY-31 PR note | feature, not a defect |

## Dropped (intentionally not filed)

| Item | Source | Why |
| --- | --- | --- |
| `doh.path` not configurable (fixed `/dns-query`) | DNSY-41 PR | The spec defines the path as `/dns-query`; configurability was never a requirement. Reopen if a user asks. |
| CNAME chains leaving local zones are not chased upstream | DNSY-31 PR | Standard authoritative behaviour: the client (RD) re-queries the target; chasing would mix authoritative and recursive answers. |
| Query-log "block/allow domain" quick actions in the UI | DNSY-48 PR | Product feature without an endpoint; not a defect. |
| BIND-signed fixtures / `delv` interop when tools are missing | DNSY-24, 54 PRs | The interop tests exist and skip without the tools; nothing to fix in the product. |
| Firefox/WebKit in the browser suite | DNSY-56 PR, DNSY-68 (d) | Local host limitation; noted on DNSY-64 for the CI image. |
| Dependabot grouping, `cargo machete`/`audit` gates, `schema.d.ts` drift check, sccache, Node pin | DEP section 6, F1, F9, coupling F13 | Pipeline configuration; attached as a comment to DNSY-64 (D7). |
| `cargo-geiger`, `cargo-udeps`, `bloaty` unavailable on the pinned toolchain | DEP, SEC method notes | Tooling gaps, not findings; the reports used substitutes. |
| Unmeasured items of the performance pass (validation cold/warm, idle connections, startup/reload, dnsmasq reference, browser runtime) | PERF 3.5-3.11 | Become measurable with `just bench` (DNSY-72); the related code paths are covered by DNSY-81, DNSY-89 and DNSY-106 where a finding exists. |
| `rust-embed` single-owner risk | DEP F12 | Documented in `security.md` by DNSY-73; replacing it with a `build.rs` table is not worth a story. |
| `ring` release gap | DEP F12 | Documented by DNSY-73; the exit (`aws-lc-rs`) is a dependency decision for a later release. |

## Finding inventory and disposition

Security (SEC-nn): 01 -> 77; 02 -> 78 + 81; 03 -> 77; 04 -> 81 (+92); 05 -> 74; 06 -> 79; 07 -> 79; 08 -> 79; 09 -> 78; 10 -> 92; 11 -> 81; 12 -> 80 (+94); 13 -> 76; 14 -> 78; 15 -> 79; 16 -> 79; 17 -> 79; 18 -> 79; 19 -> 79; 20 -> 80; 21 -> 75; 22 -> 75 (doc); 23 -> 75; 24 -> 73; 25 -> 80; 26 -> covered by 07; 27 -> 75; 28 -> 94; 29 -> 75; 30 -> 94; 31 -> 93; 32 -> 93; 33 -> 94; 34 -> 94; 35 -> 93; 36 -> 80 (doc); 37 -> 94; 38 -> 94; 39 -> 94; 40 -> 80 (doc); 41 -> 94; 42 -> 94. SEC stories F1 -> 77; F2 -> 78 + 81; F3 -> 74 + 78; F4, F5 -> 79; F6 -> 76 + 79 + 80 + 81; F7 -> 73 + 75; F8 -> 80; F9 -> 75; F10 -> 75 + 78 + 80 + 84; F11 -> 92; F12 -> 93.

Coupling (F): F1 -> 86; F2 -> 88; F3 -> 83; F4 -> 97; F5 -> 98; F6 -> 77 (+74); F7 -> 84; F8 -> 99; F9 -> 88; F10 -> 99; F11 -> 99; F12 -> 100; F13 -> 82; F14 -> 86.

Dependencies (F / story): F1 (story 3) -> 73 measured; F2 (2) -> 73; F3 (4) -> 90; F4 (1) -> 73; F5 (9) -> 91; F6 (6) -> 82; F7 (5) -> 82; F8 (5) -> 82; F9 (7) -> 73 + 82; F10 -> falls out of 73; F11 (8) -> 73; F12 (10) -> 73 docs; F13 -> 73; F14 -> nothing to fix; F15 -> 100; F16 -> 73 (precompression); F17 -> nothing; section 6 -> DNSY-64 comment.

Database (F / S): F1 (S1) -> 76; F2 (S2) -> 76; F3 (S6) -> 87; F4 (S3) -> 76; F5 (S4) -> 76; F6 (S11) -> 85; F7 (S5) -> 76; F8 (S6) -> 87; F9 (S7) -> 76 (+82 badge); F10 (S8) -> 76; F11 (S9) -> 76; F12 (S4 sessions, S10) -> 76 + 96; F13 (S12) -> 95.

Performance (story / finding): 1 (Q1) -> 72; 2 (Q2, Q9) -> 73; 3 (Q3, 5.6) -> 85; 4 (Q4) -> 81; 5 (5.1) -> 89; 6 (5.2) -> 101; 7 (Q5) -> 101; 8 (Q6) -> 73; 9 (Q8) -> 103; 10 (5.4) -> 102; 11 (5.10) -> 104; 12 (Q7, 3.11) -> 105; 13 (5.3, 5.5, 5.7, 5.8, 5.9, 5.11) -> 106; 14 -> 72.

DNSY-68: items 1, 2, DoH throttle -> 77; rcode -> 75; mTLS expiry, (a) client-cert ids, (d) blocklist fetch, check-svg -> 80; (b) unknown fields -> 84; (c) TTL clamp -> 78; UI (a), (b), (c) -> 82; UI (d) -> DNSY-64 comment; items 3 and bearer role re-check -> already fixed.

PR notes: DNSY-31 response-IP config -> 107; DNSY-31 CNAME chase, DNSY-41 `doh.path`, DNSY-48 quick actions, DNSY-24/54 fixtures, DNSY-56 browsers -> dropped table; DNSY-52 NTA expiry -> fixed by DNSY-70; DNSY-53 notes -> DNSY-68 items above.

## Process notes for the batch skill

- Dispatch by the wave table; concurrency 5; `just ci` on every PR head before squash-merge; the orchestrator transitions Jira (To Do 11, In Progress 21, Done 31).
- Stories that record benchmark numbers (72, 81, 85, 89) run `just bench` on the PR head and paste the table into the PR body; the orchestrator re-runs it before merging when the numbers gate the acceptance criteria.
- Migration-owning stories (76, 80, 87) append their rows to both migration tables; reviewers check the number against this plan.
- A story that discovers an out-of-scope defect files a new `E11-hardening` story (next free key) instead of widening its own PR, and links it to the pipelines if it is must-fix.
- After H5 and DNSY-68 are Done, wave F (DNSY-64 to 67) starts; nothing under `.github/` exists before that.
