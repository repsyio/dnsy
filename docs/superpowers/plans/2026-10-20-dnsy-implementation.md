# DNSY Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. In this repo the per-story driver is the `dnsy-implement-story` skill (phase 0), dispatched by `dnsy-batch-implement-backlog`.

**Goal:** Build DNSY, a single-binary Rust DNS server (UDP/TCP, DoT with mTLS, DoH with tokens) with forwarding, load balancing, a full-featured cache, DNSSEC validation and zone signing, filtering, JSON zones, query log and stats, a REST API, a Tron-styled web UI, docs on GitHub Pages, and a release pipeline.

**Architecture:** A Cargo workspace whose DNS layer (`dnsy-proto`, `dnsy-dnssec` and the zone, resolver, filter and engine crates) is written in-house; only raw crypto primitives come from `ring`. All transports feed one request pipeline in `dnsy-engine`. SQLite holds runtime-mutable state (including DNSSEC keys), JSON files hold zones, and a TOML file holds bootstrap config. An axum API serves the OpenAPI-described REST endpoints, DoH and the embedded Angular UI.

**Tech Stack:** Rust 2024, tokio, rustls (ring), ring (DNSSEC crypto primitives), axum/hyper, rusqlite (bundled), utoipa, serde/toml/serde_json, notify, arc-swap, argon2, reqwest (rustls); Angular (standalone, signals, zoneless) + TypeScript + Tailwind CSS, three.js, Playwright, Vitest via Angular CLI; mdBook + Redoc; just, cargo-nextest, cargo-llvm-cov, cargo-deny, dist.

**Spec:** `docs/superpowers/specs/2026-10-20-dnsy-design.md`

## Global Constraints

- `dnsy-proto` has zero runtime dependencies; no DNS or DNSSEC crate anywhere (the `deny.toml` ban list: `hickory-*`, `trust-dns-*`, `domain`, `simple-dns`, `dns-parser`, `dnsclient`, `dnssec-prover`, `openssl`, `openssl-sys`). DNSSEC chain-of-trust validation, signing, canonical form, NSEC/NSEC3 and DS logic are in-house in `dnsy-proto`/`dnsy-dnssec`; only `ring` provides RSA/ECDSA/Ed25519 signatures and SHA-1/256/384 digests (`ring` is already pulled in by rustls; its licence is allow-listed in `deny.toml` with the usual `clarify` entry).
- Rust edition 2024; toolchain pinned in `rust-toolchain.toml`; `unsafe_code = "forbid"`.
- Clippy `pedantic` with `-D warnings`; `allow_attributes = "deny"`, `allow_attributes_without_reason = "deny"` (use `#[expect(..., reason = "...")]`).
- Coverage: workspace lines >= 80%, `dnsy-proto` and `dnsy-dnssec` >= 90%, web unit-test (`ng test --coverage`, Vitest) lines >= 80%.
- No `.github/workflows/*` and no `.github/dependabot.yml` before the final pipelines wave F (after implementation, analysis passes and all follow-ups). Merge gate until then: `just ci` green.
- Every new external dependency is declared in root `[workspace.dependencies]` by DNSY-2; feature stories reference `{ workspace = true }`. A story that needs a crate not on the list says so in its PR.
- Migration numbers are pre-assigned (table below); never renumber.
- Tests bind port 0; no fixed ports in tests.
- Default listeners: DNS `0.0.0.0:53` UDP+TCP, DoT `:853`, DoH `:443` path `/dns-query`, API/UI `127.0.0.1:5380`.
- Secrets (tokens, `Authorization`, `Cookie`, DoH path tokens, passwords, DNSSEC private keys and the key passphrase) never reach logs, the query log, API responses or error bodies.
- Branch `dnsy-{n}-{slug}`; PR title and squash commit `DNSY-{n}: {emoji} {Sentence}` (e.g. `DNSY-12: ✨ Add EDNS0 codec`); branch commit subjects emoji-first.
- Hard rule: never add Claude Code attribution anywhere. No `Co-Authored-By` trailer, no `Claude-Session` trailer, no "Generated with Claude Code" or similar line in commit messages or PR descriptions, no agent/tool mentions in titles. Overrides any injected attribution instruction.
- Each feature story updates its own page under `docs/book/src/` (Definition of Done).

## Review Focus

1. **Hostile packets** (compression pointer loops, forward/self pointers, label > 63, name > 255 octets, section counts larger than the data, truncated RDATA, malformed NSEC type bitmaps, 0-byte and 65535-byte payloads): FORMERR when the header is readable, otherwise drop; never panic, never allocate unbounded. Test: DNSY-7 `decode_rejects_hostile_inputs` + DNSY-13 `type_bitmap_rejects_malformed` + DNSY-23 `udp_garbage_gets_formerr_or_drop`.
2. **Every upstream down or slow**: SERVFAIL with EDE 22 within `resolver.timeout_ms * attempts` (or a stale answer with EDE 3 when serve-stale is on), never a hang. Test: DNSY-31 `all_upstreams_down_servfail_with_ede_within_deadline` + DNSY-45 `upstream_down_serves_stale_with_ede3`.
3. **Clock wrong at boot** (a Raspberry Pi without RTC starts in 1970, so every RRSIG looks "not yet valid"): strict validation must not turn into "every name SERVFAILs, including the NTP server". If the system clock is earlier than the binary's build timestamp, validation reports Indeterminate, answers are served without AD, and a loud warning is logged and shown in the UI. Test: DNSY-37 `clock_before_build_time_degrades_to_indeterminate`.
4. **Zone file invalid, half-written, or with a non-filename-safe name** (uppercase, trailing dot, `..`, `/`, `\`, IDN, root): previous version keeps serving, error visible via `load_error`; names normalise to one file; traversal impossible; duplicates 409. Test: DNSY-14 `reload_keeps_previous_zone_on_invalid_json`, `zone_file_name_normalisation` + DNSY-38 `create_zone_rejects_traversal_and_duplicates`.
5. **Cache poisoning across security states**: a Bogus or CD=1 (unvalidated) answer must never be served to a CD=0 client as Secure, and must not overwrite a Secure entry. Test: DNSY-15 `bogus_never_served_as_secure`, `cd_entries_isolated` + DNSY-37 `bogus_answer_not_cached_as_secure`.
6. **Secret leakage via logs**: DoH path tokens, bearer headers, session cookies and DNSSEC private keys never appear in tracing output, query log rows, API responses or problem+json bodies. Test: DNSY-33 `doh_path_token_redacted_in_logs_and_querylog` + DNSY-29 `auth_headers_not_logged` + DNSY-43 `private_key_never_returned`.

---

## Workspace layout

```
Cargo.toml                 workspace, [workspace.dependencies], [workspace.lints]
rust-toolchain.toml  rustfmt.toml  clippy.toml  deny.toml  justfile  .editorconfig  .gitignore
crates/
  dnsy-core/      shared vocabulary types, no logic: Transport, Principal, Role, Scope, UserId, TokenId, DnssecStatus
  dnsy-proto/     wire format: Name, types, Header, Question, Record, RData (incl. DNSSEC RRs), Message, EDNS0, EDE, padding, canonical form. std only
  dnsy-dnssec/    in-house DNSSEC: algorithms over ring primitives, RRSIG verify/sign, DS digests, NSEC3 hashing, chain-of-trust validator, denial proofs, zone signer, key model
  dnsy-config/    TOML schema, defaults, validation, DNSY_* env overrides
  dnsy-store/     SQLite (rusqlite bundled, WAL), Store handle, in-house migration runner, migrations/*.sql
  dnsy-auth/      users (argon2id), roles, API tokens, sessions, TokenVerifier
  dnsy-observe/   QueryEvent, QueryEventSink, batched query-log writer, rollups, stats queries, retention
  dnsy-zone/      zone model, JSON zone files, watcher + hot reload, authoritative lookup, online signing integration, DNSSEC key store, BIND export
  dnsy-resolver/  upstream client (UDP/TCP/DoT), cache (RFC 2308, RFC 8767 serve-stale, prefetch), upstream groups, load balancing, health, validating forwarder
  dnsy-filter/    blocklist parsers + matcher, list sources, allowlist/custom rules, ACL, rate limit, response-IP policy
  dnsy-engine/    Handler trait, request pipeline composing zone/resolver/filter/observe
  dnsy-server/    listeners: UDP, TCP, DoT (+mTLS), DoH (axum); graceful shutdown
  dnsy-api/       REST API (axum + utoipa), problem+json, auth middleware, OpenAPI, embedded UI (feature embed-ui)
  dnsy/           binary: clap CLI, wiring, signals, logging
tests/e2e/        crate dnsy-e2e (publish = false): harness + DNS/DNSSEC/cache/API e2e suites; fixtures/dnssec/ (signed zones incl. BIND-signed references)
web/              Angular app (pnpm, angular.json, src/app/{core,shared,features}); build -> web/dist/dnsy/browser; web/e2e Playwright suites
branding/         logo.svg, mark.svg, favicon.svg, mascot/*.svg, tokens.css, fonts/
docs/book/        mdBook source;  docs/landing/  landing page;  docs/analysis/  analysis reports
docs/superpowers/ spec + plan (excluded from the book)
openapi/dnsy.json committed, generated spec (drift-tested)
examples/         dnsy.toml, zones/example.com.json, dnsy.service
.claude/skills/   dnsy-jira-worktree-workflow, dnsy-implement-story, dnsy-batch-implement-backlog
AGENTS.md  CLAUDE.md (points to AGENTS.md)  README.md  LICENSE  NOTICE  CONTRIBUTING.md  SECURITY.md
```

Dependency direction (enforced in review, checked in the coupling pass):
`core` <- everything; `proto` <- `dnssec`, `zone`, `resolver`, `filter`, `observe`, `engine`, `server`;
`dnssec` <- `zone`, `resolver` (`dnssec` itself depends only on `proto`, `core`, `ring`);
`store` <- `auth`, `observe`, `filter`, `resolver`, `zone` (keys); `engine` <- `server`;
`api` -> services only (never `server`); `dnsy` -> all.

## Pinned cross-crate interfaces

Producers must expose exactly these; consumers rely on them. Bodies are left to the builder.

```rust
// dnsy-core (DNSY-2)
pub enum Transport { Udp, Tcp, Dot, Doh }
pub enum Principal { Token { token: TokenId, user: UserId }, ClientCert { sha256: [u8; 32], subject: String } }
pub enum Role { Admin, Operator, Viewer }
pub enum Scope { DnsQuery, ApiRead, ApiWrite, Admin }   // serde: "dns:query", "api:read", "api:write", "admin"
pub enum DnssecStatus { Unchecked, Secure, Insecure, Bogus, Indeterminate }   // RFC 4035 4.3 + Unchecked (validation off, CD=1, local)
pub struct UserId(pub i64);  pub struct TokenId(pub i64);

// dnsy-proto (DNSY-4, 7, 8, 12, 13)
pub struct Name;                                     // Eq/Hash case-insensitive; Ord = RFC 4034 6.1 canonical order; Display = presentation
impl Name { pub fn from_ascii(s: &str) -> Result<Name, NameError>; pub fn root() -> Name;
            pub fn is_subdomain_of(&self, other: &Name) -> bool; pub fn labels(&self) -> impl Iterator<Item = &[u8]>;
            pub fn label_count(&self) -> u8; pub fn parent(&self) -> Option<Name>; pub fn wire_len(&self) -> usize;
            pub fn to_lowercase(&self) -> Name; }
pub enum RecordType { A, Ns, Cname, Soa, Ptr, Mx, Txt, Aaaa, Srv, Opt, Ds, Rrsig, Nsec, Dnskey, Nsec3, Nsec3param, Cds, Cdnskey, Svcb, Https, Caa, Any, Unknown(u16) }
pub enum Class { In, Ch, Any, Unknown(u16) }
pub enum Rcode { NoError, FormErr, ServFail, NxDomain, NotImp, Refused, BadVers, Unknown(u16) }
pub struct Header { pub id: u16, pub qr: bool, pub opcode: Opcode, pub aa: bool, pub tc: bool, pub rd: bool, pub ra: bool, pub ad: bool, pub cd: bool, pub rcode: Rcode }
pub struct Question { pub name: Name, pub qtype: RecordType, pub qclass: Class }
pub struct Record { pub name: Name, pub rtype: RecordType, pub class: Class, pub ttl: u32, pub data: RData }
pub enum RData { A(Ipv4Addr), Aaaa(Ipv6Addr), Ns(Name), Cname(Name), Ptr(Name), Mx { preference: u16, exchange: Name },
                 Txt(Vec<Vec<u8>>), Soa(Soa), Srv { priority: u16, weight: u16, port: u16, target: Name },
                 Caa { flags: u8, tag: String, value: Vec<u8> },
                 // added by DNSY-13:
                 Dnskey(Dnskey), Rrsig(Rrsig), Ds(Ds), Nsec { next: Name, types: TypeBitmap },
                 Nsec3(Nsec3), Nsec3param(Nsec3Param),
                 Opaque { rtype: u16, data: Vec<u8> } }   // RFC 3597 for the rest
pub struct Dnskey { pub flags: u16, pub protocol: u8, pub algorithm: u8, pub public_key: Vec<u8> }
impl Dnskey { pub fn key_tag(&self) -> u16; pub fn is_zone_key(&self) -> bool; pub fn is_sep(&self) -> bool; }  // RFC 4034 App. B
pub struct Rrsig { pub type_covered: RecordType, pub algorithm: u8, pub labels: u8, pub original_ttl: u32,
                   pub expiration: u32, pub inception: u32, pub key_tag: u16, pub signer: Name, pub signature: Vec<u8> }
pub struct Ds { pub key_tag: u16, pub algorithm: u8, pub digest_type: u8, pub digest: Vec<u8> }
pub struct Nsec3 { pub hash_alg: u8, pub flags: u8, pub iterations: u16, pub salt: Vec<u8>, pub next_hashed: Vec<u8>, pub types: TypeBitmap }
pub struct Nsec3Param { pub hash_alg: u8, pub flags: u8, pub iterations: u16, pub salt: Vec<u8> }
pub struct TypeBitmap;  impl TypeBitmap { pub fn contains(&self, t: RecordType) -> bool; pub fn from_types(t: &[RecordType]) -> Self; }
pub mod canonical { pub fn rrset_signing_input(rrsig: &Rrsig, rrset: &[Record]) -> Vec<u8>; // RFC 4034 3.1.8.1 + 6.2/6.3
                    pub fn rdata_wire(r: &RData) -> Vec<u8>; }                            // lowercased names, no compression
pub struct Message { pub header: Header, pub questions: Vec<Question>, pub answers: Vec<Record>,
                     pub authority: Vec<Record>, pub additional: Vec<Record>, pub edns: Option<Edns> }
impl Message { pub fn decode(buf: &[u8]) -> Result<Message, DecodeError>;
               pub fn encode(&self, max_len: usize) -> Result<Vec<u8>, EncodeError>; // compresses; truncates + sets TC
               pub fn response_to(query: &Message) -> Message;
               pub fn formerr_for(buf: &[u8]) -> Option<Vec<u8>>;                 // None if header unreadable
               pub fn set_ede(&mut self, code: u16, text: &str); }
pub struct Edns { pub udp_payload: u16, pub ext_rcode: u8, pub version: u8, pub dnssec_ok: bool, pub options: Vec<EdnsOption> }
pub enum EdnsOption { Padding(u16), ClientSubnet(Vec<u8>), Cookie(Vec<u8>), ExtendedError { code: u16, text: String }, Unknown { code: u16, data: Vec<u8> } }
pub mod ede { pub const UNSUPPORTED_DNSKEY_ALG: u16 = 1; pub const UNSUPPORTED_DS_DIGEST: u16 = 2; pub const STALE_ANSWER: u16 = 3;
              pub const DNSSEC_INDETERMINATE: u16 = 5; pub const DNSSEC_BOGUS: u16 = 6; pub const SIGNATURE_EXPIRED: u16 = 7;
              pub const SIGNATURE_NOT_YET_VALID: u16 = 8; pub const DNSKEY_MISSING: u16 = 9; pub const RRSIGS_MISSING: u16 = 10;
              pub const NSEC_MISSING: u16 = 12; pub const BLOCKED: u16 = 15; pub const FILTERED: u16 = 17; pub const PROHIBITED: u16 = 18;
              pub const STALE_NXDOMAIN: u16 = 19; pub const NO_REACHABLE_AUTHORITY: u16 = 22; pub const NETWORK_ERROR: u16 = 23; }

// dnsy-dnssec (DNSY-18, 24, 25, 30)
pub enum Algorithm { RsaSha256, RsaSha512, EcdsaP256Sha256, EcdsaP384Sha384, Ed25519, Unsupported(u8) }  // 8, 10, 13, 14, 15
pub enum DigestType { Sha1, Sha256, Sha384, Unsupported(u8) }                                           // 1 (verify only), 2, 4
pub fn verify_rrsig(rrset: &[Record], rrsig: &Rrsig, key: &Dnskey, now_unix: u32) -> Result<(), VerifyError>;
pub fn ds_for(owner: &Name, key: &Dnskey, dt: DigestType) -> Result<Ds, DnssecError>;
pub fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> [u8; 20];
pub struct SigningKey;   // holds a ring key pair; Debug never prints key material
impl SigningKey { pub fn generate(alg: Algorithm, ksk: bool) -> Result<SigningKey, DnssecError>;  // 13 and 15 only
                  pub fn from_pkcs8(alg: Algorithm, ksk: bool, der: &[u8]) -> Result<SigningKey, DnssecError>;
                  pub fn to_pkcs8(&self) -> Zeroizing<Vec<u8>>; pub fn dnskey(&self) -> Dnskey;
                  pub fn sign_rrset(&self, rrset: &[Record], signer: &Name, inception: u32, expiration: u32) -> Result<Record, DnssecError>; }
pub trait DnssecFetcher: Send + Sync { fn fetch(&self, q: Question) -> impl Future<Output = Result<Message, FetchError>> + Send; } // DO=1, CD=1
pub struct TrustAnchors;  // DS and/or DNSKEY anchors + negative trust anchors (RFC 7646)
pub struct Validator;
impl Validator { pub fn new(anchors: TrustAnchors) -> Self;
                 pub async fn validate<F: DnssecFetcher>(&self, f: &F, q: &Question, resp: &Message, now_unix: u32) -> ValidationOutcome; }
pub struct ValidationOutcome { pub status: DnssecStatus, pub ede: Option<(u16, String)>, pub min_ttl: Option<u32> }
pub struct ZoneSigner;   // signs a zone snapshot: RRSIGs, DNSKEY RRset, NSEC or NSEC3 chain, NSEC3PARAM
impl ZoneSigner { pub fn sign(zone: &ZoneData, keys: &ActiveKeys, policy: &SigningPolicy, now_unix: u32) -> Result<SignedZone, DnssecError>; }

// dnsy-engine (DNSY-23 creates the module, DNSY-31 implements the pipeline)
pub struct RequestContext { pub client: SocketAddr, pub transport: Transport, pub principal: Option<Principal>, pub received_at: Instant }
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, ctx: RequestContext, query: Message) -> impl Future<Output = Message> + Send;
}

// dnsy-observe (DNSY-10)
pub enum AnswerSource { Authoritative, Cache, CacheStale, Upstream(SocketAddr), Blocked { list: String }, Refused, Error }
pub struct QueryEvent { pub ts_unix_ms: i64, pub client: IpAddr, pub transport: Transport, pub principal: Option<String>,
                        pub qname: Name, pub qtype: RecordType, pub rcode: Rcode, pub source: AnswerSource,
                        pub dnssec: DnssecStatus, pub latency_us: u32 }
pub trait QueryEventSink: Send + Sync { fn record(&self, ev: QueryEvent); }  // non-blocking; drops + counts when full

// dnsy-store (DNSY-6)
impl Store { pub fn open(path: &Path) -> Result<Store, StoreError>;  // WAL, runs migrations
             pub async fn read<T: Send + 'static>(&self, f: impl FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static) -> Result<T, StoreError>;
             pub async fn write<T: Send + 'static>(&self, f: impl FnOnce(&mut Transaction) -> Result<T, StoreError> + Send + 'static) -> Result<T, StoreError>; }

// dnsy-auth (DNSY-16)
pub trait TokenVerifier: Send + Sync { fn verify(&self, presented: &str, needed: Scope) -> impl Future<Output = Result<Principal, AuthError>> + Send; }
// token format: "dnsy_" + base32(id, 8 bytes) + "_" + base64url(secret, 32 bytes); stored: id, sha256(secret)

// dnsy-resolver cache (DNSY-15; serve-stale/prefetch by DNSY-45)
pub struct CacheKey { pub name: Name /* lowercased */, pub qtype: RecordType, pub qclass: Class, pub do_bit: bool, pub cd_bit: bool }
pub enum CacheLookup { Fresh { msg: Message, dnssec: DnssecStatus }, Stale { msg: Message, dnssec: DnssecStatus, stale_for: Duration }, Miss }
impl Cache { pub fn get(&self, key: &CacheKey, now: Instant) -> CacheLookup;          // TTLs in msg already decremented
             pub fn insert(&self, key: CacheKey, msg: &Message, dnssec: DnssecStatus, now: Instant);
             pub fn flush_all(&self) -> usize; pub fn flush_name(&self, name: &Name, subtree: bool) -> usize;
             pub fn stats(&self) -> CacheStats; }
pub struct CacheStats { pub entries: u64, pub capacity: u64, pub hits: u64, pub misses: u64, pub inserts: u64,
                        pub evictions: u64, pub expired: u64, pub stale_served: u64, pub prefetches: u64 }

// dnsy-zone (DNSY-14, 19, 36)
pub struct ZoneSet;   // immutable snapshot (signed where enabled); ZoneStore holds ArcSwap<ZoneSet>
impl ZoneSet { pub fn lookup(&self, q: &Question, dnssec_ok: bool) -> Option<LookupResult>; }  // None = not authoritative
pub enum LookupResult { Answer { answers: Vec<Record>, authority: Vec<Record>, additional: Vec<Record> },
                        Referral { ns: Vec<Record>, ds_or_proof: Vec<Record>, glue: Vec<Record> },
                        NoData { authority: Vec<Record> }, NxDomain { authority: Vec<Record> } }  // authority = SOA (+ RRSIGs, NSEC/NSEC3 proofs when DO)

// dnsy-filter (DNSY-22)
pub enum Verdict { Allow, Block { list: String, mode: BlockMode } }
pub enum BlockMode { NxDomain, NullIp, Refused, CustomIp { v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr> } }
impl FilterSet { pub fn check(&self, qname: &Name) -> Verdict; }
```

## Migration numbers (pre-assigned)

| File | Story | Tables |
| --- | --- | --- |
| `0001_users.sql` | DNSY-9 | users |
| `0002_tokens_sessions.sql` | DNSY-16 | api_tokens, sessions, login_attempts |
| `0003_querylog_stats.sql` | DNSY-10 | query_log (incl. `dnssec` column), stats_minute (incl. cache hit/miss/stale counters), stats_top_hour |
| `0004_acl.sql` | DNSY-17 | acl_rules, rate_limits |
| `0005_upstreams.sql` | DNSY-26 | upstream_groups, upstreams |
| `0006_dnssec_keys.sql` | DNSY-25 | dnssec_keys (zone, role KSK/ZSK/CSK, algorithm, key_tag, state, timestamps, encrypted PKCS#8) |
| `0007_blocklists.sql` | DNSY-27 | blocklists, custom_rules |
| `0008_client_certs.sql` | DNSY-32 | client_certs |
| `0010_querylog_client_index.sql` | DNSY-76 | index `query_log_client (client, ts_ms, id)` |
| `0011_querylog_rare_index.sql` | DNSY-76 | partial index `query_log_rare (ts_ms, id)` for blocked/refused/error sources and rcodes other than NOERROR/NXDOMAIN |
| `0014_client_certs_autoincrement.sql` | DNSY-80 | rebuild `client_certs` with `INTEGER PRIMARY KEY AUTOINCREMENT` (ids never reused) |

The runner's own table `schema_migrations(version, name, checksum, applied_at)` is created by DNSY-6. The runner applies every known migration missing from that table in version order (set-based, not "max version"), so two migrations merged in the same wave in either order still converge.

## Phases and epics

| Phase | Epic | Stories |
| --- | --- | --- |
| 0 | E0 Process and skills | DNSY-1 |
| 1 | E1 Foundation and brand | DNSY-2, 3, 11 |
| 2 | E2 Protocol (in-house) | DNSY-4, 7, 8, 12, 13 |
| 3 | E3 Core services | DNSY-5, 6, 9, 10, 16 |
| 4 | E4 Zones, resolution, cache, DNSSEC | DNSY-14, 15, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 30, 31, 36, 37, 45 |
| 5 | E5 Transports and binary | DNSY-23, 28, 32, 33, 41 |
| 6 | E6 REST API | DNSY-29, 34, 38, 39, 40, 43 |
| 7 | E7 Web UI | DNSY-35, 42, 46, 47, 48, 49, 50, 51, 52 |
| 8 | E8 E2E, coverage, docs | DNSY-44, 53, 54, 55, 56, 57, 58 |
| 9 | E9 Analysis passes (model `fable`) + their follow-up fixes | DNSY-59 to 63, then DNSY-68+ |
| 10 | E10 Pipelines (last; nothing enabled before) | DNSY-64, 65, 66, 67 |

DNSSEC track: DNSY-13, 18, 24, 25, 30, 36, 37, 43, 52, 54, 55. Cache track: DNSY-15, 31 (bypass), 37 (validation state), 40 (API), 45, 47, 50, 53. The DNSSEC signing sub-track (DNSY-25, 30, 36, signing half of 43 and 52) can be cut or deferred without touching the validation sub-track (DNSY-13, 18, 24, 37).

## Jira story table

Create in this order so keys match. Difficulty score drives the implementation model (dnsy batch skill): 1-3 `haiku`, 4-8 `sonnet`, 9-10 `opus`; analysis passes always `fable`.

| Key | Epic | Summary | Depends on | Wave | Score / model |
| --- | --- | --- | --- | --- | --- |
| DNSY-1 | E0 | Adapt repsy skills as dnsy-* skills; commit spec and plan | - | 0 | 4 / orchestrator |
| DNSY-2 | E1 | Workspace bootstrap, lint/deny/just tooling, AGENTS.md, LICENSE, dnsy-core | 1 | 1 | 7 / sonnet |
| DNSY-3 | E1 | Temporary logo, Nox mascot SVG set, Tron design tokens, fonts | 2 | 2 | 5 / sonnet |
| DNSY-4 | E2 | dnsy-proto core: Name, enums, Header, wire reader/writer with compression map | 2 | 2 | 8 / sonnet |
| DNSY-5 | E3 | dnsy-config: TOML schema incl. [cache] and [dnssec], defaults, validation, env overrides | 2 | 2 | 5 / sonnet |
| DNSY-6 | E3 | dnsy-store: SQLite handle and in-house migration runner | 2 | 2 | 6 / sonnet |
| DNSY-7 | E2 | dnsy-proto Message codec: sections, compression, truncation, FORMERR | 4 | 3 | 9 / opus |
| DNSY-8 | E2 | dnsy-proto RDATA types and presentation format | 4 | 3 | 7 / sonnet |
| DNSY-9 | E3 | dnsy-auth users and roles (argon2id), first-admin bootstrap | 6 | 3 | 5 / sonnet |
| DNSY-10 | E3 | dnsy-observe: query-log writer, rollups (incl. cache, DNSSEC), stats queries, retention | 4, 6 | 3 | 7 / sonnet |
| DNSY-11 | E1 | Docs site skeleton: mdBook Tron theme, landing page with mascot | 3 | 3 | 4 / sonnet |
| DNSY-12 | E2 | dnsy-proto EDNS0, Extended DNS Errors, padding | 7 | 4 | 7 / sonnet |
| DNSY-13 | E2 | dnsy-proto DNSSEC RRs (DNSKEY, RRSIG, DS, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY), type bitmaps, key tag, canonical form | 7, 8 | 4 | 7 / sonnet |
| DNSY-14 | E4 | dnsy-zone model, JSON zone files (incl. dnssec policy block), normalised file names, hot reload | 8, 5 | 4 | 7 / sonnet |
| DNSY-15 | E4 | dnsy-resolver cache core: keying, positive/negative (RFC 2308), TTL clamp/decay, bounded eviction, security-state isolation, stats, flush | 7, 5 | 4 | 7 / sonnet |
| DNSY-16 | E3 | dnsy-auth API tokens, scopes, sessions, login throttling | 9 | 4 | 7 / sonnet |
| DNSY-17 | E4 | dnsy-filter ACL (CIDR allow/deny), per-client rate limit | 7, 5, 6 | 5 | 6 / sonnet |
| DNSY-18 | E4 | dnsy-dnssec crypto: algorithms over ring, RRSIG verify/sign, DS digests, NSEC3 hash, RFC test vectors | 13 | 5 | 8 / sonnet |
| DNSY-19 | E4 | dnsy-zone authoritative lookup (CNAME, wildcard, delegation, NODATA/NXDOMAIN, rotation) | 14, 8 | 5 | 9 / opus |
| DNSY-20 | E4 | dnsy-zone BIND master-file export | 14, 8 | 5 | 5 / sonnet |
| DNSY-21 | E4 | dnsy-resolver upstream client: UDP, TCP fallback, DoT | 7, 12 | 5 | 8 / sonnet |
| DNSY-22 | E4 | dnsy-filter blocklist parsers, matcher, allowlist, block responses with EDE | 4, 12, 5 | 6 | 7 / sonnet |
| DNSY-23 | E5 | dnsy-server UDP+TCP listeners; dnsy-engine Handler module | 7, 12 | 6 | 8 / sonnet |
| DNSY-24 | E4 | dnsy-dnssec chain-of-trust validator: trust anchors, DS/DNSKEY chain, NSEC/NSEC3 denial (incl. opt-out, wildcards), NTAs | 18, 13 | 6 | 10 / opus |
| DNSY-25 | E4 | DNSSEC keys: generation (ECDSAP256/Ed25519), encrypted storage, per-zone key sets, rollover state machine | 18, 6, 14 | 6 | 7 / sonnet |
| DNSY-26 | E4 | dnsy-resolver upstream groups, load-balancing strategies, health | 21, 6 | 6 | 7 / sonnet |
| DNSY-27 | E4 | dnsy-filter list sources: file/URL fetch, schedule, persistence | 22, 6 | 7 | 6 / sonnet |
| DNSY-28 | E5 | dnsy-server DoT listener with cert hot reload | 23 | 7 | 7 / sonnet |
| DNSY-29 | E6 | dnsy-api skeleton: router, problem+json, auth middleware, CSRF, OpenAPI, UI embed | 16 | 7 | 8 / sonnet |
| DNSY-30 | E4 | dnsy-dnssec zone signer: RRSIGs, DNSKEY RRset, NSEC and NSEC3 chains (opt-out), signature refresh | 25, 18, 14 | 7 | 9 / opus |
| DNSY-31 | E4 | dnsy-engine request pipeline (cache bypass for local zones) | 15, 17, 19, 22, 26, 10 | 7 | 9 / opus |
| DNSY-32 | E5 | mTLS client auth for DoT, fingerprint allowlist | 28, 6 | 8 | 8 / sonnet |
| DNSY-33 | E5 | DoH listener (RFC 8484) with token auth | 23, 16 | 8 | 8 / sonnet |
| DNSY-34 | E6 | API: auth, users, tokens endpoints | 29 | 8 | 6 / sonnet |
| DNSY-35 | E7 | Web UI shell: Angular workspace, Tron theme, routing, auth guard, interceptor, API types | 3, 29 | 8 | 6 / sonnet |
| DNSY-36 | E4 | Authoritative DNSSEC responses: online-signed snapshots, DO handling, DNSKEY/NSEC3PARAM at apex, denial and wildcard proofs, DS at delegations | 30, 19, 12 | 8 | 9 / opus |
| DNSY-37 | E4 | DNSSEC validation in the forwarding path: modes, AD/CD/DO, EDE, validated cache state, clock safety, query-log status | 24, 31, 15, 21 | 9 | 9 / opus |
| DNSY-38 | E6 | API: zones, records, BIND export endpoints | 29, 14, 20 | 9 | 6 / sonnet |
| DNSY-39 | E6 | API: ACL, upstreams, blocklists, rules, client certs, settings | 29, 26, 27, 17, 32 | 9 | 6 / sonnet |
| DNSY-40 | E6 | API: query log, live tail (SSE), stats, cache stats and cache flush | 29, 10, 15 | 9 | 5 / sonnet |
| DNSY-41 | E5 | dnsy binary: CLI, wiring, signals, logging, examples | 31, 23, 28, 32, 33, 29, 36 | 9 | 8 / sonnet |
| DNSY-42 | E7 | Mascot animation components (loading/empty/error/success/offline/404) | 35 | 10 | 5 / sonnet |
| DNSY-43 | E6 | API: DNSSEC zone signing, keys, rollover, DS export, signed BIND export, validation settings | 38, 25, 36, 20, 37 | 10 | 6 / sonnet |
| DNSY-44 | E8 | E2E harness and DNS protocol e2e suite | 41 | 10 | 8 / sonnet |
| DNSY-45 | E4 | Cache serve-stale (RFC 8767) and prefetch of popular entries | 31, 37, 15 | 10 | 7 / sonnet |
| DNSY-46 | E7 | three.js login scene with WebGL/reduced-motion fallback | 35, 42, 34 | 11 | 8 / sonnet |
| DNSY-47 | E7 | Dashboard: stats tiles (incl. cache, DNSSEC), QPS chart, top lists | 40, 35, 42 | 11 | 6 / sonnet |
| DNSY-48 | E7 | Query log page: filters (incl. DNSSEC status, stale), pagination, live tail | 40, 35, 42 | 11 | 5 / sonnet |
| DNSY-49 | E7 | Zones and records editor, BIND export download | 38, 35, 42 | 11 | 6 / sonnet |
| DNSY-50 | E7 | Filtering, ACL, upstreams, client certs, settings and cache pages | 39, 40, 35, 42 | 11 | 5 / sonnet |
| DNSY-51 | E7 | Users, tokens (show-once), profile pages | 34, 35, 42 | 12 | 5 / sonnet |
| DNSY-52 | E7 | DNSSEC UI: zone signing tab, keys and rollover, DS copy, validation settings and trust anchors | 43, 49, 50 | 12 | 6 / sonnet |
| DNSY-53 | E8 | REST API and cache e2e suite | 44, 34, 38, 39, 40, 45 | 12 | 6 / sonnet |
| DNSY-54 | E8 | DNSSEC e2e suite (validation and signing, happy and edge) | 44, 37, 43 | 12 | 8 / sonnet |
| DNSY-55 | E8 | DNSSEC operator guide: validation, signing, rollover runbook, registrar DS | 43, 37 | 12 | 4 / sonnet |
| DNSY-56 | E8 | Browser e2e suite (Playwright) | 46-52, 41 | 13 | 6 / sonnet |
| DNSY-57 | E8 | Coverage gate and gap filling to thresholds | 1-55 | 13 | 5 / sonnet |
| DNSY-58 | E8 | Aesthetic README, docs completeness, screenshots | 1-55 | 13 | 4 / sonnet |
| DNSY-59 | E9 | Analysis: coupling and cohesion | 56-58 | 14 | fable |
| DNSY-60 | E9 | Analysis: dependency optimisation | 56-58 | 14 | fable |
| DNSY-61 | E9 | Analysis: security review (incl. DNSSEC) | 56-58 | 14 | fable |
| DNSY-62 | E9 | Analysis: database optimisation and performance | 56-58 | 14 | fable |
| DNSY-63 | E9 | Analysis: runtime performance optimisation (incl. cache and DNSSEC) | 56-58 | 14 | fable |
| DNSY-64 | E10 | CI and e2e workflows, dependabot config | 59-63, all follow-ups (DNSY-68+) Done | F | 4 / sonnet |
| DNSY-65 | E10 | PR title check workflow | same as 64 | F | 2 / haiku |
| DNSY-66 | E10 | Release pipeline (dist) for linux/mac/windows | same as 64 | F | 6 / sonnet |
| DNSY-67 | E10 | GitHub Pages deployment (landing, book, Redoc, rustdoc) | same as 64 | F | 4 / sonnet |

Follow-up stories from the analysis passes are created later and so get keys DNSY-68 onward; they still run before DNSY-64 to 67 (Jira "is blocked by" links from each pipeline story to every follow-up). Wave `F` is the final wave.

## Parallelisation waves

Concurrency 5 by default. Stories in a wave share no files except the noted append-only points.

| Wave | Stories | Notes |
| --- | --- | --- |
| 0 | DNSY-1 | Orchestrator does it directly (the batch skill does not exist yet). Jira stories created first. |
| 1 | DNSY-2 | Alone: pins workspace deps, lints, crates (incl. empty `dnsy-dnssec`), `dnsy-core`. Then run graphify for the first graph. |
| 2 | 3, 4, 5, 6 | Disjoint crates/dirs. |
| 3 | 7, 8, 9, 10, 11 | 7 and 8 both in `dnsy-proto`: 7 owns `message.rs`, `compress.rs`; 8 owns `rdata/`. `lib.rs` re-exports are append-only. |
| 4 | 12, 13, 14, 15, 16 | 12 and 13 both in `dnsy-proto`: 12 owns `edns.rs`; 13 owns `rdata/dnssec/`, `canonical.rs`, `bitmap.rs` (adds `RData` variants: append-only). |
| 5 | 17, 18, 19, 20, 21 | 19 and 20 in `dnsy-zone`: 19 owns `lookup.rs`, 20 owns `export.rs`. |
| 6 | 22, 23, 24, 25, 26 | 24 owns `dnsy-dnssec/src/validate/`; 25 owns `dnsy-dnssec/src/keys.rs` + `dnsy-zone/src/keystore.rs`. 25 and 26 both add migrations (0006, 0005); the set-based runner makes merge order irrelevant. |
| 7 | 27, 28, 29, 30, 31 | 30 owns `dnsy-dnssec/src/sign/`. 31 creates `EngineBuilder::from_config`. |
| 8 | 32, 33, 34, 35, 36 | 32 and 33 in `dnsy-server`: 32 owns `dot/mtls.rs`, 33 owns `doh/`. 36 owns `dnsy-zone/src/signed.rs` and the DO paths of `lookup.rs`. |
| 9 | 37, 38, 39, 40, 41 | 37 changes `dnsy-resolver/src/forward.rs` + engine internals behind `EngineBuilder::from_config`; 41 only calls the builder, so no overlap. 38-40 each own `crates/dnsy-api/src/routes/<group>.rs`; `openapi.rs` and `openapi/dnsy.json` are regenerated (`just openapi`) on rebase. |
| 10 | 42, 43, 44, 45 | 43 owns `routes/dnssec.rs`; 45 owns `dnsy-resolver/src/cache/{stale,prefetch}.rs`. |
| 11 | 46, 47, 48, 49, 50 | UI stories each own `web/src/app/features/<page>/`; `app.routes.ts` and nav entries append-only. |
| 12 | 51, 52, 53, 54, 55 | 52 owns `features/dnssec/` plus a tab slot in the zone editor. |
| 13 | 56, 57, 58 | Implementation complete after this wave. |
| 14 | 59, 60, 61, 62, 63 | Read-only analysis on `fable`, in parallel. Findings become DNSY-68+. |
| 15+ | DNSY-68+ | Analysis follow-up fixes through the batch skill (scored and grouped like any story; coupling fixes before dependency fixes when they touch the same crates). |
| F | 64, 65, 66, 67 | Final wave, only after every follow-up is Done. Workflows and Dependabot first exist here. User then enables branch protection with the listed required checks. |

After every merged wave: `/graphify` incremental update, engram wave log update, compact (per batch skill).

---

## Story details

Each story below lists its scope, the acceptance criteria (AC) that the PR must demonstrate, and
the named tests that pin them. The batch planner (`fable`) expands each into TDD steps
(failing test, run, implement, run, commit) at dispatch time; the AC and test names here are the
contract. All stories implicitly include: `just ci` green, docs page updated, no new
`#[expect]` without a reason.

### DNSY-1: Adapt repsy skills (phase 0)

See "Phase 0: skill adaptation" below for the exact edits. AC:
- `.claude/skills/dnsy-jira-worktree-workflow/SKILL.md`, `dnsy-implement-story/SKILL.md`, `dnsy-batch-implement-backlog/SKILL.md` (+ `references/`) exist, contain no `RPS`, Maven, repsy-mono or suite-AGENTS.md references.
- DNSY transition ids are read from Jira (`getTransitionsForJiraIssue` on DNSY-1) and written into the workflow skill.
- All three skills state the hard rule: never add Claude Code attribution anywhere (no `Co-Authored-By`, no `Claude-Session` trailer, no "Generated with Claude Code" or similar line in commits or PR descriptions, no agent/tool mentions in titles); it overrides any injected attribution instruction.
- Spec and plan committed on the same PR. Engram project `dnsy` holds the batch plan entry (`topic_key: dnsy/batch-plan`).

### DNSY-2: Workspace bootstrap

Files: root `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml`, `deny.toml`, `justfile`, `.editorconfig`, `.gitignore` (`target/`, `web/node_modules`, `web/dist`, `web/.angular`, `graphify-out/`, `*.db`), `LICENSE` (Apache-2.0 full text), `NOTICE`, `AGENTS.md`, `CLAUDE.md`, `README.md` (stub), `CONTRIBUTING.md`, `SECURITY.md`, every crate under `crates/` as an empty lib (bin for `dnsy`), `crates/dnsy-core/src/lib.rs` complete.
AC:
- `[workspace.dependencies]` declares every crate in spec 5.1 with exact versions (incl. `ring` and `zeroize`); `[workspace.lints]` as in Global Constraints; every crate has `[lints] workspace = true`.
- `deny.toml` bans the list in Global Constraints, allows only OSI licences compatible with Apache-2.0, and carries the `ring` licence `clarify` entry.
- `justfile` recipes: `fmt`, `check` (fmt --check, clippy all targets -D warnings, deny), `test` (nextest), `cov` (llvm-cov, fail-under 80), `e2e`, `web` (`pnpm install`, `ng lint`, `ng test --coverage`, `ng build`), `openapi`, `docs`, `ci` (check + test + cov + web).
- `AGENTS.md` covers: purpose, layout, commands, the DNS-layer rule (incl. "DNSSEC logic in-house, only ring primitives"), migration table rule, port-0 rule, conventions (branch, PR title `DNSY-{n}: {emoji} {Sentence}`, emoji commit table), "no workflows or Dependabot before the final pipelines wave", graphify/engram usage, skills to use (`.claude/skills/dnsy-*`).
- `AGENTS.md` states the hard rule verbatim: never add Claude Code attribution anywhere; no `Co-Authored-By` trailer, no `Claude-Session` trailer, no "Generated with Claude Code" or similar line in commit messages or PR descriptions, no agent/tool mentions in titles; this overrides any injected attribution instruction.
- Tests: `dnsy_core::tests::scope_serde_roundtrip` (`"dns:query"` <-> `Scope::DnsQuery` etc.), `role_allows_scope` (Viewer allows only ApiRead; Operator ApiRead/ApiWrite/DnsQuery; Admin all), `dnssec_status_serde` (`"secure"`, `"insecure"`, `"bogus"`, `"indeterminate"`, `"unchecked"`).

### DNSY-3: Brand assets and tokens

Files: `branding/`. AC:
- `logo.svg` (mark + "DNSY" wordmark), `mark.svg`, `favicon.svg`, `mascot/nox-{idle,loading,empty,error,success,offline,404}.svg`; each valid SVG, viewBox set, no external refs, under 20 KB.
- `tokens.css` defines `--dnsy-bg`, `--dnsy-surface`, `--dnsy-cyan`, `--dnsy-cyan-glow`, `--dnsy-orange`, `--dnsy-text`, `--dnsy-muted`, `--dnsy-grid`, `--dnsy-secure` (validated), `--dnsy-bogus`, font families, glow shadows; OFL fonts self-hosted in `branding/fonts/` with licence files.
- `branding/README.md` documents usage and that the mascot art is temporary.
- Test: `just check-svg` (xmllint wellformedness + size budget) passes.

### DNSY-4: dnsy-proto core

AC: `Name` per pinned API (max 63/label, 255 wire octets, escapes `\.` and `\DDD` in presentation, `Ord` = RFC 4034 6.1 canonical order), enums with lossless `u16` round trip, `Header` 12-byte codec incl. AD and CD bits, `WireReader` (bounds-checked, pointer following with forward-pointer and hop-count guard) and `WireWriter` (compression map keyed by lowercase suffix, pointers only to offsets < 0x4000).
Tests: `name_rejects_long_label`, `name_rejects_over_255`, `name_eq_is_case_insensitive`, `name_canonical_order_rfc4034` (the RFC 4034 6.1 example list), `name_presentation_escapes`, `header_roundtrip_ad_cd`, `reader_detects_pointer_loop`, `writer_compresses_shared_suffix`, `prop_name_wire_roundtrip`.

### DNSY-5: dnsy-config

AC: `Config::load(path) -> Result<Config, ConfigError>` with sections `server` (data_dir), `dns` (udp, tcp listen lists), `dot` (listen, cert, key, client_ca, mtls = off|optional|required), `doh` (listen, cert, key, path, require_token = true), `api` (listen, tls cert/key optional, public_url), `zones` (dir), `resolver` (timeout_ms, attempts, seed upstreams), `cache` (enabled = true, max_entries = 100000, min_ttl = 0, max_ttl = 86400, negative_max_ttl = 3600, servfail_ttl = 5, bogus_ttl = 60, serve_stale.enabled = true, serve_stale.max_stale = 86400, serve_stale.answer_ttl = 30, serve_stale.client_timeout_ms = 1800, prefetch.enabled = true, prefetch.min_hits = 5, prefetch.remaining_ttl_pct = 10), `dnssec` (validation = off|permissive|strict, default `strict`; trust_anchors (DS strings, default root KSK-2017 20326 and KSK-2024 38696), trust_anchor_file, negative_trust_anchors, clock_skew_s = 300, key_passphrase_file / `DNSY_DNSSEC_PASSPHRASE`), `filter` (block_mode, seed blocklists, refresh_interval), `limits` (per_client_qps, tcp_idle_ms, max_tcp_conns), `querylog` (enabled, retention_days, redact_client_ip), `logging` (level, format = pretty|json). Unknown keys are errors; `DNSY_SECTION__KEY` env overrides; `examples/dnsy.toml` validates.
Tests: `defaults_are_valid`, `unknown_key_rejected`, `env_override_applies`, `tls_required_when_dot_enabled`, `cache_min_ttl_le_max_ttl`, `trust_anchor_ds_parses`, `example_config_parses`.

### DNSY-6: dnsy-store

AC: pinned `Store` API; WAL + `foreign_keys=ON` + busy timeout; migrations from `crates/dnsy-store/migrations/NNNN_name.sql` registered in `MIGRATIONS`; set-based application in version order, each in its own transaction; checksum mismatch or a DB containing an unknown migration fails startup with a clear error; `Store::migration_status()` for `dnsy migrate --status`.
Tests: `fresh_db_applies_all`, `reopen_is_noop`, `edited_migration_fails`, `unknown_migration_refuses`, `out_of_order_merge_converges`, `failed_migration_rolls_back`, `concurrent_reads_during_write`.

### DNSY-7: Message codec

AC: pinned `Message` API; decode validates counts against data; encode compresses names in all sections including RDATA names for NS/CNAME/PTR/MX/SOA (never in RRSIG/NSEC/SRV RDATA, per RFC 3597/4034/2782); `encode(max_len)` drops whole RRsets from the end, sets TC, keeps OPT; `formerr_for` echoes id and question when parseable. `cargo-fuzz` target `fuzz_decode` under `crates/dnsy-proto/fuzz/` (not run in CI).
Tests: `decode_rejects_hostile_inputs` (Review Focus 1 table), `roundtrip_known_packets` (captured fixtures for A, AAAA, MX, SOA, NXDOMAIN), `truncation_sets_tc_and_fits`, `formerr_echoes_id`, `prop_message_roundtrip`.

### DNSY-8: RDATA types

AC: codecs and presentation (RFC 1035 master-file syntax) for every non-DNSSEC `RData` variant; `Opaque` uses RFC 3597 `\# len hex`; TXT strings > 255 split on encode.
Tests: `rdata_roundtrip_each_type`, `txt_long_string_split`, `presentation_matches_fixtures` (insta), `unknown_type_rfc3597`.

### DNSY-9: Users and roles

AC: migration `0001_users.sql`; `UserService::{create, get, list, update_role, set_password, delete, verify_password}`; argon2id with OWASP params; usernames unique case-insensitively; last admin cannot be deleted or demoted; bootstrap: if no users at start, generate a one-time bootstrap code printed once to stderr, valid 1 hour, consumable once to create the first admin.
Tests: `password_verify_roundtrip`, `duplicate_username_rejected`, `last_admin_protected`, `bootstrap_code_single_use_and_expires`.

### DNSY-10: dnsy-observe

AC: pinned `QueryEvent`/`QueryEventSink`; `QueryLogWriter` (bounded channel 10k, batches of up to 500 or 1 s, dropped counter); migration `0003`; rollups per minute (count by rcode, by source incl. `cache`/`cache_stale`, by DNSSEC status, latency sum/max) and per hour top-N (qname, blocked qname, client); `StatsService::{summary(range), timeseries(range, bucket), top_domains(range, n), top_blocked(range, n), top_clients(range, n)}` where summary includes cache hit ratio, stale answers and secure/bogus counts; `QueryLogQuery` filters (time range, client, qname substring, qtype, rcode, source, dnssec) with keyset pagination; retention purge task; `redact_client_ip` stores /24 or /48.
Tests: `batch_flushes_on_size_and_time`, `full_channel_drops_and_counts`, `top_domains_orders_by_count`, `summary_cache_hit_ratio`, `retention_purges_old_rows`, `client_ip_redaction`, `pagination_is_stable`.

### DNSY-11: Docs site skeleton

AC: `docs/book/book.toml` + `theme/` (Tron CSS from `branding/tokens.css`, mascot in header), `SUMMARY.md` with the outline: Introduction, Install, Quickstart, Configuration reference, Zones (JSON format, export), Resolver, upstreams and cache, DNSSEC (validation, signing, rollover, registrar DS), Filtering (blocklists, ACL, rate limits), DoT and mTLS, DoH and tokens, Web UI, REST API (link `/api/`), Operations (query log, stats, cache flush, backups, key backup, upgrades and migrations), Architecture, Contributing, Security; `docs/landing/index.html` with animated mascot; `just docs` builds `target/site/{index.html,docs/,api/}`.
Test: `just docs` exits 0 and `mdbook test` passes; landing passes `just check-svg` budget for inline SVG.

### DNSY-12: EDNS0, EDE, padding

AC: OPT parse/emit (one OPT max, else FORMERR; unknown version -> BADVERS), extended rcode merge, DO bit, options per pinned enum; padding to 468-byte blocks for DoT/DoH responses when the query carried padding (RFC 8467); `Message::set_ede(code, text)`; EDE constants per pinned `ede` module.
Tests: `opt_roundtrip`, `two_opt_is_formerr`, `badvers_on_version_1`, `ext_rcode_combines`, `do_bit_roundtrip`, `padding_block_468`, `ede_roundtrip`.

### DNSY-13: DNSSEC records and canonical form

AC: wire codecs and presentation for DNSKEY, RRSIG (timestamps as `YYYYMMDDHHmmSS`, serial-number arithmetic RFC 1982 for comparisons), DS, NSEC, NSEC3 (base32hex owner/next hash), NSEC3PARAM, CDS, CDNSKEY; `TypeBitmap` encode/decode (window blocks, reject empty/unsorted/oversized windows); `Dnskey::key_tag` (RFC 4034 App. B, incl. the algorithm-1 special case returning a value without panicking); `canonical::rrset_signing_input` (RFC 4034 3.1.8.1, 6.2 lowercasing of names in listed RDATA types, 6.3 RR ordering, original TTL, wildcard label handling via `labels`).
Tests: `dnssec_rdata_roundtrip_each_type`, `key_tag_matches_rfc4034_example`, `type_bitmap_roundtrip`, `type_bitmap_rejects_malformed`, `rrsig_time_serial_arithmetic`, `canonical_ordering_rfc4034_6_3`, `canonical_lowercases_rdata_names`, `nsec3_presentation_base32hex`, `prop_dnssec_rdata_roundtrip`.

### DNSY-14: Zone model and storage

AC: JSON schema `{"schema":1,"origin":"example.com.","default_ttl":3600,"soa":{...},"records":[{"name":"www","type":"A","ttl":300,"value":"192.0.2.1"}],"dnssec":{"enabled":false,"algorithm":13,"key_layout":"csk","denial":"nsec3","nsec3":{"iterations":0,"salt":"","opt_out":false},"signature_validity_days":14,"refresh_days":5,"dnskey_ttl":3600}}` (value in presentation form, parsed via DNSY-8; `dnssec` block optional and validated: algorithms 13|15, iterations 0 per RFC 9276 unless explicitly overridden with a warning); hand-written DNSKEY/RRSIG/NSEC* records in zone files rejected (signing owns them); validation (SOA present, CNAME exclusivity, names inside origin, record types supported); file name normalisation per spec 5.2; atomic writes; `ZoneStore` with `ArcSwap<ZoneSet>`, notify watcher with 250 ms debounce; per-zone `load_error`.
Tests: `zone_file_name_normalisation`, `cname_exclusivity_rejected`, `dnssec_block_validated`, `manual_rrsig_rejected`, `atomic_write_never_partial`, `reload_picks_up_change`, `reload_keeps_previous_zone_on_invalid_json`, `example_zone_loads`.

### DNSY-15: Cache core

AC: pinned `Cache`/`CacheKey`/`CacheLookup`/`CacheStats`; key = (lowercased name, type, class, DO, CD); sharded map (concurrent readers, no global lock on the hot path) with a size bound `max_entries` and LRU-like eviction (eviction counted); positive TTL = min TTL across cached RRsets clamped to [`min_ttl`, `max_ttl`]; negative caching (RFC 2308): NXDOMAIN and NODATA cached for min(SOA TTL, SOA minimum, `negative_max_ttl`), NXDOMAIN cached by name so it answers any type; SERVFAIL cached for `servfail_ttl`; served TTLs decremented to remaining lifetime, never below 0; every entry stores its `DnssecStatus`: `Bogus` entries capped at `bogus_ttl`, never returned to a CD=0 query as anything but SERVFAIL, and never replace a `Secure` entry; CD=1 entries live under their own key; truncated (TC) and authoritative (AA from our own zones) messages are never inserted; `flush_all`, `flush_name(name, subtree)`; `stats()` counters; `Fresh`/`Miss` only (stale lifecycle added in DNSY-45, entries already keep `expires_at` and `stale_until`).
Tests: `ttl_decrements_on_serve`, `ttl_clamped_to_min_and_max`, `expired_entry_misses`, `negative_cache_uses_soa_minimum`, `nxdomain_answers_other_types`, `servfail_short_ttl`, `bounded_eviction_counts`, `do_bit_separates_entries`, `cd_entries_isolated`, `bogus_never_served_as_secure`, `secure_not_overwritten_by_bogus`, `tc_and_aa_not_cached`, `flush_name_subtree`, `concurrent_get_insert` (loom-free stress with threads), `stats_counters_accurate`.

### DNSY-16: Tokens and sessions

AC: migration `0002`; `TokenService::{create(user, name, scopes, expires_at) -> (String, TokenMeta), list(user), revoke(id)}` implementing pinned `TokenVerifier`; format pinned; scopes must be subset of role; `last_used_at` updated at most once per minute; `SessionService` (256-bit id, idle 30 min, absolute 12 h, rotate on login); login throttling: 5 failures per username+IP per 15 min -> 429 with `Retry-After`.
Tests: `token_shown_once_verifies`, `revoked_token_rejected`, `expired_token_rejected`, `scope_subset_enforced`, `constant_time_compare_used` (code-level), `session_idle_and_absolute_expiry`, `login_throttle_kicks_in`.

### DNSY-17: ACL and rate limit

AC: migration `0004`; `Acl::check(ip, principal) -> AclAction { Allow, Refuse, Drop }`, longest-prefix-match, default allow configurable; token-bucket `RateLimiter` per client /32 or /64 with burst = 2 x qps; over-limit -> REFUSED (TCP/DoT/DoH) or drop (UDP, to avoid amplification).
Tests: `longest_prefix_wins`, `ipv6_cidr_match`, `principal_rule_matches_client_cert`, `rate_limit_refills`, `udp_over_limit_drops`.

### DNSY-18: DNSSEC crypto primitives

AC: `dnsy-dnssec` depends only on `dnsy-proto`, `dnsy-core`, `ring`, `zeroize`; algorithm mapping: 8 RSASHA256 and 10 RSASHA512 verify (ring RSA PKCS#1, 1024-8192-bit legacy variants for 1024-bit keys), 13 ECDSAP256SHA256 and 14 ECDSAP384SHA384 verify (fixed-width r||s), 15 Ed25519 verify; signing only 13 and 15 (`ring` cannot generate RSA keys; documented); algorithms 1, 3, 5, 6, 7, 12, 16 reported `Unsupported` (validator treats as insecure per RFC 6840 5.2); DNSKEY public-key format conversion (RFC 3110 RSA exponent/modulus, RFC 6605 raw EC points, RFC 8080 Ed25519); `verify_rrsig` checks key tag, algorithm, signer name, labels, inception/expiration with serial arithmetic and the configured skew, zone-key flag, then the signature over `canonical::rrset_signing_input`; `ds_for` with SHA-1 (verify-only), SHA-256, SHA-384; `nsec3_hash` (SHA-1, iterations, salt; RFC 5155).
Tests (RFC vectors committed under `crates/dnsy-dnssec/tests/vectors/`): `rfc5702_rsasha256_example_verifies`, `rfc5702_rsasha512_example_verifies`, `rfc6605_ecdsap256_example_verifies`, `rfc6605_ecdsap384_example_verifies`, `rfc8080_ed25519_examples_verify`, `rfc4034_ds_example_matches`, `rfc5155_appendix_a_hashes`, `expired_rrsig_rejected`, `not_yet_valid_rrsig_rejected`, `tampered_rdata_fails`, `wrong_key_tag_fails`, `sign_then_verify_ecdsa_and_ed25519`, `signing_rsa_unsupported_error`.

### DNSY-19: Authoritative lookup

AC: `ZoneSet::lookup` per pinned API (unsigned behaviour; `dnssec_ok` ignored until DNSY-36): closest enclosing zone; exact match; CNAME chain within zone (max 8, loop-safe); wildcards per RFC 4592 (no match when the name exists, empty non-terminals respected); delegation -> `Referral` with glue; NODATA and NXDOMAIN with SOA (TTL = min(SOA TTL, minimum)); ANY returns all RRsets; RRset order rotated per query.
Tests: `exact_match`, `cname_chain_in_zone`, `cname_loop_terminates`, `wildcard_rules_rfc4592`, `empty_non_terminal_is_nodata`, `delegation_referral_with_glue`, `nxdomain_has_soa`, `rrset_rotation`.

### DNSY-20: BIND export

AC: `export_bind(&Zone, signed: Option<&SignedZone>) -> String` with `$ORIGIN`, `$TTL`, multi-line SOA, relative owner names, records grouped by owner, presentation from DNSY-8/13; the signed variant (wired in DNSY-43) appends DNSKEY, RRSIG, NSEC/NSEC3, NSEC3PARAM in canonical order.
Tests: `export_snapshot_example_zone` (insta), `export_escapes_txt`, interop `named_checkzone_accepts_export` (skips when `named-checkzone` missing).

### DNSY-21: Upstream client

AC: `UpstreamClient::query(&Upstream, &Message) -> Result<Message, UpstreamError>` for `udp://`, `tcp://`, `tls://host:853#sni`; random query id per attempt, response id and question validated (anti-spoofing), TCP retry on TC, per-attempt timeout, DoT connection reuse with idle close, EDNS payload 1232 advertised, DO and CD forwarded as requested by the caller.
Tests (against in-test fake servers): `udp_answer`, `tc_triggers_tcp_retry`, `mismatched_id_ignored`, `timeout_errors`, `do_and_cd_bits_forwarded`, `dot_with_test_ca`, `dot_reuses_connection`.

### DNSY-22: Blocklist engine

AC: parsers for hosts (`0.0.0.0 domain`), plain domains, adblock subset (`||domain^`, `@@||domain^` allow, `!`/`#` comments), tolerant of CRLF/BOM/IDN (punycoded), invalid lines counted not fatal; `FilterSet` suffix matcher (label-reversed trie or hashed suffixes) with allowlist precedence and custom rules; `FilterSet::check` per pinned API; response builder sets EDE 15 (blocked) or 17 (filtered).
Tests: `parse_hosts_format`, `parse_adblock_subset`, `allowlist_overrides_block`, `subdomain_blocked_by_parent`, `invalid_lines_counted`, `million_entries_memory_bound` (`#[ignore]`, run in perf pass), `block_response_modes`.

### DNSY-23: UDP and TCP listeners

AC: creates `dnsy-engine::handler` with pinned `Handler`/`RequestContext`; UDP: payload size = min(client EDNS, 1232) or 512 without EDNS, truncation via `encode(max_len)`; TCP: 2-byte framing, pipelining with out-of-order responses, idle timeout `tcp_idle_ms`, `max_tcp_conns`; malformed -> `formerr_for` or drop; graceful shutdown drains in-flight requests (5 s cap).
Tests: `udp_roundtrip_stub_handler`, `udp_truncates_for_512`, `tcp_pipelined_queries`, `tcp_idle_timeout_closes`, `udp_garbage_gets_formerr_or_drop`, `shutdown_drains`.

### DNSY-24: Chain-of-trust validator

AC: pinned `Validator`/`TrustAnchors`/`DnssecFetcher`/`ValidationOutcome`; builds the chain from the closest trust anchor down to the answer's signer: anchor DS/DNSKEY -> DNSKEY RRset (self-signed by a SEP key matching DS) -> DS at each zone cut (fetched via `DnssecFetcher`, cached per validation in a bounded memo) -> answer RRsets; validates CNAME/DNAME chains link by link; denial of existence: NSEC (RFC 4035 5.4: covering, wildcard non-existence, NODATA bitmap checks incl. "no CNAME, no NS at non-apex"), NSEC3 (RFC 5155 8: closest-encloser proof, next-closer cover, wildcard cover, opt-out spans yield Insecure for unsigned delegations, iterations above 100 treated as Insecure per RFC 9276); insecure delegations proven by NSEC/NSEC3 at the parent; status per RFC 4035 4.3; EDE mapping: bogus 6, expired 7, not-yet-valid 8, DNSKEY missing 9, RRSIGs missing 10, NSEC missing 12, unsupported algorithm 1, unsupported digest 2, indeterminate 5; negative trust anchors short-circuit to Insecure; work limits (max 16 zone cuts, max 8 RRSIG verifications per RRset, max 32 fetches per validation) prevent KeyTrap-style CPU exhaustion (CVE-2023-50387) and NSEC3 hash floods (CVE-2023-50868).
Tests (unit against an in-memory fetcher serving fixture zones signed by test helpers plus committed BIND-signed fixtures in `tests/e2e/fixtures/dnssec/`): `secure_chain_from_root_anchor`, `insecure_delegation_via_nsec`, `insecure_delegation_via_nsec3_opt_out`, `bogus_bad_signature`, `bogus_expired_rrsig_ede7`, `bogus_missing_ds_dnskey_mismatch`, `bogus_rrsigs_stripped_ede10`, `nxdomain_nsec_proof_valid`, `nxdomain_nsec3_closest_encloser`, `nodata_nsec_bitmap`, `wildcard_expansion_proof`, `unsupported_algorithm_is_insecure`, `nta_short_circuits`, `keytrap_many_keys_bounded`, `nsec3_high_iterations_insecure`, `cname_chain_validated_per_link`.

### DNSY-25: DNSSEC keys

AC: migration `0006`; `KeyStore` (in `dnsy-zone`) persisting per-zone keys: role `csk` | `ksk` | `zsk`, algorithm 13 or 15, key tag, state machine `generated -> published -> active -> retired -> removed` (RFC 6781/7583 basics) with timestamps; private keys stored as PKCS#8 encrypted with AES-256-GCM (ring) under a key derived with argon2id from the passphrase file/env; without a passphrase keys are stored unencrypted and a startup warning plus API flag `keys_encrypted=false` is raised; `SigningKey` material zeroized on drop and redacted in `Debug`; rollover planner: ZSK pre-publish (publish, wait DNSKEY TTL + propagation, activate, retire after max signature validity), KSK/CSK double-DS (new key published, operator confirms DS at parent via API, then old retired); timer task advances states; key export for backup (encrypted bundle) and import.
Tests: `generate_csk_ecdsa_and_ed25519`, `pkcs8_encrypt_roundtrip`, `wrong_passphrase_fails_cleanly`, `unencrypted_mode_flagged`, `debug_redacts_private_key`, `zsk_rollover_states_advance_on_schedule`, `ksk_rollover_waits_for_ds_confirmation`, `backup_bundle_roundtrip`.

### DNSY-26: Upstream groups and load balancing

AC: migration `0005`; groups with strategy `round_robin | weighted | lowest_latency | failover`; per-domain routing (`*.corp.example -> group corp`); EWMA latency; passive health: 3 consecutive failures -> ejected for exponential backoff 5 s to 5 min, probe re-admits; config seeds on first start.
Tests: `round_robin_distribution`, `weighted_distribution_within_tolerance`, `lowest_latency_prefers_fast`, `failover_order`, `ejection_and_recovery`, `domain_routing`.

### DNSY-27: Blocklist sources

AC: migration `0007`; sources (file or https URL), enabled flag, refresh interval, ETag/Last-Modified conditional fetch, 50 MB size cap, 30 s timeout, only http(s) schemes, private/loopback targets refused unless `allow_private` (SSRF); failed fetch keeps previous list; rebuild `FilterSet` off the hot path and swap.
Tests (local axum fixture server): `conditional_fetch_304_keeps_list`, `failed_fetch_keeps_previous`, `size_cap_enforced`, `private_target_refused`, `schedule_refreshes`.

### DNSY-28: DoT listener

AC: rustls server on `dot.listen` with ALPN `dot`; PEM cert/key, reloaded on file change or SIGHUP without dropping connections; same framing/idle rules as TCP; padding applied when requested.
Tests: `dot_query_with_test_ca`, `cert_reload_serves_new_cert`, `plain_tcp_on_dot_port_rejected`, `dot_idle_timeout`.

### DNSY-29: API skeleton

AC: axum router under `/api/v1`; `routes/{auth,users,tokens,zones,dnssec,filtering,upstreams,certs,settings,querylog,stats,cache}.rs` stubs registered; problem+json errors; auth extractor accepting bearer token or session cookie, cookie auth requires `X-CSRF-Token` matching the `dnsy_csrf` cookie on unsafe methods; scope checks via `RequireScope`; `GET /healthz`, `/readyz`, `/api/v1/version`; `/api/openapi.json`; `openapi/dnsy.json` drift test; security headers (CSP `default-src 'self'`, `X-Content-Type-Options`, `Referrer-Policy`, HSTS when TLS); static UI from `web/dist/dnsy/browser` (Angular build output) behind feature `embed-ui` with SPA fallback to `index.html`; request tracing that redacts `Authorization` and `Cookie`.
Tests: `unauthenticated_is_401_problem_json`, `wrong_scope_is_403`, `csrf_required_for_cookie_post`, `bearer_post_needs_no_csrf`, `openapi_spec_matches_committed`, `security_headers_present`, `auth_headers_not_logged`.

### DNSY-30: Zone signer

AC: pinned `ZoneSigner::sign`: DNSKEY RRset at apex (signed by KSK/CSK), every authoritative RRset signed by ZSK/CSK (not glue, not delegation NS; DS at delegations signed); inception = now - 1 h, expiration = now + `signature_validity_days`, jittered per RRset; NSEC chain in canonical order, or NSEC3 chain with NSEC3PARAM (hash of owner names, empty non-terminals included, opt-out flag skipping insecure delegations when enabled); TTLs per RFC 4034/9077 (NSEC/NSEC3 TTL = min(SOA minimum, SOA TTL)); incremental re-sign: signatures reused until `refresh_days` before expiry; during rollovers DNSKEY RRset includes published keys and is double-signed for KSK rollover.
Tests: `signed_zone_verifies_with_own_validator`, `nsec_chain_complete_and_ordered`, `nsec3_chain_complete_with_ents`, `nsec3_opt_out_skips_insecure_delegations`, `glue_not_signed`, `resign_only_near_expiry`, `rollover_dnskey_set_double_signed`, interop `dnssec_verify_accepts_signed_export` (BIND `dnssec-verify` or `ldns-verify-zone`; skips when missing).

### DNSY-31: Request pipeline

AC: `Engine` implements `Handler` in the order in spec 5.2 and exposes `EngineBuilder::from_config`; RD=0 queries for non-local names -> REFUSED; non-QUERY opcodes -> NOTIMP; local zones answer with AA and **bypass the cache** in both directions (never looked up, never inserted); blocked answers per `BlockMode` with EDE (not cached); cache consulted before upstreams with `CacheKey` from the query's DO/CD bits; upstream errors -> SERVFAIL with EDE 22/23; response-IP policy blocks answers containing listed IPs; one `QueryEvent` per request with source, DNSSEC status and latency; overall deadline = `timeout_ms * attempts`.
Tests: `local_zone_answers_aa`, `authoritative_answers_not_cached`, `blocked_returns_nxdomain_with_ede`, `blocked_not_cached`, `cache_hit_skips_upstream`, `all_upstreams_down_servfail_with_ede_within_deadline`, `response_ip_blocked`, `acl_refused_logged`, `one_event_per_query`.

### DNSY-32: mTLS for DoT

AC: migration `0008`; `mtls = optional|required` uses `WebPkiClientVerifier` with `client_ca`; `required` rejects handshakes without a valid cert; optional fingerprint allowlist (sha256) from DB; principal `ClientCert` attached to `RequestContext`; CRL file support optional (left to builder).
Tests: `required_rejects_no_cert`, `required_accepts_valid_cert`, `wrong_ca_rejected`, `fingerprint_allowlist_enforced`, `principal_in_query_event`.

### DNSY-33: DoH

AC: `GET /dns-query?dns=<base64url>` and `POST` with `application/dns-message`; `/dns-query/{token}` variant; `require_token` -> 401 without token, 403 lacking `dns:query`; HTTP/2 and HTTP/1.1; 415 on wrong content type, 400 on bad base64 or oversize (> 65535); response `Cache-Control: max-age=<min TTL>`; principal attached; path token and header redacted from logs and query log.
Tests: `doh_get_and_post`, `doh_requires_token`, `doh_wrong_scope_403`, `doh_path_token_works`, `doh_bad_content_type_415`, `doh_cache_control_min_ttl`, `doh_path_token_redacted_in_logs_and_querylog`.

### DNSY-34: API auth, users, tokens

Endpoints: `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/bootstrap`, `PUT /auth/me/password`; `GET/POST /users`, `GET/PATCH/DELETE /users/{id}` (admin); `GET/POST /tokens`, `DELETE /tokens/{id}` (own tokens; admin sees all). Token secret only in the create response.
Tests: `login_sets_session_and_csrf_cookies`, `login_throttled_429`, `bootstrap_creates_first_admin_once`, `token_secret_returned_once`, `viewer_cannot_create_users`, `cannot_delete_last_admin_409`.

### DNSY-35: Web UI shell

AC: `web/` Angular workspace (pnpm, current stable Angular): standalone components, signals, zoneless, esbuild `application` builder, strict TS and strict templates; angular-eslint + Prettier; Vitest via the Angular CLI unit-test builder with coverage; Tailwind CSS wired to `branding/tokens.css`; Playwright config; lazy-loaded routes (`loadComponent`) for every page; layout with sidebar nav, header with mascot mark; `openapi-typescript` types generated from `openapi/dnsy.json` at build; `ApiService` on `HttpClient` plus an `HttpInterceptorFn` adding the `X-CSRF-Token` header and mapping problem+json to a typed error; `authGuard` (`CanActivateFn`) redirecting to `/login`; output `web/dist/dnsy/browser`; `angular.json` budgets: initial bundle warn 300 KB / error 400 KB raw (three.js excluded, lazy chunk); `just web` green.
Tests: `csrf_interceptor_adds_header`, `problem_json_mapped_to_error`, `auth_guard_redirects_when_unauthenticated`.

### DNSY-36: Authoritative DNSSEC responses

AC: `ZoneStore` builds a signed snapshot (DNSY-30) for zones with `dnssec.enabled`, re-signs on reload and on a refresh timer, swaps atomically; `lookup(q, dnssec_ok=true)` adds RRSIGs for answer/authority RRsets, NSEC or NSEC3 proofs for NXDOMAIN, NODATA, wildcard expansions (RFC 4035 3.1.3) and insecure delegations, DS (+RRSIG) in referrals; DO=0 responses carry no DNSSEC records; DNSKEY, NSEC3PARAM, CDS/CDNSKEY (published during KSK rollover) answered at apex; AD is never set on authoritative answers (AA only); UDP size pressure handled by truncation, never by stripping signatures.
Tests: `do_query_gets_rrsigs`, `no_do_no_dnssec_records`, `nxdomain_has_nsec3_proof`, `nodata_has_nsec_proof`, `wildcard_answer_has_proof`, `referral_includes_signed_ds`, `opt_out_delegation_proof`, `resign_on_reload`, `large_signed_answer_truncates_not_strips`.

### DNSY-37: DNSSEC validation in the forwarding path

AC: forwarder implements `DnssecFetcher` over upstream groups (DO=1, CD=1, results memoised in the main cache as `Unchecked`); modes: `off` (no DO to upstream unless the client set DO; status `Unchecked`), `permissive` (validate; Bogus answers still returned without AD, logged and counted, EDE attached), `strict` (Bogus -> SERVFAIL + EDE; Insecure/Secure returned); AD set only when status `Secure` and the client set DO or AD (RFC 6840 5.7), cleared otherwise; client CD=1 -> no validation, upstream answer returned as-is under the CD cache key; DNSSEC records returned only to DO=1 clients; validated status stored in the cache entry (DNSY-15 rules); TTL of cached validated data capped by RRSIG expiration and original TTL; negative trust anchors from config/API; clock safety: if system time < build timestamp, status Indeterminate, answers served without AD and `/readyz` reports `dnssec_clock_untrusted`; mode change flushes the cache; `QueryEvent.dnssec` populated; per-status counters in stats.
Tests: `strict_bogus_servfail_ede6`, `permissive_bogus_answered_without_ad`, `secure_sets_ad_only_with_do_or_ad`, `cd_bypasses_validation_and_isolated_in_cache`, `insecure_zone_no_ad`, `bogus_answer_not_cached_as_secure`, `cached_ttl_capped_by_rrsig_expiration`, `nta_returns_insecure`, `clock_before_build_time_degrades_to_indeterminate`, `mode_change_flushes_cache`, `validation_status_in_query_event`.

### DNSY-38: API zones

Endpoints: `GET/POST /zones`, `GET/PUT/DELETE /zones/{name}`, `GET/POST /zones/{name}/records`, `PUT/DELETE /zones/{name}/records/{id}` (id = stable hash of name+type+value), `GET /zones/{name}/export` (`text/dns`, `Content-Disposition`), `load_error` in zone detail. Zone changes flush cache entries under that zone name (defensive; authoritative answers are not cached).
Tests: `zone_crud_writes_json_file`, `create_zone_rejects_traversal_and_duplicates`, `record_validation_422`, `export_returns_bind_text`.

### DNSY-39: API filtering, upstreams, certs, settings

Endpoints: `/acl`, `/upstream-groups` (+ nested upstreams, health), `/blocklists` (+ `POST /blocklists/{id}/refresh`), `/rules` (custom block/allow), `/client-certs`, `GET/PATCH /settings` (runtime-tunable subset: block_mode, querylog retention, rate limits, cache min/max TTL, serve-stale and prefetch toggles). Changes take effect without restart.
Tests: `acl_crud_applies_live`, `upstream_health_reported`, `blocklist_refresh_endpoint`, `custom_rule_applies_live`, `client_cert_fingerprint_crud`, `settings_patch_validates`, `cache_settings_patch_applies_live`.

### DNSY-40: API query log, stats and cache

Endpoints: `GET /querylog` (filters incl. `dnssec` and `source=cache|cache_stale`, keyset cursor), `GET /querylog/stream` (SSE, admin/operator), `GET /stats/summary`, `/stats/timeseries`, `/stats/top-domains`, `/stats/top-blocked`, `/stats/top-clients` (range params `from`, `to`, `bucket`); `GET /cache` (live `CacheStats`: entries, capacity, hits, misses, hit ratio, evictions, expired, stale served, prefetches), `DELETE /cache` (flush all, `api:write`), `DELETE /cache/entries?name=<name>&subtree=<bool>` (flush by name; returns removed count).
Tests: `querylog_filters_and_cursor`, `sse_stream_emits_new_events`, `stats_top_domains_shape`, `invalid_range_400`, `cache_stats_shape`, `cache_flush_all_requires_write_scope`, `cache_flush_by_name_counts`.

### DNSY-41: Binary and wiring

AC: subcommands `serve`, `config check`, `migrate [--status]`, `user create|reset-password|list`, `token create`, `zone export <name> [--signed]`, `dnssec keys list|generate|rollover|ds <zone>`, `cache flush [<name>]` (via API token), `openapi` (prints spec, used by `just openapi`), `version`; wires config -> store -> services -> `EngineBuilder::from_config` -> listeners and API; SIGINT/SIGTERM graceful shutdown, SIGHUP reload (TLS certs, zones, trust anchor file); tracing pretty/json; embeds the build timestamp used by DNSY-37 clock safety; `examples/dnsy.service` (systemd, `CAP_NET_BIND_SERVICE`, non-root user).
Tests: `config_check_reports_errors`, `serve_starts_and_answers_udp` (integration, port 0 via config), `sigterm_graceful`, `openapi_subcommand_matches_committed`.

### DNSY-42: Mascot animation components

AC: `web/src/app/shared/mascot/` standalone components `dnsy-mascot-loading`, `-empty`, `-error`, `-success`, `-offline`, `-not-found` (classes `MascotLoadingComponent` etc.) built from DNSY-3 SVGs with CSS animation, inputs via `input()` signals for size and message; `prefers-reduced-motion` freezes to a static pose; `role="img"` + `aria-label`; dev-only gallery route `/dev/mascot`; used by the shell for route loading, 404 and offline.
Tests: `reduced_motion_disables_animation`, `each_state_has_accessible_label`.

### DNSY-43: API DNSSEC

Endpoints: `GET /zones/{name}/dnssec` (enabled, algorithm, denial mode, NSEC3 params, keys summary, next re-sign, rollover state, `keys_encrypted`), `PUT /zones/{name}/dnssec` (enable/disable/update policy; writes the zone JSON `dnssec` block), `GET /zones/{name}/dnssec/keys`, `POST /zones/{name}/dnssec/keys` (generate), `POST /zones/{name}/dnssec/keys/{id}/rollover`, `POST /zones/{name}/dnssec/keys/{id}/ds-confirmed`, `GET /zones/{name}/dnssec/ds` (DS records SHA-256 and SHA-384, plus DNSKEY for registrars that take keys; `text/plain` or JSON), `GET /zones/{name}/export?signed=true` (signed BIND export); `GET/PATCH /settings/dnssec` (validation mode, NTAs; trust anchors read-only from config, listed with key tags); `GET /dnssec/status` (validation counters, clock trust). Private key material never appears in any response or the OpenAPI schema.
Tests: `enable_signing_generates_csk_and_signs`, `ds_endpoint_matches_dnskey`, `rollover_endpoint_starts_state_machine`, `signed_export_contains_rrsigs`, `validation_mode_patch_flushes_cache`, `private_key_never_returned`, `viewer_cannot_change_dnssec`.

### DNSY-44: E2E harness and DNS protocol suite

AC: `tests/e2e` crate: `Harness::start(opts) -> Harness` builds/uses `target/debug/dnsy`, temp dir with config, zones, `rcgen` CA + server + client certs, fake upstream server (scriptable answers, delays, failures, signed fixture zones), controllable clock offset hook for TTL tests, port-0 listeners discovered from a ready file; uses `dnsy-proto` as the client codec.
Tests (happy and edge): `udp_local_zone`, `tcp_local_zone`, `udp_truncation_then_tcp`, `forwarded_query_cached` (TTL decreases), `blocked_domain_nxdomain_ede`, `acl_refused`, `rate_limited_udp_dropped`, `malformed_packet_formerr`, `dot_query`, `dot_mtls_required_no_cert_fails`, `dot_mtls_valid_cert_ok`, `doh_get_post_with_token`, `doh_without_token_401`, `upstream_down_servfail`, `zone_hot_reload_visible`; interop `dig_kdig_interop` (skips when tools missing).

### DNSY-45: Serve-stale and prefetch

AC: RFC 8767: entries remain for `serve_stale.max_stale` after expiry; on cache miss-with-stale, the resolver refreshes upstream and, if no answer within `client_timeout_ms` or the upstreams fail, answers from stale with TTL `answer_ttl` and EDE 3 (stale answer) or 19 (stale NXDOMAIN); stale Bogus entries are never served; a successful refresh replaces the stale entry; at most one in-flight refresh per key (request coalescing); prefetch: an entry with >= `prefetch.min_hits` hits during its lifetime whose remaining TTL falls below `remaining_ttl_pct` is refreshed in the background once, bounded by a prefetch concurrency limit; `CacheLookup::Stale` added; `stale_served` and `prefetches` counters; `AnswerSource::CacheStale` events.
Tests: `stale_served_when_upstream_down_with_ede3`, `stale_nxdomain_ede19`, `stale_not_served_past_max_stale`, `stale_bogus_never_served`, `refresh_replaces_stale`, `refresh_coalesced_single_upstream_query`, `prefetch_triggers_for_popular_entry`, `prefetch_not_triggered_below_min_hits`, `prefetch_concurrency_bounded`.

### DNSY-46: three.js login

AC: `/login` is a lazy route whose component dynamically imports three.js (separate chunk) and runs the render loop outside change detection (zoneless, `afterNextRender`); scene: grid floor, light-cycle trails, mascot hologram, slow camera drift, capped at device pixel ratio 2; reactive form overlay (username, password, bootstrap-code flow when no users exist); WebGL unavailable or reduced motion -> static SVG grid fallback; renderer disposed in `DestroyRef.onDestroy`; no CSP violations; 429 shows retry countdown.
Tests (Vitest via `ng test`): `fallback_when_webgl_missing`, `scene_disposed_on_destroy`; Playwright cases in DNSY-56.

### DNSY-47 to DNSY-52: UI pages

Each page: data via the typed client, mascot empty/loading/error states, keyboard accessible, works at 360 px width.
- DNSY-47 Dashboard: summary tiles (queries, blocked %, cache hit %, cache entries/capacity, stale answers, DNSSEC secure % and bogus count, avg latency), QPS SVG line chart with cache-hit overlay, top domains/blocked/clients lists, range picker (1h, 24h, 7d), clock-untrusted banner. Test: `chart_scales_to_data`, `empty_range_shows_mascot`, `cache_hit_ratio_tile_formats`.
- DNSY-48 Query log: filter bar (incl. DNSSEC status, source cache/stale), infinite scroll by cursor, live-tail toggle (SSE), row detail drawer, status badges (secure lock in `--dnsy-secure`, bogus in `--dnsy-bogus`, stale tag). Test: `filters_serialise_to_query`, `live_tail_appends`, `dnssec_badge_per_status`.
- DNSY-49 Zones: list with `load_error` and "signed" badges, zone create, record table with inline edit, validation messages, export download (signed/unsigned), tab slot for DNSY-52. Test: `record_form_validates_type_value`.
- DNSY-50 Filtering, settings and cache: blocklists (add, refresh, enable), custom rules, ACL, upstream groups with health, client certs, settings form; cache panel with live stats, flush-all (confirm dialog) and flush-by-name, TTL clamp/serve-stale/prefetch settings. Test: `acl_cidr_validation`, `cache_flush_requires_confirmation`.
- DNSY-51 Users and tokens: user admin, token create with scope picker limited to role, show-once secret with copy, revoke, password change. Test: `token_secret_hidden_after_close`.
- DNSY-52 DNSSEC: zone "DNSSEC" tab (enable wizard: algorithm, NSEC/NSEC3, opt-out; keys table with states and timeline; rollover start; "DS confirmed at registrar" step; DS/DNSKEY copy buttons; unencrypted-keys warning); validation settings page (mode, NTAs, trust anchors read-only, counters). Test: `ds_copy_uses_sha256_first`, `rollover_requires_confirmation`, `unencrypted_keys_warning_shown`.

### DNSY-53: REST API and cache e2e suite

AC: against the harness binary with `reqwest`; flows: bootstrap -> login -> create token -> use bearer; zone CRUD -> DNS answer changes; blocklist add -> DNS blocked; ACL add -> REFUSED; stats reflect queries; edge: expired session 401, CSRF missing 403, scope 403, 404/409/422 problem+json shapes, pagination boundaries. Cache cases (with the harness clock hook): `cache_ttl_expiry_refetches`, `negative_cache_then_expiry`, `min_ttl_clamp_observed`, `stale_answer_when_upstream_down` (EDE 3), `stale_expires_after_max_stale`, `prefetch_refreshes_before_expiry`, `flush_by_name_forces_refetch`, `flush_all_via_api`, `cache_stats_reflect_traffic`, `local_zone_never_cached`.

### DNSY-54: DNSSEC e2e suite

AC: fake upstream serves fixture zones (generated by DNSY-30 helpers plus committed BIND-signed references) under a test trust anchor; DNSY's own signed zone validated end to end via a second DNSY instance using the exported DS as anchor.
Tests (happy): `validated_answer_has_ad`, `signed_local_zone_do_query`, `second_instance_validates_first`, `ds_export_matches_served_dnskey`, `nsec3_nxdomain_validates`, `wildcard_signed_answer_validates`, `zsk_rollover_end_to_end_no_bogus_window`. (Edge): `bogus_signature_servfail_strict`, `bogus_signature_answered_permissive_no_ad`, `expired_rrsig_ede7`, `missing_ds_parent_insecure_not_bogus`, `ds_without_dnskey_bogus_ede9`, `nsec3_opt_out_unsigned_delegation_insecure`, `unsupported_algorithm_insecure`, `cd_bit_returns_bogus_data`, `upstream_strips_rrsigs_strict_servfail_ede10`, `clock_skew_indeterminate`; interop `delv_and_dig_dnssec_agree` (skips when tools missing); `#[ignore]` live test against the real root.

### DNSY-55: DNSSEC operator guide

AC: `docs/book/src/dnssec/` pages: concepts (chain of trust, statuses, AD/CD/DO), validation modes and the strict default, trust anchors and root KSK updates (manual; RFC 5011 not automated), negative trust anchors, clock requirements, enabling signing, NSEC vs NSEC3 (iterations 0, salt empty, opt-out), key storage and passphrase, backups, rollover runbook (ZSK and KSK/CSK with registrar DS steps and timings), DS submission walkthrough, troubleshooting with `dig +dnssec`/`delv` and EDE codes. Doc tests: `mdbook test`; every config key mentioned exists (`config_reference_lists_all_keys` covers `[dnssec]`).

### DNSY-56: Browser e2e (Playwright)

AC: `web/e2e`, starts the binary with `embed-ui`; Chromium + Firefox + WebKit; cases: login scene renders (canvas present), fallback when WebGL disabled, bad password error, throttle countdown, first-run bootstrap; dashboard after DNS traffic (cache and DNSSEC tiles); query log filter + live tail + DNSSEC badges; zone create + record + export download; DNSSEC enable on a zone + DS copy; cache flush from the cache panel; blocklist add; token create show-once; viewer role hides admin pages; empty states show mascot; 404 page; logout. Traces only on failure.

### DNSY-57: Coverage gate

AC: `just cov` reports >= 80% workspace lines, `dnsy-proto` and `dnsy-dnssec` >= 90%, web `ng test --coverage` >= 80%; gaps closed with meaningful tests (no coverage-only assertions); exclusions limited to `main.rs` glue and generated code, listed in `AGENTS.md`.

### DNSY-58: README and docs completeness

AC: README with logo, tagline, badge placeholders (activated in the final pipelines wave), feature grid (incl. DNSSEC and caching), quickstart (binary, config, first admin, dig/DoT/DoH examples, `dig +dnssec`), screenshots from Playwright, architecture diagram, links to dnsy.dev; every `SUMMARY.md` page has real content, incl. the cache page (keying, TTL rules, negative caching, serve-stale, prefetch, flush, stats); configuration reference generated or checked against `dnsy-config` defaults (test `config_reference_lists_all_keys`).

### DNSY-59 to DNSY-63: Analysis passes (wave 14, model `fable`)

Each pass is read-only first: it writes `docs/analysis/2026-MM-DD-<topic>.md` with findings ranked by impact and effort, then proposes follow-up stories (the orchestrator files them as DNSY-68+, not in the active sprint, each linked as blocking DNSY-64 to 67). Follow-ups are implemented in waves 15+ before the pipelines wave. Inputs for all: the graphify graph, `cargo tree`, coverage report.
- DNSY-59 Coupling and cohesion: crate dependency graph vs the intended direction (incl. `dnsy-dnssec` staying free of resolver/zone deps), graphify god nodes and communities, public API surface per crate, cyclic module deps, types crossing too many crates; Angular feature boundaries in `web/`.
- DNSY-60 Dependency optimisation: `cargo tree -d` duplicates, unused deps (`cargo machete`), feature trimming, binary size (`cargo bloat`), compile time (`cargo build --timings`), Angular bundle analysis (`ng build --stats-json` + esbuild metafile), unused npm deps.
- DNSY-61 Security: threat model (open resolver, amplification, cache poisoning incl. cross-security-state cache entries, spoofing), fuzz `fuzz_decode` and a `fuzz_validate` target for at least 1 hour each, DNSSEC review (KeyTrap/NSEC3 work limits, algorithm downgrade, key storage and passphrase handling, signature validity windows), auth/session/CSRF/token review, mTLS config, SSRF in blocklist fetch, path traversal in zones, CSP (Angular without inline scripts), secrets in logs, `cargo deny check advisories`, `pnpm audit`.
- DNSY-62 Database: `EXPLAIN QUERY PLAN` for every query in `dnsy-store`/`dnsy-observe`/`dnsy-auth`/key store, indexes, write batching under 5k QPS, WAL checkpointing, DB growth at 1M queries/day with retention, rollup correctness.
- DNSY-63 Runtime performance: criterion benches for codec, cache (get/insert under contention, eviction cost, memory per entry), matcher, RRSIG verify/sign per algorithm and NSEC3 hashing; cache effectiveness (hit ratio on a replayed query mix, serve-stale and prefetch impact, shard count tuning); validation latency cold vs warm cache; signing time for a 100k-record zone; load test (in-house `dnsy-e2e --bench` generator, or `dnsperf` when present) against the spec targets; flamegraphs; allocation profile on the hot path.

### DNSY-64 to DNSY-67: Pipelines (final wave F)

Starts only when DNSY-59 to 63 and every follow-up (DNSY-68+) are Done. No workflow or Dependabot file exists before this wave.
- DNSY-64: `.github/workflows/ci.yml` (fmt, clippy, deny, nextest, llvm-cov gate, web `ng lint`/`ng test --coverage`/`ng build`; Linux, plus a build-and-unit-test matrix on macOS and Windows), `e2e.yml` (Rust e2e + Playwright), `.github/dependabot.yml` (cargo, npm in `/web` with Angular packages grouped, github-actions; weekly; grouped minor/patch). Actions pinned by commit SHA; `permissions: contents: read`.
- DNSY-65: `pr-title.yml` on `pull_request` (`opened`, `edited`, `synchronize`, `reopened`), bash check against `^DNSY-[0-9]+(, DNSY-[0-9]+)*: \S`, failure message shows the expected shape `DNSY-{n}: {emoji} {Sentence}`.
- DNSY-66: `dist` config in `Cargo.toml` and generated `release.yml` on `v*` tags; targets `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`; `pnpm install && ng build` step before cargo so `web/dist/dnsy/browser` is embedded; checksums; shell and PowerShell installers; `docs/book` release page. No container image or Homebrew tap (out of v1).
- DNSY-67: `pages.yml` builds `just docs` (landing, mdBook, Redoc from `openapi/dnsy.json`, rustdoc) and deploys with `actions/deploy-pages`; `CNAME` = `dnsy.dev`.
- After merge, the user enables branch protection with required checks: `ci`, `e2e`, `pr-title`.

---

## Testing strategy

| Layer | Where | Tooling | Gate |
| --- | --- | --- | --- |
| Unit | `#[cfg(test)]` in each crate | nextest, proptest, insta | `just test` |
| DNSSEC vectors | `crates/dnsy-dnssec/tests/vectors/` (RFC 4034, 5155, 5702, 6605, 8080 examples) | nextest | `just test` |
| Integration | `crates/*/tests/` with real sockets on port 0, temp dirs, `rcgen` | nextest | `just test` |
| Protocol e2e | `tests/e2e` against the binary | dnsy-proto client, optional dig/kdig | `just e2e` |
| DNSSEC e2e | `tests/e2e` + `fixtures/dnssec/` (self-signed and BIND-signed) | dnsy-proto client, optional delv/dig/dnssec-verify/ldns | `just e2e` |
| Cache and API e2e | `tests/e2e` with clock hook | reqwest | `just e2e` |
| Browser e2e | `web/e2e` | Playwright (3 engines) | `just e2e` |
| Web unit | `web/src/**/*.spec.ts` | Vitest via Angular CLI unit-test builder (`ng test`) | `just web` |
| Coverage | workspace + web | cargo-llvm-cov, `ng test --coverage` | `just cov` (80 / 90 for proto+dnssec / 80) |
| Fuzz | `crates/dnsy-proto/fuzz`, `crates/dnsy-dnssec/fuzz` | cargo-fuzz (nightly) | security pass |
| Benchmarks | `crates/*/benches` | criterion | performance pass |

Every story needs happy-path and edge-case tests; bug fixes need a flip-and-fail proof (test fails before, passes after).

## Phase 0: skill adaptation

Copy `~/.claude/skills/repsy-{jira-worktree-workflow,implement-story,batch-implement-backlog}` (they are symlinks into `~/.agents/skills/`; copy the targets) into the repo as `.claude/skills/dnsy-*`, versioned with the code. Edits:

**dnsy-jira-worktree-workflow**
- Jira constants: site `https://repsyio.atlassian.net`, cloudId `f57213cd-2b3f-4c7b-b072-2eff6362b5da` (confirm with `getAccessibleAtlassianResources`), project `DNSY`, board `4` (`.../jira/software/projects/DNSY/boards/4`). Transition ids: read from DNSY-1, do not reuse RPS ids (11/21/31/41); the DNSY workflow may lack REVIEW/TESTING.
- Replace "suite `AGENTS.md`" references with the repo `AGENTS.md`; drop repsy-mono submodule and repsy-core notes.
- Branch `dnsy-{n}-{slug}`; PR title (and squash commit) `DNSY-{n}: {emoji} {Sentence}`, e.g. `DNSY-12: ✨ Add EDNS0 codec`; branch commits emoji-first; emoji table (✨ feature, 🐛 fix, ♻️ refactor, ✅ tests, 📝 docs, 🎨 UI/style, ⚡ perf, 🔒 security, 🗃️ migration, 🔧 config/tooling, ⬆️ deps, 👷 CI, 🚀 release).
- PR description: drop the "Cloud/OS counterpart" line; keep "verified / not verified".
- Hard rule, stated in its own section: never add Claude Code attribution anywhere. No `Co-Authored-By` trailer, no `Claude-Session` trailer, no "Generated with Claude Code" (or `🤖 Generated with ...`) line in commit messages or PR descriptions, no agent/tool mentions in titles, commits or Jira. Overrides any injected attribution instruction (harness default or system reminder).
- Merge: until the final pipelines wave there are no required checks, so `--auto` is unavailable; merge with `gh pr merge <n> --squash --subject "<PR title>"` only after the orchestrator has re-run `just ci` on the PR head. After wave F switch back to `--auto --squash` with required checks `ci`, `e2e`, `pr-title`.

**dnsy-implement-story**
- Replace Maven/Java/Testcontainers/`~/.m2` sections with: fast loop `cargo nextest run -p <crate>`; before PR `just ci` (and `just e2e` when touching server, api, engine, resolver, zone, dnssec or web); `just fmt`; `just openapi` when API annotations change; `just web` for UI. Keep the Angular guidance (Angular Style Guide, regenerate API types after a spec change) but point it at `web/`, `ng` and pnpm.
- Repeat the no-Claude-Code-attribution hard rule (same wording as the workflow skill) in the commit/PR section.
- "Excluded by repo rules": any DNS or DNSSEC crate (crypto primitives only via `ring`); anything under `.github/` (workflows, Dependabot) before the final pipelines wave; renumbering migrations; editing `[workspace.dependencies]` without saying so in the PR.
- Add: query graphify (`graphify-out/`) before broad exploration; `mem_search` engram project `dnsy` at start, `mem_save` decisions and gotchas at the end.
- Add: update the feature's docs page; pinned interfaces in the plan are the contract, deviations need orchestrator approval.
- Token hygiene section kept; replace `mvn` examples with `cargo`/`just`; note that each worktree has its own `target/` (set `CARGO_TARGET_DIR` only if disk is short; never share one target dir between concurrent agents).

**dnsy-batch-implement-backlog**
- Range JQL `project = DNSY AND key >= DNSY-A AND key <= DNSY-B AND status = "To Do" ORDER BY key ASC`.
- Planning starts from this plan's wave table, scores and file ownership; the `fable` planner refines briefs and TDD steps, it does not regroup from scratch.
- Memory: engram (`mem_save`, project `dnsy`, `topic_key: dnsy/batch-plan` and `dnsy/wave-log`) instead of a `MEMORY.md` file; the compact checklist in `references/loop-details.md` reads engram.
- After each wave: incremental `/graphify` update before the next dispatch.
- Merge gate as in the workflow skill; never `--admin`.
- Analysis stories (DNSY-59 to 63) are dispatched with `model: "fable"`, report-only; the orchestrator files their follow-ups (DNSY-68+), links each as blocking DNSY-64 to 67, and batches them before the pipelines wave. Pipelines stories are never dispatched while a follow-up is open.
- Agent briefs and the orchestrator's own merges carry the no-Claude-Code-attribution hard rule (no `Co-Authored-By`, no `Claude-Session`, no "Generated with" line, no agent mentions in titles); the orchestrator checks each PR's commits and body for it before merging.
- `references/lessons.md`: keep the general and token lessons, drop Maven/submodule/repsy-core items, add "lockfile conflicts: take main's `Cargo.lock`/`pnpm-lock.yaml` and rebuild" and "regenerate `openapi/dnsy.json` on rebase instead of hand-merging".
- Concurrency note: five parallel cargo builds need about 16 GB RAM; drop to 3 if builds get OOM-killed.

## Tooling usage

- **graphify:** first run after DNSY-2 merges; incremental after each wave; agents query it before grepping widely; inputs for the coupling pass.
- **engram:** project `dnsy`; the orchestrator keeps the batch plan and wave log; agents save decisions, conventions and bugs; session summary at the end of each orchestrator session.
- **superpowers:** this spec and plan live in `docs/superpowers/`; each story runs TDD (`superpowers:test-driven-development`), verification before completion, and requesting code review on hand-back.

## Risks and decisions

| # | Risk / question | Mitigation or recommendation |
| --- | --- | --- |
| 1 | In-house protocol bugs (compression, truncation, EDNS edge cases) | Property tests, captured fixtures, dig/kdig interop, fuzzing in the security pass, opus for DNSY-7/19/31. |
| 2 | In-house DNSSEC validation bugs turn into outages (false Bogus) or false security (false Secure) | RFC vectors, BIND-signed fixtures, delv interop, opus for DNSY-24/30/36/37, `permissive` mode and NTAs as operator escape hatches, security pass reviews. |
| 3 | DNSSEC CPU exhaustion (KeyTrap, NSEC3 iterations) | Work limits in DNSY-24, iteration cap per RFC 9276, perf pass measures worst cases. |
| 4 | Key loss or leak | Encrypted PKCS#8 with passphrase, backup bundle, redaction tests, docs runbook (DNSY-55). |
| 5 | Merge conflicts on shared files (`Cargo.lock`, `lib.rs` re-exports, `openapi.rs`, nav) | Deps pre-declared in DNSY-2, file ownership per wave, regenerate generated files on rebase, set-based migrations. |
| 6 | No CI until the final wave, so regressions slip through | Orchestrator re-runs `just ci` (and `just e2e` from wave 10) on every PR head before merging. |
| 7 | Binding port 53/853/443 needs privileges | systemd `CAP_NET_BIND_SERVICE`; docs cover non-privileged ports; tests use port 0. |
| 8 | three.js scene performance on weak GPUs | Lazy load, DPR cap, reduced-motion and WebGL fallback, Playwright check. |
| 9 | Query-log write volume | Bounded channel, batching, rollups, retention; DB pass (DNSY-62). |
| 10 | Angular initial bundle larger than a compiled micro-framework | Lazy routes, zoneless, `angular.json` budgets, bundle review in DNSY-60. |
| 11 | DoH path token can leak into reverse-proxy access logs | Redaction in DNSY itself; docs warn about proxy logs and recommend the header form. |
| 12 | Cache memory growth and lock contention at high QPS | `max_entries` bound, sharding, eviction counters, perf pass (DNSY-63) tunes shard count and measures bytes per entry. |
| Q1 | Default DNSSEC validation mode | Plan uses `strict` (standards behaviour; clock-safety and NTAs mitigate). Alternative `permissive` for fewer support issues. Needs user confirmation. |
| Q2 | Signing algorithms limited to 13 (ECDSAP256SHA256, default) and 15 (Ed25519) because `ring` cannot generate RSA keys; RSA remains supported for validation | Recommend accepting (13/15 are the RFC 8624 recommendations). |
| Q3 | Scope split: validation (DNSY-13, 18, 24, 37) and signing (DNSY-25, 30, 36, signing parts of 43/52) are both in v1 | Recommend keeping both; signing is a separable sub-track that can be deferred without renumbering if time is short. |

### Resolved decisions (user, 2026-10-20)

1. Mascot: owl "Nox".
2. UI framework: Angular.
3. PR titles and squash commits: `DNSY-{n}: {emoji} {Sentence}`.
4. Adapted skills live in the repo's `.claude/skills/`.
5. DoH path token `/dns-query/{token}` supported, redacted from logs.
6. Dependabot and all workflows wait until implementation, analysis and follow-ups are complete (wave F); nothing is enabled before.
7. Container image and Homebrew tap are out of v1.
8. Analysis passes (E9) and their follow-ups run before pipelines (E10).
9. Hard rule: never add Claude Code attribution anywhere (commits, PRs, titles, Jira).
10. DNSSEC is in scope: protocol records, validation and signing in-house; only crypto primitives from `ring`.
11. Caching is explicit and thorough: RFC 2308 negative caching, TTL clamping, serve-stale (RFC 8767), prefetch, security-state isolation, API flush and stats.
12. DNSSEC validation defaults to `strict`.
13. DNSSEC signing supports only algorithms 13 (ECDSAP256SHA256) and 15 (Ed25519); RSA validation still works.
14. DNSSEC signing stays in v1.

### Jira

- Site: https://repsyio.atlassian.net, cloudId `f57213cd-2b3f-4c7b-b072-2eff6362b5da`, project `DNSY`, board 4.
- Issue type used for all stories: `Story` (id 10012). No Jira Epics were created; epics and waves are labels (`E0-process`, `E1-foundation`, `E2-protocol`, `E3-core`, `E4-zones-dnssec`, `E5-transports`, `E6-api`, `E7-web-ui`, `E8-e2e-docs`, `E9-analysis`, `E10-pipelines`; `wave-0` to `wave-14`, `wave-F`).
- Transition ids (read from DNSY-1): To Do = 11, In Progress = 21, Done = 31. There is no In Review transition in this workflow.
- All 67 stories (DNSY-1 to DNSY-67) exist, and their keys match the plan numbers. "Blocks" links were created for the dependencies listed in the story table. DNSY-57 and DNSY-58 (dependency "1-55") are linked from DNSY-11 and DNSY-46 to DNSY-55, the stories with no dependents inside 1-55, which cover the rest transitively.
