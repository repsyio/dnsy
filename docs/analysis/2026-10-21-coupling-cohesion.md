# Coupling and cohesion analysis (DNSY-59)

- **Date:** 2026-10-21, against `main` at `237751b` (DNSY-1..58, 69, 70 merged)
- **Kind:** read-only pass; no product code changed
- **Inputs:** `cargo metadata` (internal edges incl. dev-deps), `cargo clippy -W clippy::cognitive-complexity`, `tokei`, grep over `crates/`, `tests/e2e/`, `web/src/app/`, the design spec (5.2) and plan ("Dependency direction", "Pinned cross-crate interfaces"), the DNSY-68 comment thread. `graphify-out/` does not exist in the checkout, so the crate graph below is the real Cargo graph rather than the knowledge-graph view.
- **Effort scale:** S = under a day, M = 1-3 days, L = about a week.

## 1. Summary

| # | Finding | Severity | Effort | Before 1.0 |
| --- | --- | --- | --- | --- |
| F1 | `Engine` doubles as service locator; `EngineBuilder::from_config` builds services the API also needs and the binary pulls them back out of the engine | high | M | yes |
| F2 | `ApiState` sprawl: 24 public fields, 7 `Option`s that turn into 503s, 12 `with_*` setters, four different seam styles for "talk to the engine" | high | M | yes |
| F3 | `dnsy-config` TOML enums (`Validation`, `BlockMode`, `TrustAnchor`) leak into runtime APIs of resolver, engine and api; `resolver` and `zone` depend on `config` although the design says they do not | medium | M | yes |
| F4 | `crates/dnsy-zone/src/keystore.rs` is a 1945-line god file mixing passphrase handling, argon2/AES-GCM at rest, SQLite rows, the rollover state machine and bundle import/export; the key *model* lives in `dnsy-dnssec`, the key *store* in `dnsy-zone` | medium | L | no (first nice-to-have) |
| F5 | Three incompatible `Clock` traits plus five ad-hoc `unix_now()`/`now()` functions and a fourth closure-based clock in the engine | medium | M | no |
| F6 | Three per-client failure counters (filter `RateLimiter`, DoH `Throttle`, auth `login_attempts`) with three keying policies; only one groups IPv6 by /64 | medium | M | yes (overlaps DNSY-68) |
| F7 | Zone record editing (serial bump, record splice, `If-Match`) is implemented in `dnsy-api` on `serde_json::Value`, guarded by a `Mutex<()>` in `ApiState`, instead of in `dnsy-zone` | medium | M | yes |
| F8 | `dnsy-filter` bundles seven concerns (parse, match, HTTP fetch, scheduler, SQLite sources/rules, ACL, rate limit, block response) and pulls reqwest, rustls, rusqlite and axum into one crate | medium | L | no |
| F9 | API constructs resolver internals (`GroupSet::new(specs, SystemClock, ThreadRng)`) duplicating `EngineBuilder`; `Engine<E = UpstreamClient>` concrete type fixed into `ApiState` | low | S | no |
| F10 | `dnsy-server` reaches sideways into `dnsy-auth` (`ClientCertService`) and `dnsy-store` (`StoreError`) for the mTLS allowlist refresh, while DoH already uses a trait seam | low | S | no |
| F11 | Duplicated helpers: four `hex()` encoders, DS export in both CLI and API, `BlockMode` spelled three times | low | S | no |
| F12 | `dnsy-api` carries 5386 lines of tests inside `src/` (45% of the crate) and two 1.1-1.5k-line route files | low | M | no |
| F13 | Web: the generic `Dialog`/`ConfirmDialog` live in `features/zones/` and are imported by eight other features; `admin-shared/` sits under `features/`; `shared/` holds only the mascot | low | S | no |
| F14 | `crates/dnsy/src/serve.rs`: the only two functions over clippy's cognitive-complexity threshold (`reload` 51/25, `serve` 42/25) | low | S | no |

Already good (section 7): `dnsy-proto` and `dnsy-dnssec` honour the zero/limited dependency rule exactly; no cycles; `dnsy-core` is 77 lines of vocabulary; the pipeline is one function with named steps; complexity is low everywhere except `serve.rs`; the Angular app has a clean `core/` HTTP layer and type-aliases the generated schema per feature.

## 2. Crate dependency graph

### 2.1 Actual internal edges (`cargo metadata`, normal deps; dev-deps listed separately)

```
dnsy          -> api auth config core dnssec engine filter observe proto server store zone   (dev: config proto resolver)
dnsy-api      -> auth config core dnssec engine filter observe proto resolver store zone
dnsy-server   -> auth core engine proto store                                           (dev: auth core proto)
dnsy-engine   -> config core dnssec filter observe proto resolver store zone
dnsy-zone     -> config core dnssec proto store                                         (dev: core)
dnsy-resolver -> config core dnssec proto store
dnsy-filter   -> core proto store
dnsy-observe  -> core proto store
dnsy-auth     -> core store
dnsy-dnssec   -> core proto          (external: ring, zeroize only)
dnsy-config   -> (none)
dnsy-store    -> (none)
dnsy-proto    -> (none)              (external: none)
dnsy-core     -> (none)
dnsy-e2e      -> core dnssec proto
```

No cycles (Cargo forbids them, and no `dev-dependency` closes a loop either).

### 2.2 Fan-in / fan-out (internal crates only)

| Crate | Fan-out | Fan-in (who depends on it) | Design says |
| --- | --- | --- | --- |
| dnsy-core | 0 | 12 | `core <- everything` |
| dnsy-proto | 0 | 10 | `proto <- dnssec zone resolver filter observe engine server` (+ api, dnsy, e2e: fine) |
| dnsy-store | 0 | 8 | `store <- auth observe filter resolver zone` |
| dnsy-config | 0 | 6 (api engine resolver zone dnsy, dev: dnsy) | only the binary and `EngineBuilder::from_config` were meant to read it |
| dnsy-dnssec | 2 | 5 (zone resolver engine api e2e) | `dnssec <- zone resolver` |
| dnsy-auth | 2 | 3 (api server dnsy) | api and binary |
| dnsy-observe | 3 | 3 (engine api dnsy) | engine, api |
| dnsy-filter | 3 | 3 (engine api dnsy) | engine, api |
| dnsy-zone | 5 | 3 (engine api dnsy) | engine, api |
| dnsy-resolver | 5 | 3 (engine api dnsy) | engine, api |
| dnsy-engine | 9 | 3 (server api dnsy) | `engine <- server`; api was to use "services only" |
| dnsy-server | 5 | 1 (dnsy) | |
| dnsy-api | 11 | 1 (dnsy) | |
| dnsy | 12 | 0 | `dnsy -> all` |

### 2.3 Deviations from the declared direction

| Edge | Evidence | Verdict |
| --- | --- | --- |
| `resolver -> config` | `crates/dnsy-resolver/src/forward.rs:17,40,79` (`DnssecPolicy::from_config(&dnsy_config::Dnssec)`, `Anchor(#[from] dnsy_config::ConfigError)`); `crates/dnsy-resolver/src/cache/mod.rs:13` (`Cache::new(&dnsy_config::Cache)`) | undeclared; see F3 |
| `zone -> config` | `crates/dnsy-zone/src/keystore.rs:132` (`dnsy_config::PASSPHRASE_ENV`) | undeclared, one constant; see F3 |
| `engine -> store` | `crates/dnsy-engine/src/builder.rs:19,110` (`from_config(&Config, &Store)`) | consequence of F1; the plan pinned `EngineBuilder::from_config` so this is by contract, but it is why the engine ends up owning stores |
| `engine -> config` (14 use sites) | `builder.rs:7,51-57,294`, `engine.rs:23,329` (`dnsy_config::Validation` is the engine's runtime mode type) | see F3 |
| `server -> auth`, `server -> store` | `crates/dnsy-server/src/dot/mtls.rs:16,76`; `doh/mod.rs:23` | `TokenVerifier` (trait) is a fine seam; `ClientCertService` + `StoreError` are concrete; see F10 |
| `api -> engine` | `crates/dnsy-api/src/state.rs:11,56` (`pub engine: Option<Arc<Engine>>`), `validation.rs:6,43`, routes `acl.rs`, `settings.rs`, `live.rs`, `upstreams.rs`, `blocklists.rs` | the design wanted api to depend on services only; it depends on the concrete `Engine<UpstreamClient>`; see F1/F2 |
| `api -> resolver` (14 sites), `api -> dnssec`, `api -> proto` | `state.rs:13-14`, `routes/live.rs:7`, `routes/upstreams.rs:11-12`, `routes/dnssec.rs:18` | acceptable as "services"; `live.rs:75` constructs resolver internals, see F9 |

What the design pinned and is honoured: `dnsy-proto` has zero external dependencies; `dnsy-dnssec` depends only on `core`, `proto`, `ring`, `zeroize` (`crates/dnsy-dnssec/Cargo.toml`); `api` never depends on `server` (the binary passes a `CertReload` closure instead, `state.rs:22-26`); `dnsy-store` has no internal deps.

## 3. Size, complexity, surface

### 3.1 Production vs test lines per crate

Files named `*test*`, files under `tests/`, and everything after the first `#[cfg(test)]` count as test.

| Crate | Prod | Test | Test/prod | Files in `src/` | `pub fn` | `pub struct` | `pub enum` | `pub trait` | `pub use` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| dnsy-api | 6573 | 5386 | 0.81 | 30 | 42 | 101 | 12 | 2 | 2 |
| dnsy-zone | 2961 | 3301 | 1.11 | 10 | 50 | 11 | 5 | 0 | 8 |
| dnsy-proto | 2715 | 2396 | 0.88 | 22 | 62 | 17 | 9 | 0 | 14 |
| dnsy-dnssec | 2577 | 4311 | 1.67 | 18 | 56 | 18 | 7 | 2 | 10 |
| dnsy-filter | 2124 | 1382 | 0.65 | 13 | 43 | 18 | 14 | 1 | 9 |
| dnsy-server | 1747 | 1794 | 1.02 | 10 | 18 | 8 | 2 | 1 | 4 |
| dnsy | 1534 | 1245 | 0.81 | 8 | 5 | 3 | 10 | 0 | 0 |
| dnsy-engine | 1447 | 1961 | 1.35 | 8 | 38 | 5 | 1 | 1 | 4 |
| dnsy-auth | 1290 | 624 | 0.48 | 8 | 30 | 9 | 2 | 1 | 6 |
| dnsy-resolver | 1223 | 3221 | 2.63 | 14 | 41 | 17 | 8 | 3 | 6 |
| dnsy-observe | 811 | 500 | 0.61 | 7 | 15 | 12 | 3 | 1 | 5 |
| dnsy-config | 719 | 288 | 0.40 | 3 | 5 | 17 | 6 | 0 | 2 |
| dnsy-store | 358 | 229 | 0.63 | 3 | 6 | 3 | 1 | 0 | 2 |
| dnsy-core | 77 | 57 | 0.74 | 1 | 1 | 2 | 5 | 0 | 0 |
| tests/e2e | 0 | 9856 | | | | | | | |

`pub struct = 101` in `dnsy-api` is the utoipa request/response DTO set (50 paths in `openapi/dnsy.json`), which is expected. Re-export sprawl is absent: every `lib.rs` re-exports a curated list; the only cross-crate re-export is `dnsy_zone::SignedZone` (`crates/dnsy-zone/src/lib.rs:12`), which is intentional (the API and CLI never import `dnsy-dnssec` to export a zone).

### 3.2 Largest non-test files

| File | Lines | Prod lines | Note |
| --- | ---: | ---: | --- |
| `crates/dnsy-zone/src/keystore.rs` | 1945 | 1115 | F4 |
| `crates/dnsy-api/src/routes/zones.rs` | 1482 | 811 | F7, F12 |
| `crates/dnsy-api/src/routes/dnssec.rs` | 1141 | 1138 | 13 handlers; its tests are a separate 1374-line file |
| `crates/dnsy-engine/src/engine.rs` | 814 | 814 | the pipeline; tests live in `tests.rs` |
| `crates/dnsy-zone/src/export.rs` | 671 | 671 | BIND export |
| `crates/dnsy-auth/src/users.rs` | 591 | 390 | |
| `crates/dnsy-api/src/routes/querylog.rs` | 557 | | |
| `crates/dnsy-zone/src/store.rs` | 520 | | |
| `crates/dnsy/src/admin.rs` | 519 | 500 | CLI subcommands |

### 3.3 Longest functions (non-test) and complexity

| Function | Lines | Cognitive complexity |
| --- | ---: | ---: |
| `tests/e2e/src/dnssec.rs:361 build_zone` | 145 | (test harness) |
| `crates/dnsy/src/serve.rs:50 serve` | 104 | 42 (threshold 25) |
| `crates/dnsy-zone/src/lookup.rs:290 resolve_unsigned` | 104 | under threshold |
| `crates/dnsy-engine/src/engine.rs:366 pipeline` | 102 | under threshold |
| `crates/dnsy-dnssec/src/sign/mod.rs:269 sign_zone` | 93 | under threshold |
| `crates/dnsy-zone/src/export.rs:114 rdata` | 91 | under threshold (one `match` per RR type) |
| `crates/dnsy-proto/src/rdata/mod.rs:132 decode` | 91 | under threshold (one `match` per RR type) |
| `crates/dnsy-dnssec/src/validate/chain.rs:257 child_trust` | 91 | under threshold |
| `crates/dnsy/src/serve.rs:280 reload` | 35 | 51 |
| `crates/dnsy-filter/src/manager.rs:173 tick` | | 31 |

`cargo clippy --workspace -W clippy::cognitive-complexity -W clippy::too-many-lines` reports exactly three functions over 25 (the three above) and no `too_many_lines` beyond the one `#[expect]` on a test table (`crates/dnsy-proto/src/message_tests.rs:351`). The pedantic gate with `allow_attributes = "deny"` has kept function size in check: the whole workspace carries only seven `#[expect(clippy::...)]` attributes.

## 4. Findings

### F1. `Engine` is a service locator; `EngineBuilder::from_config` owns what the API needs (high, M)

Evidence:

- `crates/dnsy-engine/src/builder.rs:110-180`: `from_config` creates `RuleStore`, `SourceStore`, `ListManager`, `ZoneStore`, `KeyStore`, `ZoneSigning`, `GroupStore`/`GroupSet`, `QueryLogWriter` and stores them in the engine.
- `crates/dnsy-engine/src/engine.rs:86-121`: `Engine` has 22 fields; `engine.rs:220-260` exposes `cache()`, `zone_store()`, `zone_signing()`, `groups()`, `list_manager()` as accessors, plus seven `set_*` mutators and six DNSSEC mode/anchor methods.
- `crates/dnsy/src/serve.rs:52-80, 157-190`: the binary builds the engine, then reads `engine.list_manager()`, `engine.zone_store()`, `engine.zone_signing()`, `engine.cache()`, `engine.dnssec_clock_flag()` back out to spawn background tasks and to fill `ApiState`.
- `crates/dnsy-api/src/state.rs:56`: the API keeps `Option<Arc<Engine>>` *and* separate handles to `ZoneStore`, `Cache`, `ZoneSigning`, `GroupStore`, `RuleStore`, `SourceStore` that the engine also holds, so two owners of each service exist.

Why it matters: the request pipeline (a `Handler`) and the lifecycle of persistent services are one type. Every new service (DNSY-70 added the rollover timer) grows `Engine`, `EngineBuilder`, `serve.rs` and `ApiState` together. Tests of the API need a real `UpstreamClient` to get an `Engine` (`crates/dnsy-api/src/tests_policy.rs:71-73`).

Recommendation: introduce a `Services` (or `Runtime`) struct in a small wiring layer (either the binary or a new `dnsy-runtime` crate between engine and api): `Services::open(&Config, &Store)` builds store-backed services once (`ZoneStore`, `ZoneSigning`/`KeyStore`, `ListManager`, `GroupStore`, `Cache`, query-log writer, `ClientCertService`). `EngineBuilder` then takes references to those (it already has the setters `zones()`, `list_manager()`, `groups()`, `sink()`), and `ApiState` is built from the same `Services`. Remove the five accessors from `Engine` and the pass-through fields from `ApiState`. `EngineBuilder::from_config` can stay as a thin shim over `Services::open` to honour the pinned name. Effort M (touches builder, serve.rs, api state, tests).

### F2. `ApiState` sprawl and four seam styles (high, M)

Evidence, `crates/dnsy-api/src/state.rs:30-73, 78-194`:

- 24 public fields; 7 `Option`s (`bootstrap`, `zones`, `cache`, `engine`, `cert_reload`, `signing`, `validation`) each of which produces a 503 branch in the routes (`routes/live.rs::require_engine`, `routes/zones.rs::store`, cache and dnssec routes).
- 12 `with_*` setters across two `impl` blocks; `ApiState::new` is called at 10 sites, each test re-deriving the subset it needs.
- Four different ways for the API to reach the engine: a concrete `Arc<Engine>` (`set_acl`, `set_groups`, `set_block_mode`), a trait object `Arc<dyn ValidationControl>` defined in the API and implemented for `Engine` (`crates/dnsy-api/src/validation.rs:34-43`), a shared `Arc<AtomicBool>` (`dnssec_clock_untrusted`), and a boxed closure `CertReload` (`state.rs:25-26`). `serve.rs:164-171` passes the same engine three times (`with_engine`, `with_validation`, `with_dnssec_clock_flag`).
- `state.rs:19` imports `crate::routes::RuntimeSettings`, while every route imports `crate::state::ApiState`: a module-level cycle inside the crate (`RuntimeSettings` is defined in `routes/settings.rs:34`).

Recommendation: (a) one `LivePolicy` trait in `dnsy-api` (or in `dnsy-engine` as the public contract) covering ACL, rate limit, block mode, response-IP policy, groups, DNSSEC mode/anchors and the clock flag, implemented once for `Engine<E>`; `ApiState.engine`, `.validation`, `.dnssec_clock_untrusted` collapse into `Option<Arc<dyn LivePolicy>>`. (b) group the fields: `AuthServices { users, tokens, sessions, client_certs, bootstrap }`, `PolicyStores { rules, sources, groups }`, `Zones { store, signing, lock }`, `Observe { redact, live_tail, poll }`. (c) move `RuntimeSettings` to `state.rs` or its own module. Effort M; purely mechanical once F1 provides `Services`.

### F3. Config schema types used as runtime vocabulary (medium, M)

Evidence:

- `dnsy_config::Validation` is the mode type of `DnssecPolicy` (`crates/dnsy-resolver/src/forward.rs:17`), of `Engine::dnssec_mode()/set_dnssec_mode()` (`engine.rs:280-292`) and of the API's `ValidationControl` trait (`crates/dnsy-api/src/validation.rs:35-36`). A TOML enum is therefore a public runtime contract of three crates.
- `BlockMode` exists three times: `crates/dnsy-config/src/model.rs:337` (`Nxdomain`), `crates/dnsy-filter/src/matcher.rs:22` (`NxDomain`, also carries `CustomIp`), `crates/dnsy-api/src/routes/settings.rs:86` (`BlockModeView`); `crates/dnsy-engine/src/builder.rs:51-57` is the hand-written mapping.
- `TrustAnchor::parse` (`crates/dnsy-config/src/validate.rs:8-24`) parses DS presentation format inside the config crate (which cannot use `dnsy-proto`), and `dnsy-resolver` converts it to `dnsy_proto::Ds` (`forward.rs:83-91`), so DS parsing is split across two crates.
- `Cache::new(&dnsy_config::Cache)` (`crates/dnsy-resolver/src/cache/mod.rs:13`) and `KeyStore` reading `dnsy_config::PASSPHRASE_ENV` (`crates/dnsy-zone/src/keystore.rs:132`) are the other two reasons `resolver` and `zone` depend on `config`.

Recommendation: move `Validation` and `BlockMode` to `dnsy-core` (they are vocabulary, like `DnssecStatus`), keep `serde` renames there; `dnsy-config` re-exports them. Give `Cache::new` a `CacheOptions` struct owned by the resolver (`From<&dnsy_config::Cache>` lives in the engine builder). Move `TrustAnchor::parse` to `dnsy-dnssec` (it owns `TrustAnchors`), leaving config with a plain string list validated at load time by calling it, which flips the dependency the right way only if config may depend on dnssec; otherwise keep the string in config and parse in resolver as today but delete `validate::TrustAnchor`. Pass the passphrase env name as a parameter of `passphrase_from_environment`. After this `resolver`, `zone` and `engine` no longer need `dnsy-config` except in `EngineBuilder::from_config`. Effort M.

### F4. `keystore.rs` god file; key domain split across two crates (medium, L)

Evidence: `crates/dnsy-zone/src/keystore.rs` (1945 lines, 1115 prod) contains: `Passphrase`/`resolve_passphrase` (lines 71-135), KDF and AEAD (`KdfCost`, `derive`, `encrypt`, `decrypt`, 137-237), SQLite row mapping and SQL (`row_to_record`, `list_zone`, `insert`, 245-333), the `KeyStore` service with generate/bootstrap/rollover/confirm/abort/tick (395-884), bundle export/import and passphrase change (885-1092). The key *model* (`KeyRecord`, `KeyRole`, `KeyState`, `Clock`) lives in `crates/dnsy-dnssec/src/keys.rs:20-155`; the rollover *timings* also come from the API/CLI (`serve.rs:193-199 rollover_timings`). `dnsy-zone` imports `dnsy_dnssec` at 45 sites, more than `dnsy_proto` (25).

Nothing in `keystore.rs` is about JSON zones: it keys rows by zone name only. It sits in `dnsy-zone` because the plan assigned "DNSSEC key store" there and `dnsy-dnssec` must not depend on `dnsy-store`.

Recommendation: split into a crate `dnsy-keys` (depends on `dnssec`, `store`, `core`): modules `passphrase.rs`, `sealed.rs` (KDF + AEAD, unit-testable without SQLite), `repo.rs` (SQL), `rollover.rs` (state machine), `bundle.rs`. `dnsy-zone` keeps `ZoneSigning` and depends on `dnsy-keys`. `KeyRecord`/`KeyRole`/`KeyState` move with it (they are not needed by the validator), which shrinks `dnsy-dnssec`'s public surface by one module. Effort L because of the test volume (830 lines of tests in the file plus `signed_tests.rs`), but it is file moves, not logic changes.

### F5. Four clocks (medium, M)

| Where | Shape |
| --- | --- |
| `crates/dnsy-dnssec/src/keys.rs:20` | `trait Clock { fn now(&self) -> i64 }` (unix seconds) |
| `crates/dnsy-filter/src/manager.rs:31` | `trait Clock: 'static { fn now(&self) -> i64; fn sleep(&self, Duration) -> Pin<Box<dyn Future>> }` |
| `crates/dnsy-resolver/src/groups/mod.rs:31` | `trait Clock { fn now(&self) -> Duration }` (monotonic since an origin) |
| `crates/dnsy-engine/src/engine.rs:56` | `type Now = Arc<dyn Fn() -> Instant + Send + Sync>` |
| ad hoc | `dnsy_auth::unix_now` (`lib.rs:27`), `dnsy_filter::rules::unix_now` (`rules.rs:39`), `dnsy_resolver::groups::store::unix_now` (`store.rs:30`, `i64`), `dnsy_resolver::forward::unix_now` (`forward.rs:202`, `u64`), `dnsy_api::routes::certs::now` (`certs.rs:39`); 13 direct `SystemTime::now()` calls in production code across 9 crates |

Consequences: `ApiState.clock` is `Arc<dnsy_dnssec::Clock>` (`state.rs:72`) and is used for negative-trust-anchor expiry, so the API's time source is the DNSSEC crate's trait; `EngineBuilder::from_config` instantiates `dnsy_filter::SystemClock`, `dnsy_dnssec::SystemClock` and `dnsy_resolver::groups::SystemClock` (`builder.rs:140,150,163`); the DNSY-68 thread asks for "an injectable clock" in mTLS re-verification, which would be a fifth one.

Recommendation: one `dnsy_core::Clock { fn unix(&self) -> i64; fn instant(&self) -> Instant }` with `SystemClock` and a `ManualClock` test helper behind a `test-util` feature; the filter's `sleep` becomes a separate `Sleeper` or stays a method with a default impl that uses tokio. Replace the five free functions. Effort M (mechanical, many call sites, but each change is local).

### F6. Three per-client failure counters, three keying policies (medium, M)

| Counter | Storage | Key | Window | Eviction |
| --- | --- | --- | --- | --- |
| `dnsy_filter::RateLimiter` (`ratelimit.rs:42-109`) | sharded in-memory token buckets | `client_key(ip)` = IPv4 /32, IPv6 /64 (`ratelimit.rs:25-31`) | token bucket | bounded `max_keys` |
| DoH `Throttle` (`crates/dnsy-server/src/doh/throttle.rs:15-52`) | `Mutex<HashMap<IpAddr,(u32,Instant)>>` | raw `IpAddr` | fixed window | `MAX_TRACKED`, then `clear()` (the DNSY-68 finding) |
| login throttle (`crates/dnsy-auth/src/sessions.rs:90-135`) | SQLite `login_attempts` | `(username, ip.to_string())` | 15 min sliding count | `DELETE ... WHERE at <= since` on every failure |

The correct IPv6 policy already exists in `dnsy-filter::client_key` and the other two do not use it; DNSY-68 asks to add /64 grouping to both, which would be a third copy.

Recommendation: a `FailureThrottle` in `dnsy-core` or a tiny `dnsy-ratelimit` module (bounded, sharded, fixed-window, keyed by `ClientKey` = `client_key(ip)` plus an optional secondary key), used by DoH and, for the per-IP half, by auth; auth keeps the per-username row in SQLite for durability. Do this inside DNSY-68 rather than after it. Effort M.

### F7. Zone editing logic lives in the API (medium, M)

Evidence: `crates/dnsy-api/src/routes/zones.rs:300-316` (`mutate`: `spawn_blocking` under `ApiState.zone_lock: Arc<Mutex<()>>`), `:318-330` (`current` + `If-Match`), `:401-419` (`bumped`, `records_mut`, `position`: the zone is serialised with `Zone::to_json`, re-parsed into `serde_json::Value`, the `"soa"."serial"` and `"records"` array are edited as JSON, then parsed back with `Zone::from_json`). `dnsy-zone` offers only `write_zone(&Zone)`/`remove_zone` (`crates/dnsy-zone/src/store.rs:273-290`) with no record-level or serial-aware operation. Record ids (`view(r).id`) are also computed in the API (`zones.rs:181 hex`).

Consequences: the CLI cannot edit records without re-implementing this; a second writer (future AXFR/IXFR, dynamic update, the DNSSEC policy patch in `routes/dnssec.rs`) must remember to take the API's lock; the invariant "every write bumps the serial" is enforced by convention in route code.

Recommendation: `ZoneStore::update(origin, expected_serial: Option<u32>, f: impl FnOnce(&mut Zone) -> Result<...>) -> Result<Arc<Zone>, ZoneError>` in `dnsy-zone` that owns the lock, serial bump, atomic write and the optimistic-concurrency check; `Zone::add_record/replace_record/remove_record(id)` plus a stable `Record::id()`. The API becomes DTO mapping. Effort M (moves ~150 lines, needs the existing 10 route tests re-pointed).

### F8. `dnsy-filter` cohesion (medium, L)

Evidence: `crates/dnsy-filter/src/` holds `parse.rs`/`matcher.rs` (pure), `fetch.rs` (reqwest + rustls + webpki-roots), `manager.rs` (tokio scheduler with its own `Clock`), `sources.rs`/`rules.rs` (rusqlite), `acl.rs`, `ratelimit.rs`, `response.rs` (builds `dnsy_proto::Message`). `Cargo.toml` normal deps: `arc-swap ipnet rand reqwest rustls rusqlite thiserror tokio tracing webpki-roots` (+ `axum` in dev). 14 public enums and 9 `pub use` lines for a crate whose pinned interface is `FilterSet::check` and `Verdict`.

Recommendation (after F6, since the rate limiter moves anyway): keep `dnsy-filter` = parse + match + rules + sources (the "what is blocked" domain); move `acl.rs` and `ratelimit.rs` to `dnsy-engine` or a `dnsy-policy` module (they are request admission, not content filtering); move `fetch.rs` + `manager.rs` to `dnsy-filter::sync` behind a `fetch` feature so `dnsy-engine` tests that use `Filters::Fixed` do not compile reqwest. Effort L; nice to have.

### F9. API builds resolver internals (low, S)

`crates/dnsy-api/src/routes/live.rs:75` calls `GroupSet::new(specs, Arc::new(SystemClock::new()), Arc::new(ThreadRng))`, duplicating `crates/dnsy-engine/src/builder.rs:161-165`. The clock and RNG choice is a resolver detail. Add `GroupSet::from_specs(specs)` (or `GroupStore::load_set()`) in `dnsy-resolver` and use it from both. Also `ApiState.engine: Option<Arc<Engine>>` pins `E = UpstreamClient`; after F2 the trait object removes that. Effort S.

### F10. `dnsy-server` sideways edges (low, S)

`crates/dnsy-server/src/dot/mtls.rs:16,76-98`: `Allowlist::refresh(&ClientCertService)` and `spawn_refresh(ClientCertService, Duration)` take the concrete auth service and return `dnsy_store::StoreError`. DoH already uses `DohAuthenticator`/`TokenVerifier` as a trait seam (`doh/mod.rs:62-75`). Make `refresh` take `impl Fn() -> Future<Output = Result<Vec<AllowedCert>, E>>` or a `CertSource` trait, and have the binary adapt `ClientCertService` (it already builds the `CertReload` closure for the API, `serve.rs:251`). Drops `dnsy-auth` and `dnsy-store` from `dnsy-server`'s normal deps. Effort S.

### F11. Duplicated helpers (low, S)

- Hex encoders: `crates/dnsy/src/admin.rs:266 hex`, `crates/dnsy-api/src/routes/acl.rs:88 hex`, `crates/dnsy-api/src/routes/zones.rs:181 hex`, `crates/dnsy-api/src/validation.rs:11 hex_upper`; plus `crates/dnsy-zone/src/policy.rs:185 hex_decode` and `crates/dnsy-proto/src/rdata/text.rs:111 parse_hex`. One `dnsy_core::hex` (or expose `dnsy_proto`'s) suffices.
- DS export: `crates/dnsy/src/admin.rs:421-500 dnssec_keys` and `crates/dnsy-api/src/routes/dnssec.rs:896-967 ds_export` both iterate keys, call `ds_for` for each digest type and format presentation text. Add `KeyStore::ds_records(zone, digests) -> Vec<(KeyRecord, Ds)>` and let both format.
- `BlockMode` x3 (see F3).

### F12. `dnsy-api` test placement and route file size (low, M)

5386 of the crate's 11959 lines are tests inside `src/` (`tests.rs`, `tests_auth.rs`, `tests_obs.rs`, `tests_policy.rs`, `routes/dnssec_tests.rs`, inline module in `routes/zones.rs` from line 812). They use only the public surface (`router`, `ApiState`, `EngineBuilder`) and belong in `crates/dnsy-api/tests/`, which would also stop `cargo check` from compiling them. `routes/zones.rs` (811 prod lines, 10 handlers) and `routes/dnssec.rs` (1138 lines, 13 handlers) should each split into `dto.rs` + handlers once F7 removes the mutation logic. Effort M.

### F13. Web feature boundaries (low, S)

Evidence (`web/src/app/`):

- `shared/` contains only `mascot/`. The generic `Dialog` (`features/zones/dialog.ts:15`, selector `app-dialog`) and `ConfirmDialog` (`features/zones/confirm-dialog.ts:6`) are imported from `zones/` by `acl`, `cache`, `certs`, `dnssec`, `filtering`, `tokens`, `upstreams`, `users` (sibling imports `../zones/...`: 12 occurrences).
- `features/admin-shared/` holds `util.ts` (`messageOf`, `formatEpoch`) and `testing.ts` (spec helpers) and is imported by 11 pages; it is a shared folder living under `features/`.
- `features/users` imports `../profile/password-strength`; `features/dnssec` and `features/zones` import each other (`zone-dnssec-tab` is mounted by `zone-detail.page`).
- Positive: no feature imports another feature's service; every feature has its own `*.service.ts` wrapping `core/api.service.ts` (a 5-method `HttpClient` facade), and types are aliased from the generated `api/schema.d.ts` per service (`features/dnssec/dnssec.service.ts:7-17`, `filtering.service.ts:7-13`) instead of being copied; 74 exported interfaces/types in features, of which the hand-written ones are view-state (`query-log.model.ts Filters`, `RangeKey`).
- `api/schema.d.ts` (5016 lines) is committed although the design said "generated at build time (not committed)"; `package.json` has the `types` script. Either is fine, but the drift test only covers `openapi/dnsy.json`, not this file.

Recommendation: move `dialog.ts`, `confirm-dialog.ts`, `tokens/copy.ts`, `admin-shared/util.ts` to `shared/ui/` and `shared/util/`; move `admin-shared/testing.ts` to `src/testing/`; move `password-strength.ts` to `shared/`; add an ESLint `no-restricted-imports` rule forbidding `../<other-feature>/` except `shared`, `core`, `api`. Add a CI step that regenerates `schema.d.ts` and fails on diff (pipelines epic). Effort S.

### F14. `serve.rs` complexity (low, S)

`crates/dnsy/src/serve.rs:280 reload` (cognitive complexity 51) handles SIGHUP for zones, mTLS CA, allowlist and trust anchors in one function; `serve.rs:50 serve` (42) spawns prefetch, list manager, zone watcher, signer, rollover timer, server, API, signals. Both shrink naturally once F1's `Services` exposes `reload()` and `spawn_background()`; otherwise extract one function per reloadable thing. Effort S.

## 5. Conceptual cycles and seams checked

- `zone <-> dnssec`: no cycle. `dnsy-dnssec` owns `ZoneData`, `SigningPolicy`, `ActiveKeys`, `SignedZone` (`sign/mod.rs:32-129`); `dnsy-zone` adapts (`Zone::signing_data() -> dnsy_dnssec::ZoneData`, `model.rs:237`). This is the right direction. The only smell is F4 (key model in dnssec, key store in zone).
- `engine <-> api`: the API depends on the engine, never the reverse; the `ValidationControl` trait lives on the API side (consumer-defined interface), which is good practice but inconsistent with the concrete `Arc<Engine>` next to it (F2).
- `server <-> api`: never linked; shared concerns (mTLS allowlist reload, DoH token verification) go through closures and traits built by the binary. Good.
- `Handler` (`crates/dnsy-engine/src/handler.rs`) is the only trait transports see; `RefusedHandler` exists for tests. `Exchange` (`crates/dnsy-resolver/src/groups/mod.rs:145`) makes the engine testable without sockets (`EngineBuilder<E>`), and `NoUp` is used in API tests (`routes/dnssec_tests.rs:69`). Good seams.
- `QueryEventSink`, `TokenVerifier`, `DohAuthenticator`, `DnssecFetcher`: all pinned traits are present and used as the only coupling point.
- Feature flags: one (`embed-ui`, `crates/dnsy-api/Cargo.toml`, forwarded by `crates/dnsy/Cargo.toml`). No feature creep.
- SQLite access: every crate uses `Store::read/write` closures (`auth` 29, `zone` 18, `filter` 15, `observe` 8, `resolver` 3 call sites) and `rusqlite` directly inside them; 35 `params!`, 21 `prepare`, 5 `prepare_cached`. No ad-hoc connections outside `dnsy-store`. Consistent; the DB pass (DNSY-62) owns the rest.
- Error types: 24 `pub enum *Error`, one per module boundary, all `thiserror`; `ApiError` is an HTTP-status-shaped enum of 10 variants (`crates/dnsy-api/src/error.rs:34-55`) with explicit `From<AuthError>`/`From<UserError>` (`error.rs:158,174`) and call-site mapping for every other domain error, so no store or protocol error type leaks into a problem body. `StoreError` is re-wrapped at each layer instead of leaking. Fine.
- Redaction: single `redact_client_ip` (`crates/dnsy-observe/src/event.rs:93`), applied by the writer and the API through one `redact_client_ip` flag; the DoH path token is parsed in one place (`crates/dnsy-server/src/doh/wire.rs::path_token`). No duplication found.
- Module naming: consistent (`mod.rs` + `tests.rs` or `*_tests.rs`), except `dnsy-api` which mixes inline tests (`routes/zones.rs`), sibling files (`routes/dnssec_tests.rs`) and crate-root files (`tests_*.rs`) (F12), and `dnsy-zone/src/export.rs:10-11` which imports a type under `#[cfg(test)]` at the top of a production module.

## 6. Must fix before 1.0 vs nice to have

**Before 1.0** (they shape the public wiring surface that downstream tooling, tests and the 1.0 config contract depend on):

1. F1 `Services` + engine stops being a locator.
2. F2 `ApiState` regrouping and one `LivePolicy` seam.
3. F3 config enums out of runtime APIs (`Validation`, `BlockMode`, `TrustAnchor`).
4. F6 one failure-throttle implementation, folded into DNSY-68.
5. F7 zone mutation into `dnsy-zone`.

**Nice to have** (internal, no contract change): F4, F5, F8, F9, F10, F11, F12, F13, F14.

## 7. What is already good

- The hard rules hold exactly: `dnsy-proto` has zero dependencies, `dnsy-dnssec` depends on `core`, `proto`, `ring`, `zeroize` only, no DNS crate anywhere, no `unsafe`, no `#[allow]`.
- No dependency cycles, no `dev-dependency` back-edges, `api` never sees `server`, every pinned trait from the plan exists and is the only coupling point at its boundary (`Handler`, `Exchange`, `QueryEventSink`, `TokenVerifier`, `DohAuthenticator`, `DnssecFetcher`).
- `dnsy-core` is 77 production lines and has stayed pure vocabulary.
- One request pipeline (`Engine::pipeline`, 102 lines) in the spec's order, with the transports only framing bytes; `Engine<E: Exchange>` makes it testable without sockets, and the resolver carries a 2.6:1 test-to-code ratio.
- Complexity is under control: three functions over clippy's cognitive threshold in 54k lines of Rust, seven `#[expect]`s in the whole workspace.
- Curated `pub use` lists in every `lib.rs`; no glob re-exports; one cross-crate re-export, justified.
- SQLite access goes through one `Store::read/write` API everywhere; errors are per-boundary `thiserror` enums; client-IP redaction exists once.
- Web: a five-method `ApiService` facade, one service per feature, generated OpenAPI types aliased per feature rather than copied, no feature-to-feature service imports, lazy routes.

## 8. Proposed follow-up stories (priority order)

| # | Title | Acceptance criteria | Estimate |
| --- | --- | --- | --- |
| 1 | ♻️ Extract `Services` wiring and remove service accessors from `Engine` | `Services::open(&Config, &Store)` builds zone store, signing, list manager, group store, cache, query-log writer, client-cert service once; `EngineBuilder` and `ApiState` are both fed from it; `Engine::{cache,zone_store,zone_signing,groups,list_manager}` removed; `serve.rs::serve` and `reload` under cognitive complexity 25 without `#[expect]`. | M (3 d) |
| 2 | ♻️ Collapse `ApiState` seams into `LivePolicy` and grouped sub-states | One `LivePolicy` trait replaces `engine`, `validation` and `dnssec_clock_untrusted`; fields grouped into `AuthServices`, `PolicyStores`, `Zones`, `Observe`; at most 3 `Option`s remain; `RuntimeSettings` no longer imported from `routes` by `state.rs`; all API tests pass unchanged in behaviour. | M (2 d) |
| 3 | ♻️ Move `Validation` and `BlockMode` to `dnsy-core`; drop `dnsy-config` from resolver and zone | `dnsy-resolver`, `dnsy-zone` and `dnsy-engine` (outside `builder.rs`) have no `dnsy_config::` use; `BlockMode` defined once (`BlockModeView` may stay as the API DTO); `Cache::new` takes a resolver-owned options struct; `cargo metadata` shows `config` with fan-in 3 (api, engine, dnsy). | M (2 d) |
| 4 | 🔒 One `FailureThrottle` for DoH and login, keyed by `client_key` (/64) | Shared bounded fixed-window throttle used by `dnsy-server` DoH and `dnsy-auth` per-IP path; DNSY-68's saturation and IPv6-rotation tests pass against the shared type; `doh/throttle.rs` deleted. Coordinate with DNSY-68 (same files). | M (2 d) |
| 5 | ♻️ `ZoneStore::update` owns zone mutation, serial bump and `If-Match` | `ZoneStore::update(origin, expected_serial, f)` with internal lock and atomic write; `Zone::{add,replace,remove}_record` and stable `Record::id()`; `ApiState.zone_lock` and `routes/zones.rs::{mutate,bumped,records_mut,position}` removed; existing route tests and `rest_zones` e2e pass. | M (3 d) |
| 6 | ♻️ Split `keystore.rs` into a `dnsy-keys` crate | New crate with `passphrase`, `sealed`, `repo`, `rollover`, `bundle` modules; `KeyRecord`/`KeyRole`/`KeyState` move there; `dnsy-zone` keeps `ZoneSigning`; `dnsy-dnssec` loses `keys.rs`; coverage per crate stays at or above the gate. | L (5 d) |
| 7 | ♻️ One `Clock` in `dnsy-core` | `dnsy_core::{Clock, SystemClock, ManualClock}`; the three crate-local `Clock` traits, `Now` and the five `unix_now`/`now` functions are gone; no direct `SystemTime::now()` outside `SystemClock`; existing manual-clock tests re-pointed. | M (2 d) |
| 8 | ♻️ Trait seam for the mTLS allowlist source; `dnsy-server` drops `auth` and `store` deps | `Allowlist::refresh` takes a `CertSource` trait or closure; binary adapts `ClientCertService`; `crates/dnsy-server/Cargo.toml` lists only `core`, `proto`, `engine` (+ `auth` for the `TokenVerifier` adapter if kept). | S (1 d) |
| 9 | ♻️ Deduplicate hex, DS export and `GroupSet` construction | One hex helper; `KeyStore::ds_records`; `GroupSet::from_specs`; CLI and API DS output byte-identical before and after (snapshot test). | S (1 d) |
| 10 | 🎨 Web: shared UI and util folders, import boundary lint | `Dialog`, `ConfirmDialog`, `copy.ts`, `util.ts`, `password-strength.ts` under `shared/`; `testing.ts` under `src/testing/`; ESLint `no-restricted-imports` blocks cross-feature imports; `ng lint` and unit tests green. | S (1 d) |
| 11 | ♻️ Move `dnsy-api` tests to `tests/` and split the two largest route files | `src/tests*.rs` and `routes/dnssec_tests.rs` under `crates/dnsy-api/tests/`; `routes/zones.rs` and `routes/dnssec.rs` each split into DTOs and handlers, no file over 700 lines; coverage unchanged. | M (2 d) |
| 12 | ♻️ Narrow `dnsy-filter` to filtering; move ACL and rate limit to the engine, fetch behind a feature | `acl.rs`, `ratelimit.rs` in `dnsy-engine` (or `dnsy-policy`); `fetch.rs`/`manager.rs` behind `features = ["fetch"]`; `dnsy-filter` default build has no reqwest/rustls; `dnsy-engine` unit tests compile without the feature. | L (4 d) |

Stories 1-5 are the "before 1.0" set; 6-12 can be scheduled after the dependency, security, database and performance passes land, with 4 merged into DNSY-68 if that story is still open.
