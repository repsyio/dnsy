# Dependency optimisation analysis (DNSY-60)

Read-only analysis pass over the DNSY workspace (13 crates + `tests/e2e`) and the Angular web app
(`web/`) at commit `237751b` (`main`, all implementation stories DNSY-1..58, 69, 70 merged).
Nothing in this pass changes product code, `Cargo.toml` or `package.json`; every number below was
measured, not estimated, unless marked "expected".

Environment: Linux, 24 cores, 30 GB RAM, rustc/cargo 1.99.1 (pinned), node 24.21, pnpm 10.16,
`CARGO_TARGET_DIR` on a local SSD, warm crates.io and pnpm store caches (no download time in any
timing). All build timings were taken sequentially on an otherwise idle machine; a first round that
overlapped with tool installation and the web build was discarded because contention tripled every
number.

Tools used: `cargo tree`, `cargo metadata`, `cargo build --timings`, `cargo deny 0.18`, and, installed
for this pass, `cargo-machete 0.9`, `cargo-bloat 0.12.1`, `cargo-audit 0.22.2`; `pnpm outdated`,
`pnpm audit`, `pnpm dedupe --check`, `ng build --stats-json` (esbuild metafile), `esbuild` for the
three.js tree-shaking experiment. Not available: `cargo-udeps` (needs nightly; `cargo-machete` plus
a grep cross-check was used instead), `cargo-geiger` (0.14.0 does not compile on 1.99.1; `unsafe`
sites were counted with a grep over the resolved registry sources instead), `bloaty` (not installed;
`cargo-bloat` and `strip` cover the same questions).

## 1. Headline numbers

| Metric | Value |
| --- | --- |
| Packages in `Cargo.lock` (all targets, all kinds) | 308 |
| Crates compiled for the `dnsy` release binary on Linux (`cargo tree -p dnsy -e normal`) | 210 (215 with `embed-ui`) |
| Crates in the whole workspace build incl. dev/build deps (`cargo tree --workspace`) | 238 |
| Distinct third-party crates declared in `[workspace.dependencies]` | 39 (37 used, 2 unused) |
| `dnsy-proto` runtime dependencies | 0 (dev: `insta` only) |
| Banned DNS/TLS crates anywhere in the tree | none (verified with `cargo tree -i` for each) |
| Duplicate versions on the Linux tree | `getrandom` 0.2/0.4, `syn` 2/3, `synstructure` 0.13/0.14 |
| `cargo deny check` (licenses, advisories, bans, sources) | all ok; 2 unused licence allowances |
| `cargo audit` | 0 vulnerabilities, 0 warnings, 0 yanked |
| Clean release build, `cargo build --release -p dnsy` | 74.2 s wall, 353 s CPU, 261 units |
| Critical path of that build | `libsqlite3-sys` build script: 45.7 s (62 % of the wall time) |
| Incremental release rebuild after touching `crates/dnsy/src/main.rs` | 7.9 s |
| Incremental release rebuild after touching `crates/dnsy-core/src/lib.rs` | 21.0 s |
| Clean debug build, `cargo build -p dnsy` | 24.1 s wall, 159 s CPU |
| Incremental debug rebuild (`dnsy-core` / `dnsy-api` / `main.rs` touched) | 2.2 s / 1.8 s / 0.6 s |
| Clean debug build, `cargo build --workspace --all-targets` | 38.1 s wall, 383 s CPU, 325 units |
| Release binary (default profile, no UI) | 27.78 MB; 20.39 MB after `strip` (-27 %) |
| Release binary with `embed-ui` | 28.99 MB (+1.21 MB for a 1.17 MB `web/dist`); 21.60 MB stripped |
| Release binary, `lto = "thin"`, `strip = true` | 20.94 MB, clean build 74.6 s (no slower) |
| Release binary, `lto = "thin"`, `strip`, `codegen-units = 1` | 17.07 MB, clean build 115.7 s |
| Release binary, `lto = "fat"`, `codegen-units = 1`, `strip`, `panic = "abort"` | 13.60 MB (-51 %), clean build 132.5 s |
| Web: packages in `pnpm-lock.yaml` / `node_modules` size | 527 / 457 MB |
| Web: initial bundle | 304.45 kB raw (83.1 kB transfer) against a 300 kB warning budget |
| Web: largest lazy chunk (`login-scene`, three.js) | 546.8 kB raw, 136.6 kB gzip |
| Web: `pnpm audit` | 3 advisories (1 high, 2 moderate), all in `vite` 8.3.x via `@angular/build` |
| Web: `pnpm outdated` | 3 (typescript-eslint patch, @types/node major, typescript major) |

## 2. Inventory

### 2.1 Rust workspace

All versions live in `[workspace.dependencies]`; every crate uses `{ workspace = true }`. Direct
third-party dependencies per crate (dev-dependencies in brackets):

| Crate | Third-party deps | Dev-deps | Notes |
| --- | --- | --- | --- |
| `dnsy-core` | serde | serde_json | |
| `dnsy-proto` | none | insta | std only, as required |
| `dnsy-dnssec` | ring, zeroize | - | |
| `dnsy-config` | serde, thiserror, toml | - | 6.0 s release compile for a config crate (see F15) |
| `dnsy-store` | rusqlite, sha2, thiserror, tokio | tempfile | |
| `dnsy-auth` | argon2, base64, rand, rusqlite, sha2, subtle, thiserror, tokio | tempfile | |
| `dnsy-observe` | rusqlite, thiserror, tokio, tracing | tempfile | |
| `dnsy-zone` | arc-swap, argon2, base64, notify, ring, rusqlite, serde, serde_json, thiserror, tokio, tracing, zeroize | insta, tempfile | |
| `dnsy-resolver` | arc-swap, rand, rusqlite, rustls, rustls-pki-types, thiserror, tokio, tokio-rustls, webpki-roots | rcgen, tempfile | `rustls-pki-types` unused (F9) |
| `dnsy-filter` | arc-swap, ipnet, rand, reqwest, rusqlite, rustls, thiserror, tokio, tracing, webpki-roots | axum, proptest, tempfile | |
| `dnsy-engine` | arc-swap, ipnet, thiserror, tokio, tracing | tempfile | |
| `dnsy-server` | arc-swap, base64, http-body-util, hyper, hyper-util, notify, rustls, rustls-pki-types, sha2, tokio, tokio-rustls, tracing, x509-parser | hyper(client), rcgen, tempfile, time, tracing-subscriber | `x509-parser` only builds a log string (F2) |
| `dnsy-api` | axum, base64, futures-util, ipnet, rand, rust-embed (optional), serde, serde_json, sha2, subtle, thiserror, tokio, tracing, utoipa, utoipa-axum | http-body-util, tempfile, tower, tracing-subscriber | largest workspace compile unit (F15) |
| `dnsy` (bin) | axum, base64, clap, hyper, hyper-util, rand, reqwest, rustls, rustls-pki-types, serde_json, tokio, tokio-rustls, tower, tracing, tracing-subscriber, webpki-roots | rcgen, tempfile | |
| `dnsy-e2e` | base64, rcgen, reqwest, rustls, rustls-pki-types, serde_json, sha2, tempfile, tokio, tokio-rustls | - | test harness crate, excluded from release |

Resolved features worth knowing (from `cargo metadata`): tokio `full`; axum default (`form`,
`json`, `query`, `matched-path`, `original-uri`, `tower-log`, `tracing`); hyper `client` + `server`
+ `http1` + `http2`; hyper-util `client`, `client-legacy`, `client-proxy` (all three enabled by
reqwest, not by us) + `server-auto`; reqwest `rustls-no-provider` + `http2` + `json` (`http2` and
`json` come from `tests/e2e` and unify into the release tree because cargo resolves features per
workspace build, not per package); rustls `ring` + `std` + `tls12` only (no `aws-lc-rs`, good);
rusqlite `bundled`; clap `derive`, `env`, `color`, `suggestions`, `help`, `usage`,
`error-context`; tracing-subscriber default + `json`; serde_json `raw_value` (pulled in by
utoipa-axum); time `formatting` + `parsing` + `macros` (pulled by x509-parser; our only direct use is a
dev-dependency in `dnsy-server`).

Build scripts on the Linux release tree: 21 (`libsqlite3-sys`, `ring`, `rustls`, `serde`,
`serde_core`, `serde_json`, `thiserror`, `libc`, `getrandom`, `httparse`, `proc-macro2`, `quote`,
`rustversion`, `num-traits`, `parking_lot_core`, `oid-registry`, `inotify-sys`, `zmij`,
`icu_normalizer_data`, `icu_properties_data`, `dnsy`). Proc-macro crates: 15 (`serde_derive`,
`tokio-macros`, `thiserror-impl`, `tracing-attributes`, `clap_derive`, `utoipa-gen`,
`time-macros`, `displaydoc`, `pastey`, `rustversion`, `asn1-rs-derive`, `asn1-rs-impl`,
`yoke-derive`, `zerofrom-derive`, `zerovec-derive`). Only two of those build scripts matter for
time: `libsqlite3-sys` (45.7 s, compiles the SQLite amalgamation with `cc` at `-O3`) and `ring`
(10.3 s, assembles its C/asm backends). Everything else finishes within the first 20 s of the build.

Edition and MSRV: workspace is `edition = "2024"`, `rust-version = "1.99"`, toolchain pinned to
1.99.1. Third-party crates: 49 on edition 2024, 150 on 2021, 74 on 2018, 15 on 2015 (13 of them
on the Linux tree, all tiny: `autocfg`, `fnv`, `lazy_static`, `scopeguard`, `mime`, `strsim`,
`try-lock`, `inotify-sys`, `signal-hook-registry`, `vcpkg`, ...). The highest third-party MSRV is
1.88 (`time`, `utoipa`, `sha2`, `rcgen`, `proptest`, `icu_*`); 53 crates declare none. Our own
`rust-version = "1.99"` equals the pinned toolchain, so it carries no information for consumers;
since every crate is `publish = false` this is harmless, but `cargo-msrv` could be run once if the
binary is ever meant to build on a distro toolchain.

### 2.2 Web app (`web/`)

Runtime dependencies: `@angular/{common,compiler,core,forms,platform-browser,router}` 22.2.3,
`rxjs` 7.8.2, `three` 0.186.1, `tslib` 2.8.1. No `zone.js` (zoneless app, good). Dev dependencies:
Angular build/CLI 22.2.3, `angular-eslint` + `typescript-eslint` 8.71.0 + `eslint` 10.12, Tailwind
4.3.3 (`@tailwindcss/postcss` + `postcss`), Vitest 5 + `@vitest/coverage-v8` + `jsdom`, Playwright
1.64.1 + `@axe-core/playwright`, `openapi-typescript` 7.13, `prettier` 3.8, `typescript` 6.0.3.
`web/e2e/` has no `package.json`; Playwright and its deps live in `web/package.json` (relevant for
Dependabot: one npm ecosystem at `/web`, not two).

Everything the user downloads (`web/dist/dnsy/browser`, 1,165,468 bytes before compression):

| Chunk | Raw | gzip | Composition (esbuild metafile) |
| --- | --- | --- | --- |
| `chunk-BakL2LLu` (initial) | 152.1 kB | 50.6 kB | `@angular/core` 166.9 k, `rxjs` 21.5 k, `tslib` 2.4 k |
| `main` (initial) | 101.9 kB | 29.1 kB | `@angular/router` 95.7 k, `platform-browser` 14.7 k, `common` 4.8 k, app shell + routes + auth/api services ~6 k |
| `styles.css` (initial) | 28.5 kB | 6.0 kB | Tailwind output |
| `chunk-DTlcq45b` (initial) | 21.4 kB | 7.0 kB | `@angular/common/http` 26.6 k |
| `chunk-Da4-SChG` (initial) | 0.6 kB | 0.4 kB | |
| **Initial total** | **304.45 kB** | **83.1 kB** | 98 % framework, 2 % application code |
| `login-scene` (lazy) | 546.8 kB | 136.6 kB | `three` 621 k (`three.module.js` 405 k + `three.core.js` 216 k), app 2.7 k |
| `login-page` (lazy) | 42.6 kB | 12.0 kB | `@angular/forms` 43 k |
| 24 further lazy page chunks | 0.8-36.5 kB each | | application code only |

Fonts: none bundled or linked (system font stack); `optimization.fonts.inline` is irrelevant.
Assets: 7 SVGs (mascot, mark, favicon), 5.3 kB total.

## 3. Rule verification

- **`dnsy-proto` has zero dependencies.** `cargo tree -p dnsy-proto -e normal,build` prints only
  `dnsy-proto v0.1.0`; the manifest has no `[dependencies]` table at all and a single dev-dependency
  (`insta`). Verified.
- **No DNS-protocol crate anywhere.** `cargo tree --workspace -i <crate>` for `hickory-proto`,
  `hickory-resolver`, `trust-dns-proto`, `domain`, `simple-dns`, `dns-parser`, `dnsclient`,
  `dnssec-prover`, `openssl`, `openssl-sys`, `native-tls`: every one answers "did not match any
  packages", and `cargo deny check bans` passes with the `deny.toml` list. Verified.
- One cosmetic exception worth knowing: `openssl-probe` 0.2.1 (a pure-Rust crate that only locates
  CA bundle paths; it does not link OpenSSL) is in the release tree via
  `reqwest -> rustls-platform-verifier -> rustls-native-certs`. It is dead code for us because both
  reqwest call sites pass a preconfigured `rustls::ClientConfig` with `webpki-roots`
  (`crates/dnsy-filter/src/fetch.rs:130`, `crates/dnsy/src/cacheflush.rs:95`). See F3.

## 4. Findings, ordered by gain per unit of effort

Severity scale: **High** (measurable cost in every build or every download, or a security/supply
chain exposure), **Medium** (real but bounded), **Low** (hygiene). Each finding states the evidence,
the recommendation, the expected gain and the risk.

### F1. `libsqlite3-sys` build script is the release build's critical path (High, low effort)

Evidence: `cargo build --timings` for the clean release build (74.2 s wall): the `libsqlite3-sys`
build script runs from t=3.6 s to t=49.4 s (45.7 s, single-threaded `cc` on the amalgamation).
Every workspace crate except `dnsy-proto`, `dnsy-core`, `dnsy-config` and `dnsy-dnssec` depends on
`dnsy-store` and therefore idles until t=49 s; every other third-party crate is finished by t=20 s.
After SQLite the remaining serial chain is `dnsy-store` (0.6 s) -> `dnsy-api` (15.2 s) -> `dnsy`
lib (9.2 s) -> `dnsy` bin (6.7 s) = 25 s. In the debug profile the same build script takes 7.4 s
of a 24.1 s build, so the dev loop pays less; release, `just build`, and the future CI/release
pipelines (seven targets in DNSY-66) are what pay.

Recommendation, in order of preference:

1. Keep `bundled` (single static binary is a product requirement) but lower the C optimisation
   level for that one package: `[profile.release.package.libsqlite3-sys] opt-level = 2` (the `cc`
   crate reads `OPT_LEVEL` from the package's own profile). Expected: the amalgamation compiles
   noticeably faster at `-O2` than `-O3` with no measurable SQLite throughput change for our
   workload (SQLite's own release builds use `-O2`). Must be measured in the follow-up story; if
   the gain is under 10 s, fall back to 2.
2. Cache it: once CI exists (DNSY-64), `sccache` with `CC="sccache cc"` caches the SQLite object
   between runs; `Swatinem/rust-cache` alone does not help because build-script outputs are keyed
   on the profile and rebuilt after `cargo clean`.
3. Do not switch to the system SQLite: it breaks the single-binary promise and the macOS/Windows
   matrix in DNSY-64.

Expected gain: up to 30 s of the 74 s clean release wall time (the build would end at roughly
20 s + 25 s). Risk: low; SQLite performance must be checked with the existing `dnsy-store` and
query-log tests and a before/after timing of the query-log writer before merging.

### F2. `x509-parser` is used only to format a log string, and costs 20 crates (High, low effort)

Evidence: `crates/dnsy-server/src/dot/mtls.rs:292-315` is the only use: `subject(der)` parses the
client certificate with `X509Certificate::from_der` to build a short "CN / SAN" string for the
connection log. Certificate validation itself is done by rustls/webpki. `cargo tree --prune
x509-parser` removes 20 crates from the release tree: `x509-parser`, `asn1-rs`, `asn1-rs-derive`,
`asn1-rs-impl`, `der-parser`, `oid-registry`, `rusticata-macros`, `nom`, `minimal-lexical`,
`data-encoding`, `num-bigint`, `num-integer`, `num-traits`, `num-conv`, `time`, `time-core`,
`time-macros`, `deranged`, `powerfmt`, and with them the `synstructure` 0.13 duplicate and one of
the four `syn` 2 users. Compile cost of that family in the clean release build: 34.5 s CPU
(`num-bigint` 5.4 s, `data-encoding` 5.2 s, `time` 4.8 s, `asn1-rs`, `nom`, `x509-parser`, ...),
21.0 s CPU in the debug all-targets build. Binary: 103.5 KiB of `.text` for `x509_parser`
alone plus its helpers. Supply chain: single-owner crate (`chifflier`), last release 2026-02.

Recommendation: replace `subject()` with either (a) `rustls-webpki`'s `EndEntityCert` (already in
the tree) to list DNS SANs, or (b) a 40-line DER walk in `dnsy-server` that extracts the CN
(OID 2.5.4.3) and the SAN extension (OID 2.5.29.17) with the project's existing reader style, or
(c) log only the SHA-256 fingerprint (already computed) and drop the subject string. The DNSSEC
crates already contain DER handling (`dnsy-dnssec/src/pubkey.rs`), so (b) is in character for the
project. Also move `time` out of `[workspace.dependencies]` or keep it dev-only (it is only used by
`crates/dnsy-server/tests/mtls.rs` for CRL dates via rcgen).

Expected gain: -20 crates (210 -> 190), about -35 s CPU per clean release build, -21 s CPU debug,
-1 proc-macro duplicate, ~ -0.3 MB binary. Risk: low; covered by the existing mTLS tests
(`crates/dnsy-server/tests/mtls.rs`).

### F3. `reqwest` pulls 30 crates, including the ICU/IDNA stack and a dead platform verifier (High, medium effort)

Evidence: `cargo tree --prune reqwest` removes 30 crates: `reqwest`, `hyper-rustls`,
`rustls-platform-verifier`, `rustls-native-certs`, `openssl-probe`, `tower-http`, `url`, `idna`,
`idna_adapter`, `icu_collections`, `icu_locale_core`, `icu_normalizer`, `icu_normalizer_data`,
`icu_properties`, `icu_properties_data`, `icu_provider`, `litemap`, `potential_utf`,
`stable_deref_trait`, `tinystr`, `utf8_iter`, `writeable`, `yoke`, `yoke-derive`, `zerofrom`,
`zerofrom-derive`, `zerotrie`, `zerovec`, `zerovec-derive`. 24 of them exist only because
`url` -> `idna` wants Unicode normalisation tables for internationalised hostnames; blocklist URLs
and the admin API base URL in our config are ASCII. Three of them (`rustls-platform-verifier`,
`rustls-native-certs`, `openssl-probe`) are unconditionally enabled by reqwest's
`rustls-no-provider` feature and never executed, because both call sites use
`use_preconfigured_tls` with `webpki-roots`. Compile cost: ICU/IDNA/URL family 21.0 s CPU +
reqwest/hyper-rustls/platform-verifier family 6.6 s CPU in the clean release build (14.4 s + 3.2 s
in debug). Binary: `reqwest` 661.5 KiB of `.text` (4.4 %), the fourth largest crate after
`dnsy_api`, `std` and `rustls`. The two features `http2` and `json` are enabled only by
`tests/e2e` but leak into the release binary through feature unification; `h2` (4.3 s compile,
430 KiB) is needed anyway by hyper for DoH, so that part is not reqwest's fault.

What reqwest does for us: two HTTPS GET clients. `dnsy-filter/src/fetch.rs` fetches blocklists with
`If-None-Match`/`If-Modified-Since`, reads `ETag`/`Last-Modified`/`Location`, redirect policy
`none`, a size cap and a timeout. `dnsy/src/cacheflush.rs` calls the local admin API once. Both
already own a `rustls::ClientConfig`.

Recommendation: a small `dnsy-filter::http` client on `hyper` 1 + `hyper-util` (`client-legacy`
is already compiled in) + `tokio-rustls` + `http-body-util`, all present in the tree, with manual
URL splitting (scheme, host, port, path; IDNA not supported, documented). About 150 lines, reusable
by `cacheflush.rs`; the e2e crate may keep reqwest (it is not in the release tree, but note that
its `http2`/`json` features then stop leaking). Keep `webpki-roots`.

Expected gain: -30 crates (190 -> 160 together with F2), about -28 s CPU per clean release build,
-18 s CPU debug, about -0.6 MB `.text`, and removes `openssl-probe` and the platform verifier from
the tree entirely. Risk: medium (hand-written HTTP client: redirects, chunked bodies, size caps,
timeouts must keep their current tests in `dnsy-filter`; the 12 fetch tests in
`crates/dnsy-filter/src/source_tests.rs` run against an axum test server with ETag, redirect-loop,
redirect-to-ftp and size-cap routes and will catch regressions).

### F4. No `[profile.release]`: 7.4 MB of symbols ship, and monomorphised closures are duplicated (High, trivial effort)

Evidence: `Cargo.toml` has no `[profile.*]` table. Default release: `strip = "none"`, `lto = false`
(thin-local), `codegen-units = 16`, `panic = "unwind"`. Measured: 27,778,504 bytes unstripped vs
20,386,008 stripped (-26.6 %); with `embed-ui` 28,991,152 vs 21,595,864. `cargo bloat` shows the
same closure emitted three times (`dnsy::run::{closure#0}` 3 x 41.3 KiB, `dnsy::serve::serve
::{closure#0}` 3 x 28.4 KiB, `dnsy::admin::dnssec_keys::{closure#0}` 3 x 26.1 KiB,
`toml::...deserialize_any::<Config visitor>` 2 x 28 KiB): the codegen-unit split duplicates large
generic async state machines. Profile experiments (clean builds, no UI):

| Profile | Binary | Clean build wall |
| --- | --- | --- |
| default | 27.78 MB (20.39 MB stripped by hand) | 74.2 s |
| `lto = "thin"`, `strip = true` | 20.94 MB (-25 %) | 74.6 s |
| `lto = "thin"`, `strip = true`, `codegen-units = 1` | 17.07 MB (-39 %) | 115.7 s |
| `lto = "fat"`, `codegen-units = 1`, `strip = true`, `panic = "abort"` | 13.60 MB (-51 %) | 132.5 s |

Recommendation: add `[profile.release] strip = true, lto = "thin"` now (free: same build time,
-6.8 MB) and take `codegen-units = 1` as well if a 40 s longer release build is acceptable for a
further -3.9 MB and deduplicated closures (release builds run only in `just build` and the
DNSY-66 pipeline, never in the dev loop). Decide `panic = "abort"` separately because it changes
behaviour: tokio task panics then abort the process instead of being caught by the runtime (no
`catch_unwind` exists in the tree today), so the handler pipeline's panic policy should be chosen
explicitly. Expected gain: 6.8-14.2 MB per binary times seven release targets. Risk: low;
`cargo llvm-cov` and tests run on the dev profile, so coverage is unaffected.

### F5. three.js is 137 kB gzip for the login scene and cannot be tree-shaken further (Medium, high effort)

Evidence: the `login-scene` lazy chunk is 546.8 kB raw / 136.6 kB gzip, of which 621 kB of inputs
come from `three` (the ratio is above 1 because esbuild minifies). `login-scene.ts` already uses
named imports of 16 symbols. Experiment with esbuild 0.27 on the same import list: package import
544,145 B / 136,024 B gz; deep `three/src/...` imports 549,771 B / 141,483 B gz (worse);
`WebGLRenderer` alone 531,581 B / 135,912 B gz. three's `sideEffects` list only covers
`src/nodes/**`, so the shaking is already working: the renderer is the weight, not the import
style. It loads lazily and only on `/login`, after the initial 83 kB, and is cached afterwards.

Recommendation: no dependency-level fix exists. Options for a product decision: keep it (it is the
brand moment of the UI, lazy, and cached); or replace the scene with a hand-written WebGL2/2D-canvas
grid (the scene uses a grid, a few boxes, a torus, sprites and fog; about 300 lines) and drop
`three` + `@types/three` (23 MB in `node_modules`). Expected gain if replaced: -137 kB gzip on first
login, -1 runtime dependency, -2 packages. Risk: medium (visual parity, the Playwright
`login-scene` and `mascot` specs cover behaviour but not pixels).

### F6. Initial bundle is 4.45 kB over the 300 kB warning budget and is 98 % framework (Medium, trivial effort)

Evidence: table in section 2.2. Application code in the initial bundle is about 6 kB
(`app.routes.ts` 2.5 k, `auth.service.ts` 1.1 k, `api.interceptor.ts` 0.9 k, `api.service.ts`
0.7 k, shell). The rest is `@angular/core` 167 k, `router` 96 k, `common` + `http` 31 k, `rxjs`
21.5 k, `platform-browser` 15 k, Tailwind CSS 28.5 k. `withFetch()` is already used (no XHR path),
there is no `zone.js`, `@angular/forms` is already lazy with the login page, and no component in
the initial graph imports `CommonModule` wholesale. Transfer size is 83.1 kB.

Recommendation: raise `maximumWarning` to `320kB` (keep `maximumError` at `400kB`) and add a
second budget of type `anyComponentStyle` (default 4 kB) so the budget keeps catching real
regressions. The alternatives (dropping the router's `withComponentInputBinding`, replacing
`HttpClient` with a hand-written `fetch` wrapper to drop the 21 kB http chunk) save under 25 kB
raw for a loss of framework features and are not recommended. Expected gain: a clean `ng build`
with no warning; no bytes. Risk: none.

### F7. `pnpm audit`: vite 8.3.0-8.3.2 (1 high, 2 moderate) via `@angular/build` (Medium, trivial effort)

Evidence: GHSA-587h-7wmj-h5pm (high), GHSA-698v-4r3x-3vcv and GHSA-r825-w8mm-5pxw (moderate), all
in `launch-editor` as used by vite's dev server; path `.>@angular/build>vite`; patched in
`vite >= 8.3.3`. This is build/dev tooling only: nothing from vite ships in `web/dist`, and the
dev server is only ever bound locally.

Recommendation: bump `@angular/build` once its lockfile resolves `vite >= 8.3.3` (a patch release;
`pnpm update @angular/build` when available), otherwise add
`pnpm.overrides = { "vite": ">=8.3.3" }` in `web/package.json`. Expected gain: audit clean before
DNSY-64 turns `pnpm audit --prod`/`--audit-level=high` into a gate. Risk: none for the override
(same major).

### F8. npm duplicates and version drift (Low, trivial effort)

Evidence: 52 of 527 packages in `pnpm-lock.yaml` exist in two or three versions. The avoidable
ones: `@typescript-eslint/*` 8.71.0 and 8.72.0 (7 packages) because `typescript-eslint` is pinned to
8.71.0 while `angular-eslint` 22.6.0 already resolves 8.72.0; `zod` 4.6.6/4.6.7 (`pnpm dedupe
--check` fails on exactly this); `lightningcss` 1.32/1.33 with all 12 platform binaries
(`tailwindcss` 4.3 vs `@angular/build`), `@babel/*` 7 and 8, `magic-string` 0.30/1.4.1/1.4.3.
`pnpm outdated`: `typescript-eslint` 8.71.0 -> 8.72.0, `@types/node` 24.19.2 -> 26.6.5,
`typescript` 6.0.3 -> 7.0.2. `openapi-typescript` 7.13.0 declares `peer typescript@^5.x` and gets
6.0.3 (pnpm warns on every install). `@angular/cli` carries `@modelcontextprotocol/{core,server}`
and `zod` (the `ng mcp` command): pure tooling weight in `node_modules`, nothing in `dist`.

Recommendation: bump `typescript-eslint` to 8.72.0 and run `pnpm dedupe` (-8 packages); keep
`@types/node` on 24 (matches the Node 24 runtime that `packageManager`/CI will use) and
`typescript` on 6.0 (Angular 22.2 supports TS >= 6.0 < 6.1; TS 7 is out of range); add
`pnpm.peerDependencyRules.allowedVersions = { "typescript": "6" }` for `openapi-typescript` or
bump it when a release accepts TS 6. Make `pnpm dedupe --check` part of `just web` once clean.
Expected gain: -8 lockfile entries, quiet installs. Risk: none.

### F9. Unused and misplaced dependencies (Low, trivial effort)

Evidence: `cargo machete --with-metadata`: `dnsy-resolver` declares `rustls-pki-types` and never
uses it (the code imports `rustls::pki_types`, the re-export). Grep cross-check of every
`[dependencies]`/`[dev-dependencies]` entry against `src/`, `tests/`, `benches/` of each crate found
no other unused entries, and no normal dependency that is only used under `#[cfg(test)]`. At
workspace level two `[workspace.dependencies]` entries are referenced by no manifest: `tower-http`
0.7.1 (the tree contains `tower-http` 0.6.11 only through reqwest; adding a crate that uses the
workspace entry would introduce a second version) and `criterion` 0.8.2 (no `benches/` exist yet).
In `tests/e2e`, `dnsy-core` is only used from `tests/`, not from `src/`. On the web side
`eslint-config-prettier` is a devDependency that `eslint.config.js` never imports (it uses
`@eslint/js`, `typescript-eslint`, `angular-eslint`); `@angular/compiler` is a runtime
dependency but is only needed at build time (AOT; nothing from it lands in `dist`).

Recommendation: remove `rustls-pki-types` from `dnsy-resolver`; delete the `tower-http` workspace
entry (re-add when a story needs it) or bump it to the version reqwest uses; keep `criterion` only
if the performance analysis (DNSY-63) files benchmark stories, otherwise delete; move `dnsy-core`
to `[dev-dependencies]` in `tests/e2e`; remove `eslint-config-prettier` (prettier runs separately
via `prettier --check`); move `@angular/compiler` to devDependencies. Expected gain: none in
bytes (all are already compiled or not compiled); keeps `cargo machete` clean so DNSY-64 can run
it as a gate. Risk: none.

### F10. Duplicate crate versions (Low, mostly upstream)

Evidence (`cargo tree -d`, Linux): `getrandom` 0.2.17 (only `ring`) and 0.4.3 (`rand`, `tempfile`,
`password-hash`, `phc`); `syn` 2.0.119 (`asn1-rs-derive`, `asn1-rs-impl`, `synstructure` 0.13,
`tracing-attributes`) and 3.0.9 (`serde_derive`, `thiserror-impl`, `tokio-macros`, `clap_derive`,
`utoipa-gen`, `displaydoc`, `yoke-derive`, `zerofrom-derive`, `zerovec-derive`, `synstructure`
0.14); `synstructure` 0.13.2 (`asn1-rs-derive`) and 0.14.0 (`yoke-derive`, `zerofrom-derive`).
With `--target all`: `hashbrown` 0.16/0.17 (wasm-only via `sqlite-wasm-rs`), `windows-sys`
0.52/0.60 and the `windows-targets`/`windows_*` family 0.52/0.53 (Windows only; `notify` vs
`mio`/`socket2`). Compile cost of the duplicates: `syn` 2 = 5.2 s and `syn` 3 = 4.8 s CPU in
release (3.8 s + 3.7 s debug); they run in parallel in the first seconds and are not on the
critical path.

Recommendation: F2 removes `synstructure` 0.13 and two of the four `syn` 2 users; F3 removes
`synstructure` 0.14 and the `yoke`/`zerofrom`/`zerovec` derives. `tracing-attributes` 0.1.31 is
the last `syn` 2 user and will move with tracing 0.1.x; `getrandom` 0.2 goes when `ring` adopts
0.3+/0.4 (no release since 2025-03, see F12). Keep `multiple-versions = "warn"` in `deny.toml`;
do not pin. Expected gain after F2+F3: `syn` 2 remains, `synstructure` duplicate gone. Risk: none.

### F11. Feature trimming with small, certain gains (Low, trivial effort)

Measured per feature family (crates exclusive to the dependency, from `cargo tree --prune`):

| Dependency | Today | Proposal | Exclusive crates | CPU in clean release |
| --- | --- | --- | --- | --- |
| `clap` | default + `derive` + `env` | `default-features = false`, `features = ["std","derive","env","help","usage","error-context"]` | 13 -> 6 (drops `anstream`, `anstyle-parse`, `anstyle-query`, `colorchoice`, `is_terminal_polyfill`, `utf8parse`, `strsim`) | 12.0 s family; `clap_builder` 5.8 s shrinks a little, the 7 crates are tiny |
| `tokio` | `full` | explicit `rt-multi-thread, macros, net, time, sync, io-util, fs, signal, process` (`process` is used only by `tests/e2e`; keep it there) | 0 (all optional deps are already needed by `signal`/`net`) | 8.4 s; a little less code to compile, no crates |
| `proptest` (dev, `dnsy-filter`) | default | `default-features = false`, `features = ["std"]` | 10 -> 3 (drops `rusty-fork`, `wait-timeout`, `quick-error`, `bit-set`, `bit-vec`, `regex-syntax`, `unarray`) | debug only: 10.6 s family, `proptest` itself 5.0 s |
| `insta` (dev) | default | `default-features = false` | 3 -> 1 (drops `console`, `similar` colours) | negligible |
| `tracing-subscriber` | default + `json` | keep (`ansi` is used for the terminal format, `json` for `LogFormat::Json`) | - | 6.7 s family |
| `axum` | default | keep (`json`, `query`, `form`, `matched-path`, `original-uri`, `tracing` are all exercised by the API) | - | - |
| `rusqlite` | `bundled` | keep; see F1 for the compile time | - | - |
| `serde_json` `raw_value` | via `utoipa-axum` | upstream choice, nothing to do | - | - |
| `rust-embed` | default, `embed-ui` only | consider `compression` (include-flate) to embed the 1.17 MB UI as ~0.35 MB | +2 crates | - |

Expected gain of the first four rows together: -14 crates across release and dev trees, a few
seconds of CPU, no wall-time change. Risk: none (all behaviour-neutral; clap colour output goes
away on the terminal, which the `dnsy` CLI tests do not assert).

### F12. Supply-chain risk ranking of direct dependencies (Medium, no code change)

Method: crates.io owner lists and release dates for the 39 workspace dependencies (all are at
their latest release as of 2026-10-21), `unsafe` sites counted by grep over the 202 third-party
crates on the Linux tree (130 contain `unsafe`; 11,146 sites in total; the workspace itself has
`unsafe_code = "forbid"`). Ranking by exposure (single owner, pseudonymous owner, release gap,
amount of `unsafe`, how deep it sits in the trust path):

| Rank | Crate | Why | Mitigation |
| --- | --- | --- | --- |
| 1 | `ring` 0.17.14 | one owner (`briansmith`), last release 2025-03-11 (19 months), the only crypto provider for TLS and DNSSEC, 230 `unsafe` sites + C/asm, still on `getrandom` 0.2 | Watch for a maintained release line; rustls' `aws-lc-rs` provider is the exit, at the cost of a C build and bigger binary. Keep `ring` pinned exactly in `[workspace.dependencies]`. |
| 2 | `libsqlite3-sys`/`rusqlite` | 3,581 + 386 `unsafe` sites (FFI bindings), bundled C | Unavoidable for SQLite; two owners; pin exact version (already). |
| 3 | `rust-embed` 8.13 | single pseudonymous owner (`ghost_5546`), proc-macro that reads the filesystem at compile time | Only compiled with `embed-ui`; alternative is a 30-line `include_bytes!` table generated by `build.rs` (the build script already exists). |
| 4 | `x509-parser` 0.18 | single owner, 20-crate subtree, parses attacker-controlled DER after the handshake | Remove (F2). |
| 5 | `reqwest`, `hyper-util`, `http-body-util` | single owner (`seanmonstar`), very widely used; reqwest drags the platform verifier and `openssl-probe` | F3 removes reqwest; hyper/hyper-util stay (hyper has an org owner). |
| 6 | `utoipa`/`utoipa-axum` 6.0 | single owner (`juhaku`), proc-macro (`utoipa-gen` 5.0 s), 5.3 s compile of `utoipa` itself, 446 KiB `.text` | Keep (OpenAPI drift gate depends on it); its runtime footprint can be trimmed in a later pass by generating the spec at build time only (feature-gate `utoipa` behind the `gen-openapi` binary). |
| 7 | `tokio` | 1,170 `unsafe` sites, org-owned, security policy in place | Keep. |
| 8 | `ipnet`, `tempfile`, `thiserror`, `time` | single owner each, ubiquitous, tiny attack surface | Keep; `time` disappears with F2. |

Everything else is org-owned (`rustls`, `tokio-rs`, `serde-rs`, `RustCrypto`, `rust-random`,
`clap-rs`, `notify-rs`, `toml-rs`, `rust-bus`). No crate in the tree is yanked, unmaintained or
unsound according to the RustSec database (`cargo deny check advisories`, `cargo audit`, both clean
on 2026-10-21).

### F13. Licence compatibility (Low, nothing to fix)

Evidence: `cargo deny check licenses` passes. Distribution of the 288 third-party packages:
`MIT OR Apache-2.0` (and spellings) 193, `MIT` 48, `Unicode-3.0` 18 (ICU, gone with F3),
`Apache-2.0` 4, `ISC` 4, `CDLA-Permissive-2.0` 2 (`webpki-roots`), `BSD-3-Clause` 1 (`subtle`),
`MIT AND BSD-3-Clause` 1 (`matchit`), `Apache-2.0 AND ISC` 1 (`ring`), `Zlib` 1 (`foldhash`),
`CC0-1.0` 1 (`notify`), `Apache-2.0 OR BSL-1.0` 1 (`ryu`, satisfied by Apache-2.0),
`MIT OR Apache-2.0 OR LGPL-2.1-or-later` 1 (`r-efi`, UEFI only, satisfied by MIT). All compatible
with Apache-2.0 redistribution. `deny.toml` allows `BSD-2-Clause` and `MPL-2.0` that no crate uses
(cargo-deny warns); the spec's planned `clarify` entry for `ring` is unnecessary because 0.17.14
declares `Apache-2.0 AND ISC` itself.

Recommendation: drop the two unused allowances to keep the policy exact; nothing else.

### F14. Lockfile hygiene (Low, nothing to fix)

`Cargo.lock` is version 4, committed, crates.io-only (`unknown-registry`/`unknown-git` = deny, no
`git` sources, no `[patch]`), 308 packages. `web/pnpm-lock.yaml` is lockfileVersion 9.0,
`packageManager` pins `pnpm@10.16.0`, `just web` installs with `--frozen-lockfile`. No `.npmrc`,
`.nvmrc` or `.node-version` exist; DNSY-64 should pin Node (24) in the workflow rather than add a
file. `web/dist` and `web/node_modules` are git-ignored.

### F15. Build-time hot spots inside the workspace (Medium, follow-up for the cohesion pass)

Evidence (clean release): `dnsy-api` 15.2 s (the largest unit after the SQLite script), `dnsy`
lib 9.2 s + bin 6.7 s, `dnsy-config` 6.0 s, `dnsy-proto` 4.7 s; workspace crates are 54 of the
353 CPU seconds. In the debug all-targets build the `dnsy-api` test binary is the single largest
unit (17.1 s) and `dnsy-api` lib the second (13.6 s); the workspace is 172 of 383 CPU seconds
there. `dnsy_api` is also 23 % of the `.text` section (3.4 MiB), more than the next five crates
combined: axum handler monomorphisation plus `utoipa` schema code for every route. `dnsy-config`
spends its time in two monomorphised `toml::Value::deserialize_any` instantiations for the
`Config` visitor (28 KiB each in the binary). These are not dependency problems but they define
the serial tail of every release build (25 s after SQLite) and most of the incremental cost
(`touch crates/dnsy-core/src/lib.rs` -> 21 s release, 2.2 s debug).

Recommendation: leave to the cohesion analysis (DNSY-59) or a later pass; cheap levers are
splitting the `dnsy-api` route modules into a separate test crate and deserialising config through
`toml::from_str` into `serde::Deserialize` directly rather than through `toml::Value`.

### F16. `rust-embed` and the UI payload (Low)

`embed-ui` adds 5 crates (`rust-embed`, `rust-embed-impl`, `rust-embed-utils`, `mime_guess`,
`unicase`) and 1.21 MB to the binary for a 1.17 MB `web/dist`. Serving is already
pre-compressed-friendly; if binary size becomes a release concern, `rust-embed`'s `compression`
feature or pre-gzipped assets in `web/dist` bring that to about 0.35 MB. Not a priority next to
F4's 7.4 MB.

### F17. Tooling-only dependencies (Low, informational)

`mdbook` 0.5.4 is invoked by `just docs` and pinned in the justfile, not in `Cargo.toml`;
`cargo-nextest`, `cargo-llvm-cov`, `cargo-deny`, `jq`, `just` are required tools, not
dependencies. `rcgen` is dev-only in every crate and a normal dependency only in the `dnsy-e2e`
harness, which is excluded from release builds. `notify` is a genuine runtime dependency (zone
hot reload and certificate reload in `dnsy-server`), 6 crates, 7.0 s CPU, 83 KiB; the spec asks
for it and no cheaper crate exists, so it stays.

## 5. Proposed follow-up stories (priority order)

Estimates are story points on the project's scale (1 = under an hour, 2 = half a day, 3 = a day,
5 = two to three days).

1. **Add a release profile (strip, thin LTO, one codegen unit)** - est. 1
   AC: `[profile.release]` in `Cargo.toml` with `strip = true`, `lto = "thin"` and
   `codegen-units = 1`; `just build` produces a `dnsy` binary under 18 MB without the UI (baseline
   27.78 MB); `just ci` green. Document the sizes and the `panic` decision in
   `docs/book/src/install.md`.

2. **Replace `x509-parser` with an in-house subject/SAN extractor** - est. 2
   AC: `x509-parser` and `time` removed from `[workspace.dependencies]` (time stays dev-only if
   still needed by `tests/mtls.rs`); `cargo tree -p dnsy -e normal` shows at most 190 crates; the
   mTLS log line still shows CN and DNS SANs; `crates/dnsy-server/tests/mtls.rs` passes unchanged.

3. **Cut the `libsqlite3-sys` build-script time** - est. 2
   AC: `cargo build --timings --release -p dnsy` from clean on an idle 24-core machine shows the
   `libsqlite3-sys` build script under 25 s (baseline 45.7 s) and total wall time at least 15 s
   lower than the 74 s baseline; query-log insert throughput within 5 % of baseline; decision and
   numbers recorded in `docs/book/src/contributing.md`.

4. **Replace `reqwest` with a hyper-based fetcher in `dnsy-filter` and `cacheflush`** - est. 5
   AC: `reqwest` is no longer a dependency of any `crates/*` manifest (the e2e harness may keep it);
   `cargo tree -p dnsy -e normal` contains none of `url`, `idna`, `icu_*`,
   `rustls-platform-verifier`, `openssl-probe`; all existing blocklist-fetch tests in
   `crates/dnsy-filter/src/source_tests.rs` (conditional requests, redirect refusal, size cap,
   timeout) and the e2e cache tests (`tests/e2e/tests/cache_api.rs`) pass.

5. **Web dependency hygiene** - est. 1
   AC: `typescript-eslint` bumped to the version `angular-eslint` resolves, `pnpm dedupe --check`
   clean, `eslint-config-prettier` removed, `@angular/compiler` moved to devDependencies,
   `openapi-typescript` peer warning silenced or resolved, vite advisory gone from `pnpm audit`;
   `just web` green.

6. **Angular budget and bundle guard** - est. 1
   AC: `initial` warning budget set to 320 kB with the measured composition documented in
   `docs/book/src/web-ui.md`; an `anyComponentStyle` budget added; `ng build` emits no budget
   warning; `just web` green.

7. **Cargo manifest hygiene** - est. 1
   AC: `cargo machete` reports nothing; `tower-http` and `criterion` removed from
   `[workspace.dependencies]` (or `criterion` kept with a first benchmark); `dnsy-core` is a
   dev-dependency of `tests/e2e`; `deny.toml` allow-list contains only licences that occur;
   `cargo deny check` prints no warnings.

8. **Feature trimming: clap, tokio, proptest, insta** - est. 1
   AC: features set as in F11; `cargo tree --workspace` shows at least 14 fewer crates than the
   238 baseline; `dnsy --help` output and the CLI tests unchanged apart from colour.

9. **Decide the fate of the three.js login scene** - est. 3 (if replaced)
   AC: either an ADR in `docs/book/src/web-ui.md` accepting the 137 kB lazy chunk with the
   measurements from F5, or the scene re-implemented without `three`, `three` and `@types/three`
   removed, and the `login-scene` Playwright specs passing.

10. **Supply-chain watch items** - est. 1
    AC: `docs/book/src/security.md` gains a "third-party crates" section listing `ring`'s release
    status and the aws-lc-rs exit path, the `rust-embed` single-owner note, and the policy that
    `[workspace.dependencies]` pins exact versions for crypto crates; `cargo audit` added to
    `just check` (non-blocking until DNSY-64 makes it a gate).

Stories 1, 2, 5, 6, 7, 8 touch disjoint files and can run in one wave; 3 and 4 touch
`dnsy-filter`/`dnsy-store` and should run after story 2 lands.

## 6. Proposed Dependabot configuration (for DNSY-64)

Three ecosystems: `cargo` at `/`, `npm` at `/web` (there is no manifest in `/web/e2e`),
`github-actions` at `/`. Weekly, grouped minor/patch so one PR per group per week; majors stay
individual. Ignore rules keep the toolchain-coupled pins where a bump needs a human decision.

```yaml
version: 2
updates:
  - package-ecosystem: cargo
    directory: /
    schedule: { interval: weekly, day: monday }
    open-pull-requests-limit: 5
    commit-message: { prefix: "⬆️" }
    groups:
      tokio-stack:
        patterns: [tokio, hyper, hyper-util, http-body-util, axum, tower, futures-util, h2]
        update-types: [minor, patch]
      tls:
        patterns: [rustls, tokio-rustls, rustls-pki-types, webpki-roots, ring, rcgen, x509-parser]
        update-types: [minor, patch]
      serde:
        patterns: [serde, serde_json, toml]
        update-types: [minor, patch]
      crypto-and-auth:
        patterns: [argon2, zeroize, rand, sha2, subtle, base64]
        update-types: [minor, patch]
      dev-and-test:
        patterns: [proptest, insta, criterion, tempfile]
        update-types: [minor, patch]
      cargo-minor-patch:
        patterns: ["*"]
        update-types: [minor, patch]
    ignore:
      - dependency-name: ring          # exact pin, security review before bumping
        update-types: [version-update:semver-major]

  - package-ecosystem: npm
    directory: /web
    schedule: { interval: weekly, day: monday }
    open-pull-requests-limit: 5
    commit-message: { prefix: "⬆️" }
    groups:
      angular:
        patterns: ["@angular/*", "@angular-eslint/*", angular-eslint]
        update-types: [minor, patch]
      lint-and-format:
        patterns: [eslint, "@eslint/*", typescript-eslint, prettier]
        update-types: [minor, patch]
      test:
        patterns: [vitest, "@vitest/*", jsdom, "@playwright/test", "@axe-core/playwright"]
        update-types: [minor, patch]
      tailwind:
        patterns: [tailwindcss, "@tailwindcss/*", postcss]
        update-types: [minor, patch]
      three:
        patterns: [three, "@types/three"]
      types-and-tooling:
        patterns: ["@types/node", openapi-typescript, tslib, rxjs]
        update-types: [minor, patch]
    ignore:
      - dependency-name: typescript      # bound to the Angular major (22.2 -> TS 6.0.x)
        update-types: [version-update:semver-major, version-update:semver-minor]
      - dependency-name: "@types/node"   # tracks the Node major the pipeline runs on
        update-types: [version-update:semver-major]

  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly, day: monday }
    commit-message: { prefix: "👷" }
    groups:
      actions:
        patterns: ["*"]
```

Notes for the pipeline story: Dependabot PR titles must still match `DNSY-{n}: {emoji} {Sentence}`
(DNSY-65), so either the title check allows a `⬆️`-prefixed Dependabot form or a tracking story key
is configured in the prefix; `cargo deny check` and `pnpm audit` should run on those PRs; the
`cargo` ecosystem updates `Cargo.lock` only (every version is a caret range in
`[workspace.dependencies]`), so minor/patch groups will mostly be lockfile-only PRs.

## Appendix A. Commands

```
cargo tree -p dnsy -e normal --prefix none --no-dedupe | sort -u | wc -l        # 210
cargo tree -p dnsy -e normal --prefix none --no-dedupe --features embed-ui | ...  # 215
cargo tree --workspace --prefix none --no-dedupe | sort -u | wc -l              # 238
cargo tree -p dnsy -d -e normal,build --depth 0                                  # duplicates
cargo tree --workspace -i <crate>                                                # banned crates, parents
cargo tree -p dnsy -e normal --prefix none --no-dedupe --prune <crate>           # exclusive subtree size
cargo tree -p dnsy-proto -e normal,build                                         # zero deps
cargo deny check licenses | advisories | bans | sources
cargo audit
cargo machete --with-metadata
cargo build --release -p dnsy --timings                                          # clean, then touch + rebuild
cargo build --workspace --all-targets --timings
cargo bloat --release -p dnsy --crates -n 30 ; cargo bloat --release -p dnsy -n 20
CARGO_PROFILE_RELEASE_LTO=... CARGO_PROFILE_RELEASE_STRIP=true cargo build --release -p dnsy
cd web && pnpm install --frozen-lockfile && pnpm exec ng build --stats-json
cd web && pnpm outdated ; pnpm audit ; pnpm dedupe --check ; pnpm ls --depth 0
esbuild <import-list>.mjs --bundle --minify --format=esm                        # three.js experiment
```

## Appendix B. Raw compile-time ranking (clean release, idle machine, CPU seconds per unit)

`libsqlite3-sys` build script 45.7; `dnsy-api` 15.2; `ring` build script 10.3; `dnsy` lib 9.2;
`tokio` 8.4; `dnsy` bin 6.7; `dnsy-config` 6.0; `clap_builder` 5.8; `rustls` 5.7; `num-bigint`
5.4; `utoipa` 5.3; `syn` 2 5.2; `data-encoding` 5.2; `utoipa-gen` 5.0; `syn` 3 4.8; `time` 4.8;
`dnsy-proto` 4.7; `h2` 4.3.

Family totals (CPU s, release `-p dnsy` / debug `--workspace --all-targets`): workspace crates
54.0 / 172.2; SQLite 48.1 / 13.0; x509-parser family 34.5 / 21.0; serde + json + toml 28.3 / -;
axum + hyper + http + h2 27.9 / -; ring + rustls 22.3 / -; ICU + idna + url 21.0 / 14.4; tokio
16.9 / 12.1; clap 12.0 / 9.1; argon2 family 11.5 / -; utoipa 10.9 / 7.9; syn (both) 10.0 / 10.1;
notify 7.0 / 4.3; tracing-subscriber 6.7 / -; reqwest + hyper-rustls + platform verifier 6.6 /
3.2; proptest family (dev only) - / 10.6.

Wall-clock reference points: clean release 74.2 s; clean debug `-p dnsy` 24.1 s; clean debug
all-targets 38.1 s; incremental release after a `dnsy-core` change 21.0 s, after a `main.rs`
change 7.9 s; incremental debug 2.2 s / 1.8 s / 0.6 s for `dnsy-core` / `dnsy-api` / `main.rs`.

## Appendix C. `cargo bloat --crates` (release, no UI; `.text` = 14.6 MiB)

`dnsy_api` 3.4 MiB (23.3 %); unknown/C (SQLite) 1.6 MiB; `std` 1.4 MiB; `rustls` 720 KiB;
`reqwest` 662 KiB; `dnsy` 661 KiB; `dnsy_zone` 613 KiB; `utoipa` 446 KiB; `h2` 430 KiB; `tokio`
399 KiB; `dnsy_dnssec` 328 KiB; `dnsy_config` 322 KiB; `clap_builder` 310 KiB; `ring` 305 KiB;
`hyper` 232 KiB; `dnsy_resolver` 163 KiB; `serde_json` 154 KiB; `dnsy_server` 152 KiB;
`dnsy_proto` 144 KiB; `toml` 135 KiB; `dnsy_filter` 130 KiB; `dnsy_engine` 115 KiB;
`libsqlite3_sys` 111 KiB; `dnsy_store` 105 KiB; `x509_parser` 104 KiB; `hyper_util` 94 KiB;
`dnsy_observe` 93 KiB; `notify` 83 KiB; `webpki` 81 KiB; `dnsy_auth` 72 KiB; 102 more crates
1,019 KiB.
