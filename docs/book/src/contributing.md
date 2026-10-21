# Contributing

Workflow, conventions and the `just ci` gate are described in `AGENTS.md` in the repository.
This page covers the end-to-end tests.

Pull request titles must read `DNSY-{n}: {emoji} {Sentence}` (several stories: `DNSY-12, DNSY-13: ...`).
The `pr-title` workflow (`.github/workflows/pr-title.yml`) checks this on every open, edit and push, and
prints the expected shape when the title does not match.

## Release profile and dependencies

`[profile.release]` in the root `Cargo.toml` sets `lto = "fat"`, `codegen-units = 1`,
`strip = true`, `overflow-checks = true` and keeps `panic = "unwind"` (the server has no
`catch_unwind`; `abort` would turn any panic reachable from hostile input into an outage of the
whole resolver). Measured on the release build with the UI embedded:

| | before | after |
| --- | --- | --- |
| `dnsy` binary | 28.99 MB | 17.22 MB |
| clean release build | 80 s | 180 s |
| `cargo tree --workspace` unique crates | 316 | 279 |
| `cargo tree -p dnsy` (normal) | 277 | 240 |
| UI `dist` text assets | 1.11 MB | 0.28 MB brotli (0.32 MB gzip) |

`libsqlite3-sys` at `opt-level = 2` cuts its clean build from about 65 s to 30 s, but writer
throughput on the shared development host could not be shown within 5 % of the default (the
numbers varied by more than 2x between identical runs), so it is not enabled. Revisit with a
quiet machine.

Dependencies are declared once in `[workspace.dependencies]` with only the features the code uses
(`tokio`, `clap`, `tracing-subscriber`, `proptest`, `insta`). Keep it that way: check
unused dependencies with `cargo machete` before adding a crate, and do not add `x509-parser`,
`time` or `tower-http` back for a convenience.

`web/scripts/compress-dist.mjs` runs as `postbuild` after `pnpm build` and writes `.br` and `.gz`
next to each text asset under `web/dist/dnsy/browser`.

## End-to-end tests

The crate `tests/e2e` (`dnsy-e2e`) starts the real `dnsy` binary with a temporary configuration
and talks to it over the wire, the way a client would. It is excluded from `just test` and
`just cov-rust` (coverage measures the crates, and these tests need the built binary) and has its own
recipe, which `just ci` runs last:

```sh
just e2e                                  # build target/debug/dnsy, run everything in parallel
cargo nextest run -p dnsy-e2e --test transports mtls   # a subset, once the binary is built
```

The harness looks for the binary next to the test executables (`<target>/debug/dnsy`); it builds
it with `cargo build -p dnsy` when it is missing, and `DNSY_BIN` points it at another binary. After
changing server code rebuild first (`cargo build -p dnsy`), or use `just e2e`, which always does.

### What `Harness::start(opts)` does

1. Creates a temp directory with the configuration, zone files, a blocklist file and a throwaway
   PKI (`rcgen`): a server CA and certificate (valid for `127.0.0.1`), a client CA, and three client
   certificates: valid, expired and signed by an untrusted CA.
2. Starts a scriptable fake upstream (`FakeUpstream`) when `opts.upstream` is set.
3. Creates an admin user and two tokens (`dns:query` for DoH, admin for the API) with the CLI.
4. Runs `dnsy serve --ready-file ...` with every listener on port 0 and waits (polling, with a
   deadline) for the ready file, which holds the bound addresses.
5. With mTLS on, registers the valid client certificate's fingerprint through the API.

Everything is per test: its own temp directory, its own ports and database, so tests run in
parallel (nextest runs each test in its own process). Dropping the `Harness` kills the server;
`terminate()` sends SIGTERM and waits for a clean exit. `signal("HUP")`, `logs()`,
`write_zone()`, `api_send()` and `new_token()` cover the rest of what a test usually needs.

### Clients and fixtures

The clients live in the crate and use `dnsy-proto` as the codec: `udp_exchange` / `udp_raw`,
`Framed` for TCP and DoT (`Framed::connect_dot` with or without a client certificate), and
`DohClient` (HTTP/2 or HTTP/1.1; GET, POST, bearer or path tokens, arbitrary requests).
`FakeUpstream::on(name, type, Reply)` scripts answers, NXDOMAIN, NODATA, rcodes, drops, delays,
garbage and wrong-id responses and counts what it was asked; `serve_signed_root` serves a signed
root zone whose DS you pass as a trust anchor. `zones::example_zone()` is the zone most tests use.

### Writing a test

```rust,ignore
#[tokio::test]
async fn my_case() {
    let h = Harness::start(Opts::default().zone("example.test.", example_zone())).await;
    let r = udp_exchange(h.udp, &query("www.example.test.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
}
```

- Be deterministic: never sleep for a fixed time to wait for the server. Poll with
  `eventually(deadline, "what", || async { ... })`, or use `wait_for_log`. The only fixed waits are
  the short silence windows of negative checks (a dropped UDP query, a log line that must not
  repeat).
- Bind nothing to a fixed port. Use the addresses on the harness.
- The product has no clock hook, so TTL tests use 1 second TTLs and poll for the effect.
- Tools such as `dig` and `kdig` are optional: skip with a message when they are missing
  (`tests/interop.rs`).
- Put secrets in neither assertions' messages nor logs: tests that look for leaked tokens assert on
  the server log and on the query log.

### Testing the REST API and the cache

`h.rest()` returns an `Api` client for the management API. Every request states its credential
explicitly (`Auth::None`, `Bearer`, `Session`, and session variants without or with a wrong CSRF
header), so tests can assert 401/403 mappings; `Resp::problem(status)` checks the RFC 9457 shape
and `Resp::ok(status)` returns the JSON body. `Api::login`, `create_user` and `token_for` build
sessions, users and role-limited tokens (the harness admin is `e2e` / `e2e-password-1234`, its
token is `h.api_token`). `Req::stream()` and `Stream::next_event` read server-sent events.
`Opts::no_users` starts a server without users for the bootstrap flow (`h.bootstrap_code()`), and
`Opts::prefetch` turns cache prefetch on.

- A change made through the API is asserted on the DNS path too, with `eventually`: the zone
  answer, the REFUSED, the NXDOMAIN with its extended error.
- Cache tests use 1 to 3 second TTLs (there is no clock hook) and observe the cache through
  `GET /cache` counters and the upstream's query counts; clamps show on cached answers, not on
  the first (miss) answer.
- Query log and stats are written asynchronously: poll them until the expected entries appear.

Suites: `protocol` (UDP, TCP, EDNS, malformed input, hot reload), `transports` (DoT, mTLS, DoH),
`policy` (ACL, rate limit, blocklists), `resolver` (forwarding, cache, failures, serve-stale,
validation smoke test), `lifecycle` (SIGHUP, SIGTERM) and `interop`; the REST suites `rest_auth`,
`rest_errors`, `rest_zones`, `rest_policy` and `rest_observe`, and the cache suites `cache_api`,
`cache_ttl` and `cache_stale`.

The DNSSEC suites are `dnssec_validation` (forwarding path: modes, AD/CD/DO, EDE codes, negative
trust anchors, mode changes), `dnssec_signing` (signing through the REST API, answers over UDP,
TCP, DoT and DoH, denial, wildcards, DS export, BIND export) and `dnssec_lifecycle` (a second
instance validating the first, key rollovers, the clock-sanity guard, `delv`/`dig` interop and an
ignored live test against the real root). They use `dnsy_e2e::dnssec`: `Tree::build` creates a
signed root with signed or unsigned zones below it (NSEC, NSEC3, opt-out, expired or future
signatures, missing, unsupported or mismatching DS, colliding keys) and `tree.serve(&upstream)`
makes the fake upstream answer from it; `Tree::answer` returns a response you can forge and script
with `upstream.on`. `validate_answer` runs the `dnsy-dnssec` validator on a server's own answer.
The clock guard test patches the build timestamp in a copy of the binary (`Opts::binary`), since a
child process cannot be given another clock.

## Benchmarks

The crate `tests/bench` (`dnsy-bench`, not published, excluded from `just test` and the coverage
gate like `dnsy-e2e`) holds the performance tools:

- `just bench`: the scenario runner (`bench` binary). It starts the release `dnsy` (through
  `DNSY_BIN`) with the e2e harness and a scripted upstream and prints QPS, p50 and p99 for UDP
  hit and miss, TCP and DoH. It lifts the per-client connection and UDP in-flight limits because
  all load clients share one source address; every row must report 0 errors.
- `loadgen`: a closed-loop load generator for any server over UDP or TCP (`--clients`,
  `--pipeline`, `--count` names cycled for cache hits, `--unique` for misses).
- `fakeup`: a fast multi-task UDP upstream answering every name (`nx*` gets NXDOMAIN).
- `just bench-micro`: criterion micro-benchmarks (`benches/micro.rs`).

Performance stories paste the `just bench` table into their PR. Run it on an otherwise idle
machine and pin CPUs with `taskset` when comparing before and after.

## Browser end-to-end tests

The Playwright suite in `web/e2e` drives the real UI in Chromium against a real `dnsy` (built with
`--features embed-ui`, started with a temporary configuration, free ports and a fake UDP upstream
written in the test support code). It covers sign-in and first-admin setup, the throttle, CSRF and
session expiry, the no-WebGL and reduced-motion login, navigation, 404 and the auth guard, the
dashboard after real DNS queries, zones and records (validation, ETag conflict, BIND export),
the query log (filters, live tail), filtering and ACL rules changing DNS answers, upstream groups,
client certificates, settings, cache flush, users and roles, tokens (secret shown once), password
change, the DNSSEC tab, mascot states (simulated with route interception), responsive checks at
360 and 1280 px, keyboard use and an axe scan (no serious or critical violations). Any console
CSP violation fails the test.

```sh
just e2e-ui                       # build UI and binary, install Chromium if missing, run everything
cd web && DNSY_BIN=... pnpm e2e   # run again without rebuilding
cd web && pnpm exec playwright test zones --headed   # a subset, with a visible browser
cd web && pnpm exec playwright show-report           # HTML report of the last run
```

Chromium is installed once into the Playwright cache (`pnpm exec playwright install chromium`);
the recipe does it for you. Only Chromium runs: WebKit needs system libraries not present on
every machine and Firefox lacks the clipboard permissions and console messages two tests use.
`DNSY_BIN` points at another binary (it must include the embedded UI); without it the suite uses
`$CARGO_TARGET_DIR/debug/dnsy`. A debug build reads `web/dist` from disk, so rebuild the web app
(`pnpm build`) after changing it.

How it is organised:

- A global setup starts one shared server with the users `admin`, `operator` and `viewer` (password
  `e2e-password-1234`) and stores their signed-in sessions, so most tests start signed in. Pick a
  role with `test.use({ storageState: roleState('viewer') })`.
- Tests that change global state (settings, ACL, filtering, cache, counts) start their own server
  with the `freshServer` fixture and sign in with `sessionFor`; zones use unique names, so tests
  run in parallel. Never log an API client in with the page's cookie: logging in with a session
  cookie ends that session (`Api.login` uses an empty jar for that reason).
- `support/dns.ts` sends hand-built UDP queries; `support/upstream.ts` answers every `A` query
  with `192.0.2.7` (names starting `nx.` get NXDOMAIN) and counts the queries it saw.
- No fixed sleeps: locators auto-wait and `expect.poll` / `toPass` wait for server-side effects.
- Traces and screenshots are kept only for failing tests (`web/test-results`, not committed).


## Documentation screenshots

The screenshots in `docs/book/src/images/` come from a seeded demo, not from hand-made captures:

```sh
just build                                         # or cargo build -p dnsy --features embed-ui
scripts/demo/run.sh /tmp/dnsy-demo target/release/dnsy &    # fake upstream, zones, rules, a signed zone, traffic
node scripts/demo/capture.mjs /tmp/dnsy-shots      # Playwright at 1280 px (needs `pnpm exec playwright install chromium` in web/)
python3 scripts/demo/optimize.py /tmp/dnsy-shots docs/book/src/images
```

Keep each image to a few hundred KB at most, write outputs outside the repository, and never commit
logs. `just docs` checks the book (`mdbook test`), and the `config_reference_lists_all_keys` test in
`dnsy-config` fails when the configuration reference and the schema disagree.

## Fuzzing

Two targets cover untrusted input. Neither is part of `just ci`.

| Target | Crate | What it feeds |
| --- | --- | --- |
| `fuzz_decode` | `crates/dnsy-proto/fuzz` | `Message::formerr_for`, `decode`, `encode` at five limits, `encode_padded`, `set_ede`, canonical RDATA, presentation form and the decode-encode-decode round trip |
| `fuzz_validate` | `crates/dnsy-dnssec/fuzz` | `Validator::validate` on a mutated response with mutated DS and DNSKEY answers from the fetcher, against a trust anchor that signs the seeds |

```sh
just fuzz                          # fuzz_decode, one hour, libFuzzer (nightly + cargo-fuzz)
just fuzz fuzz_validate 600        # the validator target for ten minutes
just fuzz-stable fuzz_decode 600   # pinned stable toolchain: std-only mutation fuzzer
```

`just fuzz` needs `rustup toolchain install nightly` and `cargo install cargo-fuzz`; nothing else
in the repository needs nightly. `just fuzz-stable` runs the same functions through a small
mutation engine (bit flips, interesting values, splices, truncation, 16-bit field nudges, random
buffers) with `overflow-checks` on and no coverage feedback; it is what runs where nightly is not
installed. The fuzz crates are not workspace members (their `Cargo.lock` stays out of the main
one) and `dnsy-proto` itself keeps zero dependencies. A crashing input is written to the fuzz
directory's `crashes/` (stable) or `artifacts/` (libFuzzer); fix it, and add the input as a unit
test next to the code it broke. The committed starting corpora are in `fuzz/corpus/<target>/`.

### Recorded runs

| Date | Toolchain | Target | Iterations | Panics |
| --- | --- | --- | --- | --- |
| 2026-10-21 | stable 1.99.1, `fuzz-stable`, 3 processes x 25 min | `fuzz_decode` | 2 658 869 248 | 0 |
| 2026-10-21 | stable 1.99.1, `fuzz-stable`, 2 processes x 25 min | `fuzz_validate` | 315 691 008 | 0 |

The libFuzzer one-hour runs need a nightly toolchain, which the build machines do not have; the
rows above are the stable mutation runs, shorter and without coverage guidance. Add a row here
after each `just fuzz` run.

## Code coverage

Coverage is a merge gate. `just ci` runs `just cov-rust` and the web gate (inside `just web`).

```sh
just cov        # Rust gate, then web gate
just cov-rust   # cargo llvm-cov via nextest, per-crate table, HTML report
just cov-web    # ng test --coverage (Vitest, v8)
```

### What is measured

- **Rust:** line coverage from `cargo llvm-cov nextest --workspace --exclude dnsy-e2e --exclude dnsy-bench`, that is
  unit and integration tests. The end-to-end suites (`just e2e`, `just e2e-ui`) are **not**
  counted: they spawn the real binary, so the instrumentation would have to follow child processes,
  and a gate that depends on timing-sensitive wire tests would be flaky. The e2e suites are
  additional safety, not a way to reach the numbers.
- **Web:** `ng test --coverage` over `web/src`. The thresholds live in `web/angular.json`.
- **Exclusions:** none. No `#[cfg(coverage)]`, no ignore regions and no ignore-filename regex;
  `main.rs` glue and the `gen-openapi` binary are measured like everything else.

### Gates

| Scope | Metric | Floor |
| --- | --- | --- |
| Rust workspace | lines | 80% |
| every crate | lines | 80% |
| `dnsy-proto`, `dnsy-dnssec` | lines | 90% |
| web | lines, statements, functions | 80% |
| web | branches | 70% |

The floors are set in the `justfile` (`cov-rust`) and enforced by `scripts/cov-crate-gates.sh`,
which also prints the table. Percentages are exact, so 89.99% fails a 90% gate. Raise a floor in
the same change that earns it; never lower one to merge.

### Reading the report

`just cov-rust` ends with one row per crate (`lines`, `covered`, `percent`, `min`, `ok`/`FAIL`) and
a `workspace` total. For the per-file view open `target/llvm-cov/html/index.html`, or list the
uncovered lines of a file from the last run:

```sh
cargo llvm-cov report --show-missing-lines | grep dnsy-server
```

The web table is printed by Vitest (`% Stmts`, `% Branch`, `% Funcs`, `% Lines`, uncovered line
numbers per file).

### Filling gaps

Look at uncovered lines first, then ask what behaviour they encode: error paths, limits, parsers
fed malformed input, auth, throttles, ACLs, redaction, the DNSSEC validator. Write a test that
asserts that behaviour (the right error, nothing added, memory bounded), not one that merely calls
the function. Put new tests in their own `*_tests.rs` module or `tests/` file. Untestable code
(process glue) stays measured and is justified in the PR, not hidden.
