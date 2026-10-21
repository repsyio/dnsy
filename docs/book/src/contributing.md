# Contributing

Workflow, conventions and the `just ci` gate are described in `AGENTS.md` in the repository.
This page covers the end-to-end tests.

## End-to-end tests

The crate `tests/e2e` (`dnsy-e2e`) starts the real `dnsy` binary with a temporary configuration
and talks to it over the wire, the way a client would. It is excluded from `just test` and
`just cov` (coverage measures the crates, and these tests need the built binary) and has its own
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

```rust
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

