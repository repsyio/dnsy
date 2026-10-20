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

Suites: `protocol` (UDP, TCP, EDNS, malformed input, hot reload), `transports` (DoT, mTLS, DoH),
`policy` (ACL, rate limit, blocklists), `resolver` (forwarding, cache, failures, serve-stale,
validation smoke test), `lifecycle` (SIGHUP, SIGTERM) and `interop`.
