# Architecture

DNSY is a Cargo workspace of small crates behind one binary. Dependencies point one way: the
vocabulary crate `dnsy-core` is used by everything, `dnsy-proto` (the wire format, no runtime
dependencies) feeds the DNS crates, and the binary `dnsy` wires them together.

```text
 clients                    dnsy (one process)                         upstreams
                  +---------------------------------------+
 UDP/TCP :53 ---> |  dnsy-server  listeners (UDP TCP DoT DoH)
 DoT     :853 --> |        |                                |
 DoH     :443 --> |        v                                |
                  |  dnsy-engine  pipeline: ACL, rate limit, sanity, filter,
                  |        |      local zones, cache, upstreams, validation,
                  |        |      scrubbing, response-IP policy, shaping
                  |        |---> dnsy-zone      JSON zones, signing, lookup
                  |        |---> dnsy-filter    blocklists, ACL rules
                  |        '---> dnsy-resolver  cache, load balancing ----> 1.1.1.1 ...
                  |                  '--- dnsy-dnssec  validation          9.9.9.9 ...
                  |  dnsy-observe  query log + stats   dnsy-auth  users, tokens
                  |  dnsy-store    SQLite              dnsy-config  TOML schema
 browser, curl -> |  dnsy-api      REST + OpenAPI + embedded web UI :5380
                  +---------------------------------------+
```

| Crate | Role |
| --- | --- |
| `dnsy-core` | shared vocabulary types (transport, principal, role, scope, DNSSEC status, key role and state) and the one `Clock` trait (`SystemClock`; `ManualClock` behind the `test-util` feature) |
| `dnsy-proto` | wire format, names, records, EDNS, canonical form |
| `dnsy-dnssec` | validation, signing, key handling over `ring` primitives |
| `dnsy-keys` | the DNSSEC key store: encrypted private keys, rollover, backup bundles |
| `dnsy-config` | TOML schema, defaults, validation |
| (config consumers) | Only `dnsy-engine` (its builder), `dnsy-api` and `dnsy` depend on `dnsy-config`. The shared enums `Validation` and `BlockMode` live in `dnsy-core` (config re-exports them, serde strings unchanged); the resolver owns `CacheOptions` and `DnssecOptions`, which the engine builder fills from `[cache]` and `[dnssec]`; `dnsy_dnssec::TrustAnchor::parse` parses trust anchors (config only checks the shape, `EngineBuilder::from_config` and `dnsy config check` parse fully); the key store takes the passphrase environment variable name as a parameter |
| `dnsy-store` | SQLite handle and migrations |
| `dnsy-auth` | users, roles, tokens, sessions |
| `dnsy-observe` | query events, query log, statistics |
| `dnsy-zone` | zone model, JSON files, hot reload, authoritative lookup, signing (`ZoneSigning` over the `dnsy-keys` store) |
| `dnsy-resolver` | upstream client, cache, load balancing, validating forwarder |
| `dnsy-filter` | blocklists, allowlist, stored ACL rules and list sources; fetching them is the `fetch` feature (ACL evaluation and the rate limiter live in `dnsy-engine`) |
| `dnsy-engine` | the `Handler` trait and the request pipeline |
| `dnsy-server` | UDP, TCP, DoT and DoH listeners |
| `dnsy-api` | REST API (axum, utoipa) and the embedded UI |
| `dnsy` | the binary: CLI and wiring |

`dnsy-api` talks to services only, never to the listeners; `dnsy-engine` is the only place a
query is decided. The sections below describe the listeners and the pipeline.

## Handler and plain DNS listeners

`dnsy-engine::handler` defines the transport-agnostic contract: a `Handler` takes a `RequestContext` (client address, transport, optional principal, receive time) and a decoded `Message`, borrowed (`&Message`, so the transports keep the query for sizing and encoding without cloning it), and returns the response `Message`. DoT and DoH reuse it unchanged. `Engine` (below) is the real handler; `RefusedHandler` answers REFUSED and remains only for listener tests.

`dnsy-server` runs the UDP and TCP listeners (`[dns] udp`/`tcp`) and only frames bytes:

- **UDP:** the response limit is `min(client EDNS payload, 1232)`, or 512 without EDNS. Larger answers are truncated by `Message::encode` and flagged TC, so clients retry over TCP. In-flight requests per socket are bounded and excess datagrams are dropped.
- **TCP:** RFC 1035 two-byte framing with RFC 7766 pipelining; responses are written as they complete, in any order. At most `max_tcp_conns` connections are served (further ones are closed at accept), and a complete frame must arrive within `tcp_idle_ms`, which also cuts off slowloris-style trickling. Each connection bounds its pipelined requests.
- **Malformed input:** a packet with a readable header gets a minimal FORMERR (id and question only, so no amplification); an unreadable header, a stray response or an oversized datagram is dropped. A malformed frame on TCP gets FORMERR and the connection is closed.
- **Shutdown:** listeners stop accepting, then wait up to 5 seconds for in-flight requests to be answered.

## Request pipeline

`dnsy-engine::Engine` runs every query through one pipeline, whatever the transport. The first step that produces an answer ends the pipeline; exactly one `QueryEvent` (source, rcode, DNSSEC status, latency, principal) is emitted per request, including refused and dropped ones.

1. **ACL:** the client address (or mTLS certificate) decides `allow`, `refuse` (REFUSED) or `drop`. This runs before any other reply, error replies included.
2. **Rate limit:** per client (IPv4 /32, IPv6 /64) token bucket, also before any other reply. Over the limit, UDP is dropped (one in `limits.rate_limit_slip` gets a minimal truncated reply instead) and stream transports get REFUSED.
3. **Sanity:** no question -> FORMERR; opcode other than QUERY -> NOTIMP; EDNS version other than 0 -> BADVERS.
4. **Zone transfers:** AXFR and IXFR are REFUSED, for local zones and forwarded names alike.
5. **Blocklists / allowlist:** a blocked name is answered per `block_mode` (NXDOMAIN, `0.0.0.0`/`::`, REFUSED or custom addresses) with EDE 15 (list) or 17 (custom rule). Blocked answers are never cached.
6. **Local zones:** an authoritative answer with AA set. ANY gets the RFC 8482 minimal answer. Local zones **bypass the cache in both directions**: the cache is never consulted for them and their answers are never inserted, so edits take effect immediately. A CNAME chain that ends in a name missing from the zone answers NXDOMAIN, one that ends in a missing type NOERROR (RFC 6604: the RCODE describes the last name of the chain); chains leaving our zones are returned as-is and not chased.
7. **RD and ANY check:** a non-local query with RD=0 is REFUSED (we only offer recursion), and so is a non-local ANY query: forwarding it would turn the server into an amplifier.
8. **Cache:** keyed by (name, type, class, DO, CD), so DNSSEC-requesting and checking-disabled clients never share entries with others. A hit skips the upstreams, validation and scrubbing (they ran when the entry was stored) but still passes the response-IP policy and shaping. Stale answers are served with EDE 3 or 19.
9. **Upstream groups:** on a miss, a clean copy of the question (no client EDNS options, our own id) goes to the routed group, retried up to `resolver.attempts` times. Identical concurrent misses share one upstream exchange; at most `MAX_MISS_WAITERS` (256) requests wait on it, further ones get SERVFAIL (EDE 22) at once. The whole step is bounded by the deadline `resolver.timeout_ms * resolver.attempts` measured from receipt: when every upstream is down or slow the client gets SERVFAIL with EDE 22 (no reachable upstream) within it, never a hang; upstream transport errors or unusable responses give SERVFAIL with EDE 23 (network error). Error responses are not cached.
10. **DNSSEC validation:** unless `dnssec.validation` is `off` or the client sent CD=1, the query goes upstream with DO=1 and CD=1 and the raw answer is validated by `dnsy-dnssec`, fetching DS and DNSKEY records through the cache. Validation runs before scrubbing. Answer TTLs are capped by the remaining validity of the signatures, and the status is stored with the cache entry. In `strict` mode a Bogus answer becomes SERVFAIL with the validator's EDE; in `permissive` mode it is served without AD, the EDE attached. A client CD=1 skips validation: the upstream answer is returned as-is from its own (CD) cache entry. See [DNSSEC](dnssec.md).
11. **Scrubbing (cache poisoning defence):** a response whose question differs from ours is discarded (SERVFAIL, EDE 23) and never cached. Otherwise only in-bailiwick data is kept: answer records on the CNAME chain from the question name, the SOA of a zone enclosing the final name for negative answers, DNSSEC records only for DO clients, and no additional section (minimal responses). AA and AD from upstream are cleared.
12. **Response-IP policy:** an answer (fresh or cached) with an A/AAAA address inside a listed network is replaced by a block answer (list name `response-ip`, EDE 15), e.g. against DNS rebinding.
13. **Shaping:** the client's id, flags and question spelling are restored, RA is set, AD is set only for Secure answers to clients that sent DO or AD (RFC 6840 5.7), and an OPT record is sent only to clients that sent one (our payload size, their DO bit, EDE options only).

`Handler::handle` must always return a message, so a dropped request is answered REFUSED there; transports that can stay silent call `Engine::process`, which returns `None` for drops.

### Assembly

`Services::open(&config, &store)` builds every store-backed service once: the blocklist `ListManager` over the persisted list sources (seeded from `filter.blocklists` on first start, answering in `filter.block_mode`), the zone store from `zones.dir` with its `ZoneSigning`, the cache from `[cache]`, upstream groups from the database (seeded from `resolver.upstreams` on first start) behind a shared `GroupsHandle`, and the query-log writer when `querylog.enabled`. The binary hands the same `Services` to `EngineBuilder::from_services` (ACL rules and the rate limit from the database, falling back to `limits.per_client_qps`; an upstream client using `resolver.timeout_ms` per attempt; DNSSEC from `[dnssec]`) and to `ApiState::with_services`, so the engine, the API and the background tasks hold the same handles; the engine exposes none of them. `Services::spawn_background` starts the zone watcher, blocklist refresh, zone re-signing and key rollover; `Services::reload` (SIGHUP) re-reads zones, blocklists and due signatures. `EngineBuilder::from_config` remains as a shim that does both steps. `EngineBuilder::new` starts from config defaults only and its setters (and `Services::bare` plus its public fields) replace single components (tests, embedding). At runtime the ACL, rate limit, response-IP policy and upstream groups can be swapped atomically through `Engine::set_*`, and the list manager swaps in rebuilt blocklists.

### API state and live policy

`dnsy-api` never names `Engine<E>`. The running engine is reached through one trait, `dnsy_engine::LivePolicy` (implemented once for `Engine<E>` in `policy.rs`): it applies ACL rules, the rate limit, the block mode and the response-IP policy, validates and swaps upstream groups (`GroupSet::from_specs`), reads and changes the DNSSEC mode and negative trust anchors, lists the trust anchors and reports the untrusted-clock flag shown by `/readyz`. `ApiState` holds it as `policy: Option<Arc<dyn LivePolicy>>`; without it, mutating routes answer 503 (fail closed). The state's fields are grouped by concern: `AuthServices` (users, tokens, sessions, client certificates, bootstrap code, certificate reload, cookie flag), `PolicyStores` (ACL rules, blocklist sources, upstream groups), `Zones` (zone store and signer), `Observe` (store, client-IP redaction, live-tail limits); only `policy`, `cache` and `lists` stay optional at the top level. `ApiState::new` plus `with_services(&Services)` and `with_policy(engine)` is the one wiring path; `RuntimeSettings` lives in `dnsy-api`'s own module, not under `routes`.
