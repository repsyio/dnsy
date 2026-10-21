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
                  |  dnsy-engine  pipeline: sanity, ACL, rate limit, filter,
                  |        |      local zones, cache, validation, shaping
                  |        |---> dnsy-zone      JSON zones, signing, lookup
                  |        |---> dnsy-filter    blocklists, ACL, rate limit
                  |        '---> dnsy-resolver  cache, load balancing ----> 1.1.1.1 ...
                  |                  '--- dnsy-dnssec  validation          9.9.9.9 ...
                  |  dnsy-observe  query log + stats   dnsy-auth  users, tokens
                  |  dnsy-store    SQLite              dnsy-config  TOML schema
 browser, curl -> |  dnsy-api      REST + OpenAPI + embedded web UI :5380
                  +---------------------------------------+
```

| Crate | Role |
| --- | --- |
| `dnsy-core` | shared vocabulary types (transport, principal, role, scope, DNSSEC status) |
| `dnsy-proto` | wire format, names, records, EDNS, canonical form |
| `dnsy-dnssec` | validation, signing, key handling over `ring` primitives |
| `dnsy-config` | TOML schema, defaults, validation |
| `dnsy-store` | SQLite handle and migrations |
| `dnsy-auth` | users, roles, tokens, sessions |
| `dnsy-observe` | query events, query log, statistics |
| `dnsy-zone` | zone model, JSON files, hot reload, authoritative lookup, signing |
| `dnsy-resolver` | upstream client, cache, load balancing, validating forwarder |
| `dnsy-filter` | blocklists, allowlist, ACL, rate limit |
| `dnsy-engine` | the `Handler` trait and the request pipeline |
| `dnsy-server` | UDP, TCP, DoT and DoH listeners |
| `dnsy-api` | REST API (axum, utoipa) and the embedded UI |
| `dnsy` | the binary: CLI and wiring |

`dnsy-api` talks to services only, never to the listeners; `dnsy-engine` is the only place a
query is decided. The sections below describe the listeners and the pipeline.

## Handler and plain DNS listeners

`dnsy-engine::handler` defines the transport-agnostic contract: a `Handler` takes a `RequestContext` (client address, transport, optional principal, receive time) and a decoded `Message` and returns the response `Message`. DoT and DoH reuse it unchanged. `Engine` (below) is the real handler; `RefusedHandler` answers REFUSED and remains only for listener tests.

`dnsy-server` runs the UDP and TCP listeners (`[dns] udp`/`tcp`) and only frames bytes:

- **UDP:** the response limit is `min(client EDNS payload, 1232)`, or 512 without EDNS. Larger answers are truncated by `Message::encode` and flagged TC, so clients retry over TCP. In-flight requests per socket are bounded and excess datagrams are dropped.
- **TCP:** RFC 1035 two-byte framing with RFC 7766 pipelining; responses are written as they complete, in any order. At most `max_tcp_conns` connections are served (further ones are closed at accept), and a complete frame must arrive within `tcp_idle_ms`, which also cuts off slowloris-style trickling. Each connection bounds its pipelined requests.
- **Malformed input:** a packet with a readable header gets a minimal FORMERR (id and question only, so no amplification); an unreadable header, a stray response or an oversized datagram is dropped. A malformed frame on TCP gets FORMERR and the connection is closed.
- **Shutdown:** listeners stop accepting, then wait up to 5 seconds for in-flight requests to be answered.

## Request pipeline

`dnsy-engine::Engine` runs every query through one pipeline, whatever the transport. The first step that produces an answer ends the pipeline; exactly one `QueryEvent` (source, rcode, DNSSEC status, latency, principal) is emitted per request, including refused and dropped ones.

1. **Sanity:** no question -> FORMERR; opcode other than QUERY -> NOTIMP; EDNS version other than 0 -> BADVERS.
2. **ACL:** the client address (or mTLS certificate) decides `allow`, `refuse` (REFUSED) or `drop`.
3. **Rate limit:** per client (IPv4 /32, IPv6 /64) token bucket; over the limit UDP is dropped and stream transports get REFUSED.
4. **Blocklists / allowlist:** a blocked name is answered per `block_mode` (NXDOMAIN, `0.0.0.0`/`::`, REFUSED or custom addresses) with EDE 15 (list) or 17 (custom rule). Blocked answers are never cached.
5. **Local zones:** an authoritative answer with AA set. Local zones **bypass the cache in both directions**: the cache is never consulted for them and their answers are never inserted, so edits take effect immediately. A CNAME chain that ends in a name missing from the zone answers NXDOMAIN, one that ends in a missing type NOERROR (RFC 6604: the RCODE describes the last name of the chain); chains leaving our zones are returned as-is and not chased.
6. **RD check:** a non-local query with RD=0 is REFUSED (we only offer recursion).
7. **Cache:** keyed by (name, type, class, DO, CD), so DNSSEC-requesting and checking-disabled clients never share entries with others.
8. **Upstream groups:** a clean copy of the question (no client EDNS options, our own id, the client's DO and CD) goes to the routed group, retried up to `resolver.attempts` times. The whole step is bounded by the deadline `resolver.timeout_ms * resolver.attempts` measured from receipt: when every upstream is down or slow the client gets SERVFAIL with EDE 22 (no reachable upstream) within it, never a hang; upstream transport errors or unusable responses give SERVFAIL with EDE 23 (network error). Error responses are not cached.
9. **Scrubbing (cache poisoning defence):** a response whose question differs from ours is discarded (SERVFAIL, EDE 23) and never cached. Otherwise only in-bailiwick data is kept: answer records on the CNAME chain from the question name, the SOA of a zone enclosing the final name for negative answers, DNSSEC proofs only for DO clients, and no additional section (minimal responses). AA and AD from upstream are cleared.
10. **DNSSEC validation:** a seam returning `Unchecked` until the validating forwarder lands; its status is stored with the cache entry.
11. **Response-IP policy:** an answer (fresh or cached) with an A/AAAA address inside a listed network is replaced by a block answer (list name `response-ip`, EDE 15), e.g. against DNS rebinding.
12. **Shaping:** the client's id, flags and question spelling are restored, RA is set, and an OPT record is sent only to clients that sent one (our payload size, their DO bit, EDE options only).

`Handler::handle` must always return a message, so a dropped request is answered REFUSED there; transports that can stay silent call `Engine::process`, which returns `None` for drops.

### Assembly

`EngineBuilder::from_config(&config, &store)` is the single place that wires the pipeline: ACL rules and the rate limit from the database (falling back to `limits.per_client_qps`), the blocklist `ListManager` over the persisted list sources (seeded from `filter.blocklists` on first start, answering in `filter.block_mode`; the caller spawns its refresh loop via `Engine::list_manager()`), the zone store from `zones.dir`, the cache from `[cache]`, upstream groups from the database (seeded from `resolver.upstreams` on first start) with an upstream client using `resolver.timeout_ms` per attempt, and the query-log writer when `querylog.enabled`. `EngineBuilder::new` starts from config defaults only and its setters replace single components (tests, embedding). At runtime the ACL, rate limit, response-IP policy and upstream groups can be swapped atomically through `Engine::set_*`, and the list manager swaps in rebuilt blocklists; `Engine::cache()` exposes flushing and statistics.
