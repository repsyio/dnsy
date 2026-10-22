# Resolver, upstreams and cache

Upstream selection and load balancing are described under [Upstream groups](#upstream-groups). The
cache is described below.

## Upstream groups

Upstreams are organised into named groups, stored in the `upstream_groups` and `upstreams` tables
(migration `0005`). On the first start, when no group exists, `[resolver] upstreams` seeds one
round-robin group named `default`; after that the stored groups are authoritative and config
changes do not overwrite them. Exactly one group is the default and receives every query that no
domain pattern matches.

**Strategies.** Each group has one strategy that orders its healthy members; a query walks that
order until a member answers.

| Strategy | Order |
| --- | --- |
| `round_robin` | rotating start, one step per query |
| `weighted` | random, each member chosen with probability proportional to its weight (>= 1) |
| `lowest_latency` | ascending EWMA latency (alpha 0.3); members not yet measured go first |
| `failover` | configured order; later members only when earlier ones are down or fail |

**Routing.** A group may list domain patterns (`corp.example` or `*.corp.example`). Both forms
match the name itself and everything below it, case-insensitively. The pattern with the most
labels wins; a pattern may belong to one group only.

**Health.** Transport failures (timeout, I/O, TLS, malformed or mismatched response) count against
an upstream; any DNS response, whatever its RCODE, counts as success and resets the count. After 3
consecutive failures the upstream is ejected for 5 s; each further failed probe doubles the
ejection (10 s, 20 s, ... up to 5 min). Ejected members are skipped. An active probe (a root NS
query, issued by `GroupSet::run_probes` once the backoff has elapsed) re-admits an upstream on
success. If every member of the chosen group is ejected the query fails with
`NoAvailableUpstream`.

**Determinism.** `GroupSet` takes a `Clock` and an `Rng`, so tests drive time and randomness
explicitly.

## Cache

The cache lives in memory only and is not persisted across restarts. It is tuned by the `[cache]`
section (`enabled`, `max_entries`, `min_ttl`, `max_ttl`, `negative_max_ttl`, `servfail_ttl`,
`bogus_ttl`).

**Keying.** An entry is identified by the lowercased query name, type, class, the client's DO bit
and the client's CD bit. DO=0 and DO=1 clients never share entries, and CD=1 entries live in their
own key space, so unvalidated data cannot reach a validating client.

**Positive answers.** The lifetime is the smallest TTL across the cached records, clamped to
`[min_ttl, max_ttl]`. A lifetime of zero is not cached. The answer to the miss itself is the copy
the cache stored, so the clamps show from the first reply on, not only on later hits.

**Coalesced misses.** Concurrent misses for the same key (name, type, class, DO and CD) share one
upstream exchange: the first request forwards, validates and caches; the others wait for its
result, success or failure, and are answered from it with their own id and question. A result is
shared only while it is in flight (a failure is not remembered afterwards), a waiter whose leader
is cancelled takes the exchange over, and no waiter waits longer than twice the resolver deadline.
At most 256 requests wait on one key; beyond that a miss is answered SERVFAIL (EDE 22) at once, so a
flood of one slow name cannot hold every listener slot. Serve-stale refreshes and prefetches use
the same per-key slots and hand their result to any miss that waits on them.

**Negative answers (RFC 2308).** NXDOMAIN and NODATA are cached for the smaller of the SOA record
TTL, the SOA `minimum` field and `negative_max_ttl`; a negative answer without an SOA is not
cached. An NXDOMAIN is stored by name and answers every query type for that name (unless the name
was reached through a CNAME chain). SERVFAIL is cached for `servfail_ttl`. Other response codes,
truncated (TC) responses and authoritative (AA) responses from local zones are never cached.

**TTL decay.** Served records carry the remaining lifetime, rounded down to whole seconds and never
below zero. An expired entry is a miss and is dropped.

**Security state.** Each entry stores its DNSSEC status. A Bogus entry lives at most `bogus_ttl`, is
only ever returned to a CD=0 query as SERVFAIL, and never replaces a live Secure entry.

**Bounded size.** The cache is split into `max(16, 4 x cores)` shards (fewer for a small cache: each shard keeps
about 64 entries at least), each with its own lock, its own recency clock and its own hit, miss and
insert counters (summed when the stats are read), so concurrent readers share no global lock or
counter. A hit takes a reference to the stored message under the shard lock and copies it, with
the TTLs decremented, after releasing it. The name-level NXDOMAIN entry is looked up only when the
exact entry does not answer. `max_entries` bounds the total number of entries across
shards. When an insert takes it over, the inserting shard evicts the least recently used of 8
entries sampled at random positions, as long as it holds more than its share (`max_entries /
shards`); otherwise the first other shard over its share (visited one lock at a time from a random
start) does. No insert ever locks all shards. Evictions are counted.

**Flush and statistics.** The cache can be flushed entirely or by name (optionally the whole
subtree below it). Statistics report entries, capacity, hits, misses, inserts, evictions and
expired entries, stale answers served and prefetches started.

**Serve-stale (RFC 8767).** With `[cache.serve_stale] enabled`, an expired entry is kept for
`max_stale` seconds more (memory stays bounded by `max_entries`; stale entries are evicted like any
other). A query that finds only a stale entry refreshes it upstream first and answers with the new
data. If the refresh fails, comes back SERVFAIL, or takes longer than `client_timeout_ms`, the
client gets the stale answer instead, with every TTL set to `answer_ttl` and Extended DNS Error 3
(Stale Answer), or 19 (Stale NXDOMAIN Answer) for a stale NXDOMAIN. The query log records these as
source `cache_stale` and `stale_served` counts them. At most one refresh runs per cache key: while
it is in flight, other clients asking for the same name are answered stale at once instead of
querying upstream again. A refresh that outlasts `client_timeout_ms` is abandoned with the client's
request. Never served stale: Bogus entries and cached SERVFAILs. A stale answer that was Secure is
no longer reported as validated (no AD bit): validation does not outlive the lifetime the
validator allowed. A successful refresh replaces the stale entry.

**Prefetch.** With `[cache.prefetch] enabled`, a live entry that has served at least `min_hits`
hits and whose remaining lifetime has fallen to `remaining_ttl_pct` percent is refreshed in the
background, once per entry, so popular names never expire under load. The client that triggers it
is answered from the cache as usual. Refreshes go through the normal forwarding and DNSSEC
validation path, wait in a queue of 64 (extra ones are dropped and the entry simply expires; jobs older than 30 s
are skipped) and run four at a time. A queued job holds no refresh slot: a worker claims the key's
slot only when it starts, and skips the job if a client-driven refresh already holds it, so a
backlog never keeps a client from refreshing a stale entry. `Engine::run_prefetch` is the worker
loop; `dnsy serve` spawns it when prefetch is enabled, and nothing is queued while it is not
running. A failed prefetch keeps the existing
entry.

**Clock.** Cache operations take the current time as an argument, and the engine's time source can
be replaced (`EngineBuilder::clock`), so tests move time by hand.

## Upstream client

`dnsy-resolver` talks to upstream resolvers through `UpstreamClient::query(&Upstream, &Message)`.
An upstream is written as a URL:

| Form | Transport |
| --- | --- |
| `udp://host[:port]` | UDP (default port 53); a truncated answer (TC) is retried over TCP |
| `tcp://host[:port]` | TCP with 2-byte framing (default port 53) |
| `tls://host[:port][?pin-sha256=BASE64][#sni]` | DNS over TLS, RFC 7858 (default port 853); optional SPKI pin |

IPv6 literals use brackets, for example `tcp://[2001:db8::1]:53`.

Behaviour:

- **SPKI pin.** `?pin-sha256=` takes the base64 SHA-256 of the server certificate's
  `SubjectPublicKeyInfo` (the RFC 7469 form, 44 characters). It is checked after the normal
  certificate and host-name verification, on every new connection; a mismatch fails the attempt
  with a TLS error, which counts against the upstream's health like any transport error. Example:
  `tls://9.9.9.9:853?pin-sha256=...#dns.quad9.net`. The pin is part of the upstream's identity.
- **0x20 case randomisation.** With `resolver.case_randomization = true` (default false: it is
  opt-in) the query name sent to `udp://` and `tcp://` upstreams has random upper/lower case
  letters, and the answer must echo exactly that case, adding entropy against spoofing. Callers
  and the cache see the original case. An upstream that answers with another case (it
  lowercases) is retried at once without 0x20 and then queried without it for 10 minutes before
  being probed again, so such upstreams keep working. `tls://` upstreams are not randomised
  (authenticated transport). The setting is global, not per group: groups live in the database
  and adding a per-group flag would need a migration.
- **Loop guard.** An upstream (IP literal or host name) that resolves to one of DNSY's own
  `dns.udp`/`dns.tcp` listen addresses is refused with an error instead of queried, which stops a
  host whose system resolver points at DNSY from looping. A wildcard listen address (`0.0.0.0`)
  covers loopback and wildcard addresses on its port. The refusal is a failed attempt, so the
  upstream's health reflects it.

- Every attempt uses a fresh query ID from the CSPRNG.
- UDP queries go over a small pool of connected sockets per upstream. The pool keeps these
  anti-spoofing invariants:
  - each socket is bound to an OS-chosen random source port and connected to the upstream
    address, so the kernel drops datagrams from any other source; a socket is never reused for
    another upstream address;
  - a socket serves one query at a time; concurrent queries take other sockets, and a query
    finding no idle socket opens a new one;
  - a socket is closed after 16 queries, 5 s after it was opened or 2 s idle, whichever comes
    first; at most 16 idle sockets are kept per upstream (constants `UDP_ROTATE_QUERIES`,
    `UDP_ROTATE_AGE`, `UDP_IDLE_LIFETIME` and `UDP_POOL_IDLE` in `upstream/mod.rs`);
  - before a pooled socket sends a new query, everything queued on it is discarded, so only
    datagrams arriving after the new ID goes out can match, exactly as with a fresh socket;
  - a socket whose attempt timed out or failed is closed, never reused;
  - the receive buffer (4096 bytes, above the advertised 1232) belongs to the socket and is
    reused, so a query allocates no receive buffer.
- A response is accepted only when the ID, the QR bit, the opcode and the full question section
  match the query, the name compared case-sensitively (byte for byte, as sent). Mismatching UDP
  datagrams are ignored until the attempt times out; a mismatch on a stream transport is an error.
  The QNAME case is not randomised (no 0x20): some upstreams and middleboxes do not preserve case,
  and a fallback path for them is left for later.
- The upstream address is cached: an IP literal is parsed once, a host name is resolved again at
  most every 60 s (a pooled socket connected to an old address is closed).

**The trade-off of pooling.** A fresh socket per query gives each query a new random source port
(about 15 bits on Linux's default range) on top of the 16-bit ID. A pooled socket keeps its port for
up to 16 queries or 5 s, so an off-path attacker who learnt the port (for example by observing one
query) has, inside that window, only the 16-bit ID to guess and the exact question to match: a
forged answer that arrives before the real one is accepted with probability about 1/65536 per
forgery, against about 1/2^31 with a fresh port. Rotation keeps the window short, discarding queued
datagrams on reuse prevents pre-loading forgeries into a parked socket, and the defence in depth is
DNSSEC validation in `strict` mode (the default), which rejects forged answers in signed zones
whatever the transport. Measured with `missbench` (dnsy pinned to 4 cores, 64 closed-loop clients,
unique names, query log on): a fresh socket per query 113k QPS (31 us CPU per miss); the pool with
128 queries / 60 s / 64 idle 185k QPS (18.5 us); the pool as shipped 172k QPS (20.7 us, p99
1.15 ms).

- Each attempt has a timeout (default 2 s). The TCP retry after TC is a new attempt.
- Queries advertise an EDNS UDP payload of 1232. The caller's DO bit, CD bit and EDNS options are
  forwarded unchanged.
- DoT server certificates are always verified with rustls. By default the bundled Mozilla (webpki)
  roots are trusted; a configured CA set (`TlsRoots::Custom`) replaces them. The certificate must be
  valid for the host, or for the `#sni` name when given.
- DoT keeps one connection per upstream and reuses it. A connection idle longer than `dot_idle`
  (default 30 s) is closed and replaced on the next query; a connection the peer has closed is
  replaced transparently.
