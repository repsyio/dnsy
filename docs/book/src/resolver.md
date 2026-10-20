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
`[min_ttl, max_ttl]`. A lifetime of zero is not cached.

**Negative answers (RFC 2308).** NXDOMAIN and NODATA are cached for the smaller of the SOA record
TTL, the SOA `minimum` field and `negative_max_ttl`; a negative answer without an SOA is not
cached. An NXDOMAIN is stored by name and answers every query type for that name (unless the name
was reached through a CNAME chain). SERVFAIL is cached for `servfail_ttl`. Other response codes,
truncated (TC) responses and authoritative (AA) responses from local zones are never cached.

**TTL decay.** Served records carry the remaining lifetime, rounded down to whole seconds and never
below zero. An expired entry is a miss and is dropped.

**Security state.** Each entry stores its DNSSEC status. A Bogus entry lives at most `bogus_ttl`, is
only ever returned to a CD=0 query as SERVFAIL, and never replaces a live Secure entry.

**Bounded size.** The cache is split into up to 16 shards, each with its own lock, so concurrent
readers do not contend on a global lock. `max_entries` bounds the total number of entries across
shards; when it is exceeded the least recently used entry (among a small per-shard sample) is
evicted and counted.

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
| `tls://host[:port][#sni]` | DNS over TLS, RFC 7858 (default port 853) |

IPv6 literals use brackets, for example `tcp://[2001:db8::1]:53`.

Behaviour:

- Every attempt uses a fresh random query ID. UDP queries use a new socket on an OS-chosen random
  source port, connected to the upstream so datagrams from other sources are dropped.
- A response is accepted only when the ID, the QR bit, the opcode and the question match the query.
  Mismatching UDP datagrams are ignored until the attempt times out; a mismatch on a stream
  transport is an error.
- Each attempt has a timeout (default 2 s). The TCP retry after TC is a new attempt.
- Queries advertise an EDNS UDP payload of 1232. The caller's DO bit, CD bit and EDNS options are
  forwarded unchanged.
- DoT server certificates are always verified with rustls. By default the bundled Mozilla (webpki)
  roots are trusted; a configured CA set (`TlsRoots::Custom`) replaces them. The certificate must be
  valid for the host, or for the `#sni` name when given.
- DoT keeps one connection per upstream and reuses it. A connection idle longer than `dot_idle`
  (default 30 s) is closed and replaced on the next query; a connection the peer has closed is
  replaced transparently.
