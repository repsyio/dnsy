# Resolver, upstreams and cache

Stub: upstream selection and load balancing. The cache is described below.

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
expired entries; the serve-stale and prefetch counters stay at zero until those features land.
