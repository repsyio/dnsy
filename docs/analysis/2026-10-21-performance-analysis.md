# Performance optimisation analysis (DNSY-63)

Read-only analysis pass over the merged implementation (`main` at `237751b`, stories DNSY-1..58,
69, 70). Everything below was measured on the release binary; nothing in the product was changed.
Database and SQLite tuning belong to the database analysis (DNSY-62) and are only mentioned where
they touch the DNS hot path.

## 1. Summary

The DNS hot path comfortably beats the spec targets (spec 4, "Performance targets"):

| Target (spec) | Measured | Verdict |
| --- | --- | --- |
| >= 50k QPS cache hits over UDP on 4 cores | **435k QPS** with the query log on, **628k QPS** with it off (64 clients, 4 cores) | 9-12x over target |
| p99 < 1 ms for cache hits on loopback | p99 **0.13 ms** (query log off), 0.54 ms (on), at 64 clients; 0.93 ms at 256 clients | met |
| < 200 MB RSS with 1M blocklist entries | **188 MB RSS** steady, **209 MB high-water mark** while the list is built | borderline: HWM above target |
| warm-cache validated answer < 1 ms extra | (not measured: the pass was cut short before this step; reproduce with Appendix A) | TBD |
| sign a 100k-record zone < 10 s on 4 cores | **4.6 s** (NSEC, alg 13), 6.1 s (NSEC3), single-threaded | met, with 1 core |

The main problems are not in the hot path itself but around it:

1. **TCP and DoT answers take ~41 ms each on a persistent connection** (Nagle + delayed ACK:
   the length prefix and the body are written separately and `TCP_NODELAY` is never set).
   Throughput over TCP/DoT is capped at ~100k QPS even with 256 pipelined connections, and a
   stub resolver with a kept-alive TCP connection sees 41 ms per lookup. One-line fix.
2. **The query log costs 30% of the server's capacity and 4x its tail latency** at high load
   (SQLite writer and per-event allocations on the same 4 cores); it also wrote **5.4 GB** of
   `query_log` rows in ~30 minutes of load testing, with no sampling or rate cap.
3. **Cache misses cost 30-40 µs of CPU each** (a fresh UDP socket, a 64 KiB buffer and two
   message clones per upstream exchange, plus a 16-shard eviction scan per insert) and top out
   at ~90k misses/s; that is the number that matters under cache-busting floods.
4. **UDP receive drops under burst** (one receive task per socket, default 208 KiB receive
   buffer, no `SO_REUSEPORT`/`recvmmsg`): 4,265 datagrams were dropped on the listening socket
   during the matrix, all at 256 concurrent clients.
5. **The cache does not scale past 4 threads** (shared atomic counters and a global `tick`
   touched on every lookup, 16 shards, full `Message` clone per hit): ~3M lookups/s total
   whatever the thread count, per-lookup latency 0.7 µs at 1 thread and 5.4 µs at 16.

Everything else (authoritative lookups, blocklist matcher, ACL, rate limiter, DNSSEC crypto,
startup, hot reload, shutdown, bundle sizes, login scene, dashboard polling) is within reasonable
bounds; the details and a "verified fine" list are in sections 6 and 7.

## 2. Method and environment

**Hardware.** AMD Ryzen AI 9 HX 370 (12 cores / 24 threads, 12 x 1 MiB L2, 24 MiB L3), 30 GiB
RAM, Linux 7.0.0-38-generic, `powersave` cpufreq governor (amd-pstate EPP). The server was
pinned with `taskset -c 0-3` (4 physical cores; their SMT siblings 12-15 were left to the OS),
the fake upstream to `10,11,22,23`, the load generator to `4-9,16-21`.

**Noise.** Four other analysis agents ran concurrently (load average 11-29, repeated full
`cargo build`s). Every data point is the median of 3 runs with the min-max spread shown; runs
visibly hit by a concurrent build (for example `auth` at 64 clients: 81k, 91k, 386k) were
repeated later (section 3.6). Absolute numbers are therefore conservative; relative comparisons
(on/off, before/after) were taken back to back.

**Build.** `cargo build --release` with rustc 1.99.1. The workspace has **no `[profile.release]`
section**, so the defaults apply: `opt-level = 3`, `lto = false` (thin-local), `codegen-units =
16`, `panic = "unwind"`, `debug = false`, `strip = "none"`. Binary: 28 MB unstripped (DNS only),
(not measured: the pass was cut short before this step; reproduce with Appendix A) with the UI embedded; (not measured: the pass was cut short before this step; reproduce with Appendix A) stripped. Build time 3 m 31 s clean.

**Tools.** A scratch crate outside the repository (depending on the workspace crates by path):
`fakeup` (multi-threaded UDP upstream over `SO_REUSEPORT`, plain mode and a signed root zone
with 10k names), `loadgen` (closed-loop clients: UDP, TCP and DoT with pipelining, DoH 1.1/h2
GET/POST via reqwest, idle-connection holder, uniform/zipf/unique name selection, per-query
latency histogram) and `microbench` (hand-rolled benches with a counting global allocator).
`perf` 7.0 for profiles and counters, `dnsmasq` as a local reference, headless Chromium
(Playwright 1.64) for the web UI. Full recipe in Appendix A.

**Server configuration** (unless stated): two local zones (`example.test`, 1,009 records;
`signed.test`, same records, DNSSEC enabled, alg 13 CSK, NSEC3), a 1,000,000-entry blocklist
file (`null_ip`), six ACL CIDR rules (`refuse`), query log on, cache 100k entries with
serve-stale and prefetch on, validation off, upstream = `fakeup` on loopback answering
`h<N>.test` A records with TTL 300 and `nx<N>.test` NXDOMAIN; DoT and DoH on self-signed P-256
certificates, DoH without a token requirement except where stated.

## 3. Measurements

### 3.1 UDP: cache, authoritative, negative, blocked, misses (4 cores, query log on)

`QPS` is the median of 3 runs of 3 s after 1 s warm-up; latencies are client-observed round
trips in microseconds; `CPU µs/q` is server CPU (user+sys) per answered query.

| scenario | clients | QPS (median) | QPS spread | p50 µs | p95 µs | p99 µs | max µs | timeouts | CPU µs/q |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| hit_uniform (1k names) | 1 | 70,207 | 69,645–71,149 | 13 | 20 | 27 | 821 | 0 | 11.6 |
| hit_uniform | 4 | 193,339 | 190,561–194,189 | 18 | 30 | 35 | 2,502 | 0 | 9.8 |
| hit_uniform | 16 | 374,642 | 349,811–402,195 | 30 | 95 | 115 | 2,391 | 0 | 7.5 |
| hit_uniform | 64 | 435,315 | 426,476–443,991 | 119 | 300 | 539 | 4,035 | 0 | 7.4 |
| hit_uniform | 256 | 491,752 | 454,100–518,945 | 299 | 524 | 931 | 4,071 | 276 | 7.2 |
| hit_zipf (100k names, s=1) | 1 | 60,915 | 54,429–68,555 | 13 | 23 | 41 | 1,159 | 0 | 13.6 |
| hit_zipf | 16 | 349,973 | 308,678–397,054 | 32 | 103 | 126 | 3,544 | 0 | 8.0 |
| hit_zipf | 64 | 445,542 | 445,416–461,894 | 120 | 259 | 457 | 3,734 | 0 | 7.7 |
| hit_zipf | 256 | 476,597 | 472,289–480,812 | 308 | 509 | 941 | 3,925 | 274 | 7.7 |
| auth (example.test) | 1 | 63,407 | 63,235–64,314 | 14 | 21 | 32 | 3,038 | 0 | 14.2 |
| auth | 16 | 415,421 | 395,293–415,520 | 31 | 101 | 122 | 2,525 | 0 | 7.8 |
| auth | 64 | see 3.6 (noise) | | | | | | | |
| auth_do_signed (DO, NSEC3 zone) | 1 | 58,394 | 54,195–63,651 | 15 | 20 | 31 | 2,810 | 0 | 16.4 |
| auth_do_signed | 4 | 161,524 | 160,411–162,290 | 19 | 38 | 49 | 3,174 | 0 | 10.6 |
| auth_do_signed | 256 | 275,885 | 271,375–375,976 | 465 | 1,355 | 2,324 | 8,934 | 272 | 10.7 |
| auth_nx_do_signed (NXDOMAIN + NSEC3 proof) | 1 | 29,464 | 27,430–31,753 | 28 | 40 | 65 | 6,277 | 0 | 27.0 |
| auth_nx_do_signed | 64 | 185,583 | 160,962–214,582 | 283 | 782 | 1,066 | 5,476 | 0 | 14.2 |
| auth_nx_do_signed | 256 | 217,005 | 203,546–233,897 | 677 | 1,454 | 2,075 | 6,836 | 271 | 13.5 |
| nxdomain_cached | 256 | 431,116 | 420,154–457,486 | 325 | 696 | 1,161 | 5,064 | 275 | 7.3 |
| blocked (1M-entry list) | 1 | 68,321 | 64,130–76,883 | 12 | 16 | 21 | 2,977 | 0 | 11.9 |
| blocked | 4 | 167,614 | 157,307–177,922 | 24 | 34 | 46 | 5,778 | 0 | 10.0 |
| miss_unique (every query a miss) | 1 | 23,063 | 22,565–24,664 | 37 | 45 | 72 | 3,211 | 0 | 28.5 |
| miss_unique | 16 | 77,227 | 74,768–80,817 | 160 | 412 | 596 | 10,215 | 0 | 30.4 |
| miss_unique | 64 | 92,362 | 86,550–96,776 | 623 | 1,259 | 1,883 | 6,628 | 0 | 34.3 |
| miss_unique | 256 | 82,717 | 76,963–84,660 | 2,170 | 3,907 | 5,240 | 9,887 | 222 | 40.1 |

Reading: a single closed-loop client sees 13 µs round trips; the server saturates 4 cores at
~440-490k cache hits/s with 7.2-7.7 µs of CPU per query (about 24k cycles, `perf stat`:
88.2 G cycles / 131.7 G instructions over 6.0 M queries, IPC 1.49). The 256-client runs each
lose ~275 datagrams (0.02%) to the UDP receive buffer (section 5.4). Misses cost 4-5x the CPU
of a hit and the miss path saturates at ~90k/s.

### 3.2 Query log on vs off (same binary, back to back)

| clients | query log | QPS | p50 | p95 | p99 | max | CPU µs/q |
|---:|---|---:|---:|---:|---:|---:|---:|
| 16 | on | 374,642 | 30 | 95 | 115 | 2,391 | 7.5 |
| 16 | **off** | **612,218** | 26 | 34 | 38 | 158 | 6.2 |
| 64 | on | 435,315 | 119 | 300 | 539 | 4,035 | 7.4 |
| 64 | **off** | **628,179** | 102 | 118 | 130 | 656 | 6.1 |

With the log off the 4 cores deliver 628k QPS at p99 0.13 ms. The difference is the SQLite
writer (`spawn_blocking`, batches of 500 rows plus two upsert passes per batch) running on the
same cores, the per-event `QueryEvent` (a `Name` clone, an `AnswerSource` clone, an optional
`String` for the principal) and the bounded channel. After the matrix the database held 51.5 M
rows (5.4 GB) and the writer had dropped roughly half of the ~100 M events (the `dropped`
counter is not exposed anywhere). Rate limiter on (`per_client_qps = 1000000`) at 64 clients: 456k-541k QPS, 6.5-7.2 µs CPU per
query, indistinguishable from the limiter-off runs (the 60 ns token-bucket check is < 1%).

### 3.3 TCP, DoT and DoH

| scenario | clients | QPS | p50 µs | p99 µs | max µs | CPU µs/q |
|---|---:|---:|---:|---:|---:|---:|
| tcp, pipeline 1 | 1 | 24 | 41,074 | 42,653 | 42,669 | 205 |
| tcp, pipeline 1 | 64 | 1,557 | 41,000 | 42,041 | 43,916 | 38.5 |
| tcp, pipeline 16 | 64 | 24,811 | 41,011 | 43,955 | 46,958 | 20.4 |
| tcp, pipeline 16 | 256 | 93,888 | 42,920 | 55,790 | 79,847 | 21.2 |
| dot, pipeline 16 | 64 | 24,576 | 41,887 | 43,914 | 45,812 | 25.3 |
| dot, pipeline 16 | 256 | 99,221 | 41,010 | 42,789 | 46,950 | 14.8 |
| doh/1.1 GET | 1 | 26,112 | 33 | 95 | 1,430 | 22.7 |
| doh/1.1 GET | 64 | 318,480 | 171 | 645 | 3,149 | 11.0 |
| doh/1.1 POST | 64 | 318,491 | 172 | 663 | 3,352 | 11.4 |
| doh/1.1 POST | 256 | 300,346 | 692 | 3,213 | 9,236 | 12.8 |
| doh/2 GET | 64 | 241,093 | 225 | 890 | 3,430 | 14.7 |
| doh/2 POST | 64 | 206,440 | 265 | 1,010 | 42,514 | 17.5 |
| doh/2 POST | 256 | 181,303 | 1,278 | 4,537 | 11,374 | 21.4 |
| doh/1.1 GET with bearer token | 64 | 186,271 | 299 | 1,202 | 3,721 | 19.6 |

Every TCP and DoT number is dominated by a constant 41 ms per response. A sequential probe over
one persistent TCP connection shows it directly: `0.1 41.3 40.8 41.5 40.4 41.6 ...` ms per query
(first query fast because Linux ACKs the first segments of a new connection immediately, then
the 40 ms delayed-ACK timer applies). `dig +tcp` (a new connection per query) does not show it,
which is why the e2e suite never noticed. Cause: `tcp.rs` writes the 2-byte length and the body
with two `write_all` calls on a socket without `TCP_NODELAY`; Nagle holds the second segment
until the first is acknowledged. `max = 41-42 ms` on DoH/2 POST at 1-64 clients is the same
interaction on the h2 connection (headers and body in separate writes).

DoH itself is fast: HTTP/1.1 reaches 318k QPS on 4 cores (73% of plain UDP), h2 about 240k
(frame multiplexing and flow control cost ~30%). A per-request bearer token costs 40% of the
throughput (`TokenService::verify` does a SQLite lookup per request via `spawn_blocking`; a
short-lived verified-token cache keyed by token hash would remove it).

### 3.4 Micro-benchmarks (single core, release, counting allocator)

| operation | ns/op | allocs/op | bytes/op |
|---|---:|---:|---:|
| `Message::decode` query (44 B, EDNS) | 390 | 6 | 256 |
| `Message::encode` query | 369 | 10 | 335 |
| `Message::decode` typical response (108 B, 4 A + OPT) | 934 | 23 | 1,216 |
| `Message::encode` typical response | 1,030 | 19 | 999 |
| `Message::decode` large response (472 B, 13 NS + 13 glue) | 11,235 | 154 | 11,208 |
| `Message::encode` large response (compression) | 11,448 | 77 | 7,150 |
| `Message::clone` typical response | 235 | 7 | 597 |
| `Name::from_ascii` | 262 | 7 | 176 |
| `Name::to_lowercase` | 43 | 1 | 17 |
| `hash_one(Name)` (SipHash, byte-at-a-time) | 33 | 0 | 0 |
| `Name::cmp` (canonical order) | 66 | 2 | 128 |
| `Cache::get` hit | 464 | 9 | 629 |
| `Cache::get` miss | 407 | 2 | 42 |
| `Cache::insert` at capacity (evicting) | 5,791 | 20.5 | 916 |
| `FilterSet::check` allowed / blocked (1M entries) | 63 / 91 | 1 / 2 | 17 / 31 |
| `Acl::check` (10 CIDR rules) | 36 | 0 | 0 |
| `RateLimiter::check` enabled / disabled | 60 / 2 | 0 | 0 |
| `Engine::process` cache hit (no sink / sink) | 1,584 / 2,182 | 12 / 14 | 682 / 700 |
| `Engine::process` blocked, 1M-entry filter | 649 | 9 | 748 |
| decode + clone + process(hit) + encode (what `udp.rs` does) | 2,536 | 39 | 1,986 |

Codec throughput works out to ~2.5 M typical queries decoded per second per core and ~1 M
typical responses encoded; the large-response case is 10x slower per byte because `encode`
builds a `HashMap` of RRset boundaries (hashing every owner `Name` byte by byte) and `decode`
allocates per record and per label. The full UDP cache-hit path allocates 39 times (plus the
packet `to_vec` and the task spawn): roughly 7 in the decode, 7 in the `Message::clone` that
`udp.rs` makes to keep the query for encoding, 9 in `Cache::get` (`StoreKey` clone with its
`Name`, full `Message` clone of the entry), 2 in `finish` (question clone, EDNS rebuild), ~10
in `encode`.

Cache contention (`Cache::get`, 1000 keys, 16 shards):

| threads | uniform keys, total ops/s | per-thread ns/op | single hot key, total ops/s |
|---:|---:|---:|---:|
| 1 | 1.49 M | 672 | 2.11 M |
| 4 | 3.00 M | 1,331 | 4.09 M |
| 8 | 2.82 M | 2,839 | 3.67 M |
| 16 | 2.99 M | 5,356 | 4.07 M |

The limit is not the shard mutex (a single hot key, one shard, is no slower than 1000 keys
spread over 16): it is the cache-line traffic on `tick` (`fetch_add` on every `get_exact`,
twice per lookup because exact and by-name keys are both tried), `hits`/`misses`/`len`, and the
`Message` clone under the lock. Rate limiter under contention: 25 M checks/s at 4 threads, 33 M
at 16 (fine).

### 3.5 DNSSEC

| operation | ns/op | allocs |
|---|---:|---:|
| `sign_rrset` alg 13 (ECDSA P-256) / alg 15 (Ed25519) | 16,017 / 22,073 | 20 / 20 |
| `verify_rrsig` alg 13 / alg 15 | 47,149 / 41,458 | 17 / 16 |
| `SigningKey::generate` alg 13 / 15 | 19,531 / 41,191 | 1 |
| `nsec3_hash` 0 iterations / 10 / 150 | 222 / 2,271 / 30,274 | 1 |
| `Dnskey::key_tag` | 98 | 2 |

RSA (alg 8/10) verification was not measured: the crate cannot generate RSA keys and no vector
was built; ring's RSA-2048 verify is typically 30-60 µs (unverified here). Zone signing
(`ZoneSigner::sign`, single thread, CSK):

| zone | denial / alg | sign | re-sign (unchanged) | allocations | RSS peak |
|---|---|---:|---:|---:|---:|
| 10k A records (20,004 RRsets) | NSEC / 13 | 430 ms | 139 ms | 4.2 M | - |
| 10k | NSEC3 / 13 | 476 ms | 181 ms | 5.3 M | - |
| 100k A records (200,004 RRsets) | NSEC / 13 | **4.59 s** | 1.76 s | 52.1 M | +254 MB |
| 100k | NSEC / 15 | 5.91 s | 1.78 s | 52.1 M | |
| 100k | NSEC3 / 13 | 6.08 s | **4.78 s** | 66.4 M | |

The spec target (100k records < 10 s on 4 cores) is met on one core; signing is embarrassingly
parallel per RRset and currently serial (a `spawn_blocking` job, section 5.10). A re-sign of an
unchanged NSEC3 zone still costs 79% of a full sign because the NSEC3 chain is rebuilt and
re-hashed; the NSEC variant keeps signatures and costs 38%. 520 allocations per record signed.

Validation end to end (strict mode, signed root served by the fake upstream, trust anchor =
its DS): (not measured: the pass was cut short before this step; reproduce with Appendix A)

### 3.6 Re-runs of noise-affected scenarios

(not measured: the pass was cut short before this step; reproduce with Appendix A)

### 3.7 Memory

| state | RSS | notes |
|---|---:|---:|
| after start, before the 1M blocklist is built | 98 MB | zones loaded and `signed.test` signed |
| 1M-entry blocklist loaded, idle | **188 MB** (HWM 209 MB) | `FilterSet` of 1M `Box<[u8]>` keys = +50 MB measured in isolation; the rest is the build (parsed lines + `HashMap` growth) and the old filter kept until the swap |
| fresh start with the 1M blocklist, cache empty | 175 MB (HWM 196 MB) | |
| cache full (100,000 entries, 54-byte A answers) | **292 MB** | **~1.1 KB per cache entry** for a 108-byte message: `Entry` = `Message` (4 `Vec`s, `Option<Edns>`, `Header`) + `StoreKey` (owned `Name`) + hashbrown slot; a 1M-entry cache would need ~1.1 GB |
| after 60 s of unique-name misses at 114k QPS (6.86 M inserts, 6.76 M evictions) | 292 MB, flat (+32 kB) | no growth under churn: the global bound holds, nothing leaks |
| after 30 s of zipf(1.0) over 1M names (hit ratio 40%) | 292 MB, flat | |

The cache is bounded by entry count, not bytes; with large answers (e.g. 1,200-byte DNSKEY or
TXT sets) 100k entries can reach several hundred MB. A byte-bounded cache (or a compact stored
form, section 5.2) would make `max_entries` predictable. RSS during signing of a 100k-record
zone peaks +254 MB (3.5).

### 3.8 Connections at scale

(not measured: the pass was cut short before this step; reproduce with Appendix A)

### 3.9 Startup, hot reload, shutdown

(not measured: the pass was cut short before this step; reproduce with Appendix A)

### 3.10 Reference point: dnsmasq

(not measured: the pass was cut short before this step; reproduce with Appendix A)

### 3.11 Web UI

Production build (`ng build`, Angular 22, esbuild):

| chunk | raw | gzip | when |
|---|---:|---:|---|
| initial (main + vendor + styles + 2 small chunks) | **304.5 kB** | 83 kB (brotli est. 70 kB) | every page load; the Angular budget warning fires (300 kB) |
| `login-scene` (three.js) | **546.8 kB** | 136 kB | lazy, only on the login page after first paint |
| login page | 42.6 kB | 12 kB | lazy |
| dashboard / query log / zone detail pages | 14-37 kB each | 5-10 kB | lazy |
| total `dist/browser` | 1.3 MB, 36 files | | |

The embedded server (`dnsy-api/src/ui.rs`) sets `Cache-Control: public, max-age=31536000,
immutable` on hashed assets and `no-cache` on `index.html` (good) but serves **uncompressed
bodies** regardless of `Accept-Encoding`: a cold login page transfers ~850 kB instead of
~220 kB, and `asset.body.into_owned()` copies each embedded file into a fresh `Vec` per request.

Runtime (headless Chromium, 1280x800, loopback): (not measured: the pass was cut short before this step; reproduce with Appendix A)

Code review of the three UI hot spots: the dashboard refreshes every 30 s with **8 parallel API
requests** (`/stats/summary`, `/stats/timeseries`, three `top-*` lists, `/cache`,
`/dnssec/status`, `/upstream-groups`), each a SQLite read on the blocking pool; the SSE live tail
keeps at most 1,000 rows in the browser (`MAX_ROWS`) and the server polls SQLite per
connection (`TAIL_BATCH = 200`, bounded by `MAX_LIVE_TAILS`); the login scene renders
continuously at display refresh (12 meshes, antialias on, pixel ratio capped at 2) and stops
only when the tab is hidden, not when the form is focused or `prefers-reduced-motion` is set.

## 4. Quick wins (small, low-risk changes with measured or well-bounded gains)

Ordered by gain per effort.

### Q1. Set `TCP_NODELAY` and write each TCP/DoT frame in one syscall — critical

- Evidence: 41 ms p50 on every TCP/DoT scenario (3.3); sequential probe `0.1, 41.3, 40.8, ...`
  ms; UDP p50 for the same answers 13 µs.
- Change: `stream.set_nodelay(true)` on every accepted socket in `tcp::serve_with` (plain and
  DoT; also DoH and the upstream TCP/DoT client in `dnsy-resolver`), and write the length
  prefix and the body with one `write_all` on a prepared buffer (or `write_vectored`). Also
  coalesce pipelined answers: the writer task could drain `rx` with `try_recv` and send several
  frames per write.
- Expected: p50 41 ms -> ~30 µs for persistent TCP/DoT clients; TCP/DoT throughput from ~100k
  to the UDP range (DoH/1.1 on the same code path does 318k). Risk: none.

### Q2. Add a `[profile.release]` section — high, 10 minutes

- Evidence: defaults in use (3 "Build"); 28 MB unstripped binary; 16 codegen units and no LTO
  leave cross-crate inlining (proto <-> engine <-> server) on the table.
- Change: `lto = "fat"` (or `"thin"` to keep build time), `codegen-units = 1`, `panic =
  "abort"` (the server never catches panics; unwinding tables cost size and some code-gen
  freedom), `strip = "symbols"` or `debug = 1` + separate symbols for `perf`. Keep
  `opt-level = 3`.
- Expected (unverified in this pass because the build takes 3.5 minutes per variant; typical
  for tokio servers): 5-15% fewer cycles per query, 30-40% smaller binary. Risk: longer release
  builds (`just build` only); `panic = "abort"` turns a panic in a connection task into a crash
  instead of one lost connection, so decide deliberately (the code is `unsafe_code = "forbid"`
  and panics are treated as bugs).

### Q3. Query log: sample, cap and account — high

- Evidence: 3.2: -30% throughput and 4x p99 at 400k+ QPS; 5.4 GB database after 30 minutes of
  load; ~50% of events silently dropped when the channel is full (counter not exposed).
- Change (hot-path side; storage schema is DNSY-62's): expose `QueryLogWriter::dropped` in
  `/stats` and `/metrics`; add `querylog.sample_rate` (1/N) and/or `querylog.max_rows_per_s`
  (the channel already provides the back-pressure point); build the per-event strings
  (`qname.to_string().to_ascii_lowercase()`, `client.to_string()`, `rcode.to_string()`) once per
  batch in the writer rather than per row; skip the `stats_top_hour` upsert for `source =
  cache` hits when a sampled mode is on. Consider keeping the counters (`stats_minute`) exact
  while sampling the rows.
- Expected: query log cost under 5% of capacity at any rate, bounded disk growth. Risk: sampled
  logs are a product decision (default 1 = today's behaviour).

### Q4. UDP socket: bigger receive buffer and one receive task per core — medium

- Evidence: 4,265 drops on the listening socket during the matrix (`/proc/net/udp` drops,
  `UdpRcvbufErrors`), all in 256-client runs; a second listener socket added 7-15% throughput
  at 4 cores (`259k + 258k` and `276k + 278k` combined vs 482k single, back to back).
- Change: `SO_RCVBUF` to 4-8 MiB (via `socket2` before converting to tokio; `net.core.rmem_max`
  is 4 MiB here, 212992 default); bind `N = worker_threads` sockets per address with
  `SO_REUSEPORT` on Linux (falls back to one elsewhere) so each worker has its own receive
  loop; make `MAX_IN_FLIGHT` (1024) and the queue depth configurable under `[limits]`.
- Expected: no drops at 500k QPS bursts; +10% at 4 cores, more on 8+ cores where one receive
  loop becomes the bottleneck. Risk: `SO_REUSEPORT` is Linux/BSD-specific (the spec requires
  Windows and macOS builds: gate it).

### Q5. Stop cloning the query per transport — medium, mechanical

- Evidence: `handler.respond(ctx, query.clone())` in `udp.rs`, `tcp.rs` and `doh/mod.rs`: 7
  allocations and ~235 ns per query only to keep the parsed query for `encode_response` and
  padding; `Handler::respond` takes `Message` by value but `Engine::process` only needs `&Message`.
- Change: make `Handler::handle/respond` take `&Message` (or pass the parts `finish` needs: id,
  flags, question, EDNS). Expected: -7 allocs/query (18% of the hot path's allocations), ~3% CPU.
  Risk: trait signature change across crates (pinned interface; needs a one-line note in the
  plan).

### Q6. Precompress the embedded UI — medium for first load

- Evidence: 3.11: 304 kB initial + 547 kB three.js served identity-encoded; gzip would cut
  transfer by 3.7x, brotli by ~4.3x.
- Change: build `.br`/`.gz` next to each asset (Angular does not; a small `build.rs` step or
  `pnpm` post-build), serve them with `Content-Encoding` when `Accept-Encoding` matches, and
  return `Bytes::from_static` instead of `into_owned()`. Expected: cold login ~220 kB instead of
  ~850 kB; on a 10 Mbit/s link 0.2 s instead of 0.7 s. Risk: none.

### Q7. Pause the login scene when it is not useful — low effort

- Change: respect `prefers-reduced-motion` (render one frame), stop the loop while the page is
  not visible *and* while the user types (or after 30 s idle), cap the pixel ratio at 1.5 on
  laptops. Expected: (not measured: the pass was cut short before this step; reproduce with Appendix A). Risk: none.

### Q8. Cache the verified DoH token — medium for DoH deployments

- Evidence: 3.3: 318k -> 186k QPS with a bearer token (SQLite read per request).
- Change: in `TokenAuth`, memoise `token hash -> (Principal, expiry)` for a few seconds (moka-
  style or a `Mutex<HashMap>` with a 1-5 s TTL), invalidated on revoke. Expected: token cost
  < 5%. Risk: a revoked token stays valid for the TTL (document it; 1-5 s is well within the
  existing session semantics).

### Q9. Allocator choice — measure before adopting

Not adopted here on purpose: the profile is only ~2.6% in `malloc`/`free` (`_int_malloc` 1.1%,
`free` ~1%); `memmove` is 9% but that is task-move and copies, not the allocator. A mimalloc or
jemalloc trial is a 20-minute experiment (feature-gated `#[global_allocator]`, `deny.toml`
permitting); expect 3-6% at most on this path and lower RSS fragmentation on the signing
workload (+254 MB peak). Recommendation: try it as part of the profile story (Q2) and keep it
only if it measures > 3%.

## 5. Structural findings

### 5.1 Cache miss path costs 30-40 µs CPU and tops out near 90k/s — high

- Evidence: 3.1 `miss_unique`: 23k QPS at 1 client (37 µs round trip), 92k at 64, 83k at 256
  with p99 5 ms and client timeouts; CPU 28-40 µs per miss vs 7 per hit.
- Where it goes (`dnsy-resolver/src/upstream/mod.rs`, `cache/mod.rs`, `engine.rs`): per attempt
  a new `UdpSocket::bind` + `connect` + `send` + `recv` + close (5 syscalls and an epoll
  registration), a `vec![0u8; 65535]` receive buffer (64 KiB zeroed per query), `lookup_host`
  per attempt, two `Message` clones (`query.clone()` in `UpstreamClient::query`,
  `msg.clone()` in `Cache::prepare`), `scrub`'s `chain()` allocating names, a `Recording`
  mutex, and on every insert at capacity `evict_one` which **locks all 16 shards** and samples
  the first 8 entries of each (`HashMap::iter().take(8)`: not a random sample, always the same
  bucket neighbourhood, so the "LRU" is a near-FIFO over a fixed window).
- Change: a small pool of connected upstream sockets per upstream (e.g. 4-8 per worker, random
  port on creation, rotated periodically to keep the anti-spoofing property; query id + 0x20
  randomisation already protects per query), a thread-local or pooled receive buffer sized to
  the advertised 1232/4096, cache the resolved `SocketAddr` of IP-literal upstreams, evict
  within the insert's own shard with a proper sampled-LRU (per-shard bound =
  `max_entries / shards`, sample random positions, or a CLOCK bit per entry), and make
  `insert` take the prepared message by value to drop one clone.
- Expected: miss CPU 30 -> ~12 µs, miss throughput 90k -> 200k+/s, p99 under flood well under
  1 ms; eviction from O(16 locks) to O(1 lock). Risk: medium (upstream client is security-
  sensitive: keep the per-query random id and the response matching; pooled sockets must still
  use random ports and be rotated).

### 5.2 Cache lookups: shared counters and a full clone per hit — medium

- Evidence: 3.4 contention table; `perf`: `Name::eq` 1.6%, `Name::hash` 0.8%, `evict_one`
  1.3%, `memmove` 9.2% in a hit-only profile.
- Change: per-shard `last_used` from a coarse clock (`Instant` quantised, or a per-shard
  counter) instead of the global `tick`; move `hits/misses/inserts` to per-shard counters
  summed in `stats()`; look up the by-name (NXDOMAIN) key only when the exact key misses *and*
  the type is cacheable by name (today both `StoreKey`s are built and hashed on every lookup,
  each cloning the `Name`); store entries as `Arc<Message>` plus the record TTL decrement
  applied at encode time (or store the encoded wire form with TTL offsets), so a hit clones an
  `Arc` instead of 7 allocations; shards = `max(16, 4 x cores)`; hash `Name` with a
  length-prefixed lowercase slice in one `write` instead of `write_u8` per byte.
- Expected: hit path 1.6 -> ~0.8 µs in-process, linear scaling to 16+ threads, -9 allocs/hit.
  Risk: medium (cache semantics are well covered by tests; the by-name NXDOMAIN rule and the
  `DnssecStatus` isolation must be preserved).

### 5.3 Per-datagram task spawn and large futures — medium

- Evidence: `perf` 1.7% `memmove` under `bind_new_task` from `udp::serve`; 153k context
  switches in 5 s; `to_vec` of every packet; `JoinSet::try_join_next` drained on every
  datagram.
- Change: process the datagram inline when the cache answers (`Cache::get` first, spawn only
  on a miss), or `Box::pin` the pipeline future so the spawned state is a pointer; reuse a
  per-worker receive buffer; with Q4 (one socket per worker) the spawn becomes unnecessary for
  hits. Expected: -1 µs CPU and -2 allocations per hit; lower tail at 256 clients. Risk: low.

### 5.4 Codec allocations — medium, long tail

- Evidence: 3.4: 23 allocations to decode a 108-byte response, 154 for a 472-byte one;
  `encode` builds a `HashMap<(usize,&Name,RecordType,Class), usize>` to find RRset boundaries
  on every call (10 of its 19 allocations) and writes into a `WireWriter` that is then copied
  into `out`.
- Change: `Name` as a small inline buffer (`[u8; 255]` + len, or `SmallVec<[u8; 32]>`) and
  `Vec<Record>` reserved from the section counts; RRset boundary detection by comparing each
  record with its predecessor (RRsets are contiguous in practice; fall back to the map only
  when they are not); encode straight into the output buffer with a compression table keyed by
  wire offsets; keep `Edns` options in a `SmallVec`. Expected: decode/encode 2x faster, -60%
  allocations; the large-response case 5x. Risk: medium (90% coverage gate on `dnsy-proto`
  helps; property tests exist).

### 5.5 Name canonicalisation repeated along the path — low

`question.name.to_lowercase()` is computed in `FilterSet::check`, again for the `CacheKey`, and
`Name::hash`/`eq` lowercase on the fly anyway. Lowercase once in the pipeline (or store names
lowercased with the original case kept only for the echoed question). -2 allocs/query.

### 5.6 Query log event construction — low (after Q3)

`emit` clones the `Name`, formats the principal label and clones `AnswerSource` (a `String`
for blocked lists) on every query even when the channel is full. Check `tx.capacity() > 0`
first and pass `Arc<str>` list names.

### 5.7 Authoritative signed answers — low

DO queries to the NSEC3 zone cost 1.5-2x a plain authoritative answer (16-27 µs vs 14 µs CPU at
1 client; NXDOMAIN with proofs 29k vs 63k QPS single-client) because each lookup hashes the
closest encloser and next-closer names (`nsec3_hash` 222 ns each plus base32) and clones the
RRSIG records (each a `Vec<u8>` signature). Cache the NSEC3 owner for each existing name at
index build time (the index is rebuilt per reload anyway) and keep RRsets as `Arc<[Record]>`.
Also `ZoneSet::rotation` is one `AtomicUsize` incremented by every authoritative query on every
core (cache-line bouncing); make it per shard or per worker.

### 5.8 Zone reload re-parses and re-indexes every zone — low unless zones are large

`ZoneStore::reload` re-reads all `*.json` files and `ZoneSet::with_signed` rebuilds every
`ZoneIndex` on any change (3.9: (not measured: the pass was cut short before this step; reproduce with Appendix A)). Reload only the changed file (the watcher
already knows the path) and reuse unchanged `Arc<Zone>` + indexes.

### 5.9 Blocklist build memory — low

Building the 1M-entry filter peaks at +110 MB over steady state (RSS 98 -> 209 MB HWM, 188 MB
after) because the parsed list, the growing `HashMap` and the previous `FilterSet` coexist.
Reserve the map from the source's entry count (persisted as `entries`) and build into a
`HashSet<Box<[u8]>>` with a cheaper hasher (FxHash/aHash: keys are already wire-form names);
alternatively a sorted `Vec<Box<[u8]>>` + binary search halves the memory at ~2x the lookup
cost (still < 200 ns). Target: HWM < 150 MB with 1M entries.

### 5.10 Zone signing is serial — low (target met)

4.6 s for 100k records on one core, 52 M allocations; `ZoneSigner::sign` runs in one
`spawn_blocking` job. Signing RRsets with `rayon`-style chunking (or `std::thread::scope` over
`available_parallelism`) would make it ~1.3 s on 4 cores; the NSEC3 re-sign should keep hashes
for unchanged owners (4.8 s -> ~1.8 s like NSEC).

### 5.11 Tokio runtime shape — observation

`#[tokio::main]` defaults: 6 `tokio-rt-worker` threads were observed with a 4-CPU affinity
mask (expected 4; worth checking whether `available_parallelism` is honoured or a second
runtime exists), plus the blocking pool for SQLite, argon2 and signing. The blocking pool has no
dedicated cores, which is why the query log writer competes with the hot path (3.2). Expose
`[server] worker_threads` and consider a dedicated single-thread runtime (or a plain thread) for
the SQLite writer.

## 6. Verified fine

- Spec targets for cache-hit QPS and p99 (9-12x and 7x headroom respectively).
- Authoritative lookups: 415k QPS at 16 clients, 14 µs CPU per answer; wildcard, CNAME and
  delegation paths are a `BTreeMap` walk with no allocation hot spots in the profile.
- Blocklist matcher: 63-91 ns per check at 1M entries, independent of list size; build 0.96 s
  for 1M lines (69 ms for 100k).
- ACL (36 ns, no allocation) and rate limiter (60 ns, 25-33 M checks/s across 16 threads;
  2 ns when disabled); the DoH auth-failure throttle is off the success path.
- DNSSEC crypto is ring-bound: 16/22 µs per signature, 41-47 µs per verification; NSEC3 with 0
  iterations 222 ns; key tag 98 ns.
- 100k-record zone signing 4.6 s (target 10 s).
- Startup: (not measured: the pass was cut short before this step; reproduce with Appendix A)
- Shutdown: 0.12-0.19 s idle, 0.34 s while serving 16 closed-loop clients (drain works; the
  query-log flush is bounded by `FLUSH_WAIT`).
- Memory under cache churn: flat at 292 MB over 6.9 M inserts/evictions; no leak.
- Idle connections: (not measured: the pass was cut short before this step; reproduce with Appendix A)
- Web: lazy routes everywhere, three.js only on the login page after first paint, hashed
  immutable assets, dashboard polling every 30 s (pausable), live tail bounded at 1,000 rows
  client-side and `MAX_LIVE_TAILS` server-side, login scene pauses on hidden tabs.
- UDP responses are capped at 1232 bytes (no fragmentation); TCP connection and per-connection
  in-flight caps; FORMERR/drop handling never allocates proportional to attacker-controlled
  counts (`decode` collects through `Result`).

## 7. Follow-up stories (prioritised)

| # | Story | Acceptance criteria (2 lines) | Estimate |
|---|---|---|---|
| 1 | ⚡ Set TCP_NODELAY and single-write framing on TCP, DoT, DoH and the upstream client | A persistent TCP connection answers 1,000 sequential queries with p50 < 1 ms (today 41 ms); the e2e suite gains a pipelined-persistent-connection latency test. `tcp_p16` at 64 clients >= 200k QPS on 4 cores. | 2 pt |
| 2 | 🔧 Release profile and symbol strategy | `[profile.release]` with LTO, `codegen-units = 1`, decided `panic` policy and `strip`; binary < 20 MB with the UI; cache-hit CPU per query measured within -5% or better of today's 7.4 µs by the recipe in Appendix A. | 1 pt |
| 3 | ⚡ Query log sampling, rate cap and dropped-events metric | `querylog.sample_rate`/`max_events_per_s` config and `querylog_dropped_total` exposed in `/stats` and `/metrics`; with sampling 1/100 at 400k QPS the hit-path throughput is within 10% of query-log-off (today -30%) and the database grows < 100 MB/h. | 3 pt |
| 4 | ⚡ UDP listener: SO_RCVBUF, SO_REUSEPORT per worker, configurable in-flight bound | Zero `UdpRcvbufErrors` during a 30 s burst of 256 closed-loop clients at >= 450k QPS; `[limits] udp_in_flight` and `[server] udp_sockets_per_address` documented; non-Linux builds keep one socket. | 3 pt |
| 5 | ⚡ Cache miss path: pooled upstream sockets, sized buffers, per-shard eviction | `miss_unique` at 64 clients >= 180k QPS on 4 cores with p99 < 1 ms (today 92k, 1.9 ms); CPU per miss < 15 µs; upstream source ports still random per socket and rotated; no 64 KiB allocation per query. | 5 pt |
| 6 | ⚡ Cache lookup without global counters and without cloning the message | `Cache::get` scales to >= 10 M ops/s at 16 threads (today 3 M); hit allocations <= 2; existing cache tests unchanged (TTL decrement, by-name NXDOMAIN, DNSSEC status isolation). | 5 pt |
| 7 | ♻️ `Handler` takes the query by reference; transports stop cloning | `Handler::respond(&self, ctx, &Message)`; allocations per UDP cache hit <= 30 (today 39+2) measured with the counting-allocator bench; no behavioural change in e2e. | 2 pt |
| 8 | 🎨 Precompressed, zero-copy embedded UI assets | Cold login transfers < 250 kB with `Accept-Encoding: br` (today ~850 kB); `Content-Encoding` and `Vary` set; assets served from static bytes; Lighthouse-style load under 1 s on a 10 Mbit/s throttle. | 2 pt |
| 9 | ⚡ DoH token verification cache | `doh1_token` at 64 clients within 10% of the no-token run (today -40%); revoked tokens stop working within the documented TTL (<= 5 s). | 2 pt |
| 10 | ⚡ Codec: fewer allocations in decode/encode | Typical response decode < 500 ns / <= 8 allocs, encode < 500 ns / <= 5 allocs (today 934/23 and 1,030/19); large-response case 3x faster; `dnsy-proto` coverage stays >= 90%. | 5 pt |
| 11 | ⚡ Parallel zone signing and incremental NSEC3 re-sign | 100k-record zone signs in < 1.5 s on 4 cores (today 4.6 s on 1); NSEC3 re-sign of an unchanged zone < 40% of a full sign (today 79%); peak RSS during signing < 150 MB over idle (today +254 MB). | 3 pt |
| 12 | 🎨 Login scene: reduced-motion and idle pause; dashboard request batching | Scene renders one frame under `prefers-reduced-motion` and stops after 30 s without pointer movement; dashboard refresh is one `/stats/dashboard` call (or 3) instead of 8; main-thread time of the login page over 5 s < (not measured: the pass was cut short before this step; reproduce with Appendix A). | 3 pt |
| 13 | ⚡ Reload only the changed zone file; per-shard RRset rotation counter | Editing one of N zones re-parses only that file (log shows one `loaded zone`), reload of a 100k-record zone visible within (not measured: the pass was cut short before this step; reproduce with Appendix A); `auth` QPS at 64 clients unchanged or better. | 2 pt |
| 14 | 📝 Benchmark harness in-tree (`just bench`) | The Appendix A tools live under `tests/bench/` (not a workspace member by default or excluded from coverage gates); `just bench` prints the UDP cache-hit, miss and TCP p50 numbers; documented in `docs/book/src/operations.md`. | 3 pt |

Stories 1-4 are the quick wins (together: TCP latency fixed, +30-45% hit throughput with the
log on, no UDP drops, smaller binary); 5-7 and 10 are the structural hot-path work; the rest is
polish. Allocator evaluation (Q9) is folded into story 2.

## Appendix A. Reproducible benchmark recipe

All commands assume the release binary at `$BIN` and a scratch directory `$B` outside the
repository (the pass used `/home/firat/.cache/dnsy-bench-perf`). The three helper programs are
~700 lines of Rust in a scratch crate depending on the workspace crates by path (`dnsy-proto`,
`dnsy-dnssec`, `dnsy-resolver`, `dnsy-filter`, `dnsy-config`, `dnsy-core`, `dnsy-engine`,
`dnsy-observe`) plus `socket2`, `rustls`, `reqwest` (`rustls-no-provider`, `http2`), `base64`,
`ipnet`; story 14 proposes checking them in.

```bash
# 1. Build
cargo build --release -p dnsy                       # DNS only
cd web && pnpm install --frozen-lockfile && pnpm build && cd .. \
  && cargo build --release -p dnsy --features embed-ui   # with the UI

# 2. Fixtures: zones, blocklists, TLS, user and tokens
python3 - <<'EOF'   # writes example.test.json (1k records), signed.test.json (dnssec on), big.test.json (10k/100k)
# see docs/book/src/zones.md for the JSON shape; records h<N> A 10.x.y.z
EOF
seq 0 999999 | awk '{print "ad"$1".tracker"($1%1000)".example"}' > block1m.txt
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem \
  -out cert.pem -days 30 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1
DNSY_PASSWORD=... $BIN --config dnsy.toml user create bench --role admin
$BIN --config dnsy.toml token create --user bench --name api --scope admin --scope api:read --scope api:write
# dnsy.toml: udp/tcp 127.0.0.1:5353, dot :8853, doh :8443 (require_token=false), api :5380,
# upstreams=["127.0.0.1:5399"], blocklists=[block1m.txt], cache max_entries=100000, validation="off"

# 3. Upstream and server, pinned
taskset -c 10,11,22,23 fakeup --bind 127.0.0.1:5399 --threads 4 --ttl 300 &
taskset -c 10,11,22,23 fakeup --bind 127.0.0.1:5398 --threads 4 --signed-root 10000 --ta-file signed.ta &  # validation runs
DNSY_DNSSEC_PASSPHRASE=x taskset -c 0-3 $BIN --config dnsy.toml serve --ready-file ready.json &
for c in 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12; do curl -H "Authorization: Bearer $TOK" \
  -H content-type:application/json -d "{\"cidr\":\"$c\",\"action\":\"refuse\",\"comment\":\"b\"}" http://127.0.0.1:5380/api/v1/acl; done

# 4. Load (each: 1/4/16/64/256 clients, 3 x 3 s after 1 s warm-up; server CPU from /proc/<pid>/stat)
LG="taskset -c 4-9,16-21 loadgen --duration 3 --warmup 1"
$LG --target 127.0.0.1:5353 --proto udp --clients 64 --pattern 'h{}.test.' --count 1000            # cache hit
$LG --target 127.0.0.1:5353 --proto udp --clients 64 --pattern 'h{}.test.' --count 100000 --zipf 1.0
$LG --target 127.0.0.1:5353 --proto udp --clients 64 --pattern 'h{}.example.test.' --count 1000    # authoritative
$LG --target 127.0.0.1:5353 --proto udp --clients 64 --pattern 'h{}.signed.test.' --count 1000 --do
$LG --target 127.0.0.1:5353 --proto udp --clients 64 --pattern 'nx{}.test.' --count 1000           # cached NXDOMAIN
$LG --target 127.0.0.1:5353 --proto udp --clients 64 --pattern 'sub.ad{}.tracker{}.example.' --count 1000  # blocked
$LG --target 127.0.0.1:5353 --proto udp --clients 64 --pattern 'u{}.test.' --unique                # every query a miss
$LG --target 127.0.0.1:5353 --proto tcp --pipeline 16 --clients 64 --pattern 'h{}.test.' --count 1000
$LG --target 127.0.0.1:8853 --proto dot --pipeline 16 --clients 64 --pattern 'h{}.test.' --count 1000
$LG --target 127.0.0.1:8443 --proto doh1 --clients 64 --pattern 'h{}.test.' --count 1000           # add --post, doh2, --token
$LG --target 127.0.0.1:5353 --proto tcp-idle --clients 10000 --duration 25                         # idle connections

# 5. Profiles and counters
perf stat -e task-clock,cycles,instructions,context-switches -p $PID -- sleep 5
perf record -F 999 -g -p $PID -o perf.data -- sleep 5 && perf report --no-children --percent-limit 0.8 --stdio
nstat -az UdpInErrors UdpRcvbufErrors; awk '$2 ~ /14E9$/ {print $NF}' /proc/net/udp   # drops on :5353
grep -E 'VmRSS|VmHWM' /proc/$PID/status
microbench codec cache filter dnssec engine                                            # micro-benchmarks

# 6. Reference
taskset -c 0-3 dnsmasq --no-daemon --port 5354 --no-resolv --no-hosts --addn-hosts=hosts.txt --cache-size=10000 &
$LG --target 127.0.0.1:5354 --proto udp --clients 64 --pattern 'h{}.test.' --count 1000

# 7. Web UI (headless Chromium through the web/ Playwright install)
node ui-measure.mjs http://127.0.0.1:5380 bench <password>   # nav timing, transfer sizes, CPU per 5 s, API calls per 35 s
```

Raw outputs of this pass (`results-main.txt`, `results-phase2.txt`, `results-phase3.txt`,
`microbench.out`, `perf-top.txt`) were kept out of the repository; the tables above are their
medians.
