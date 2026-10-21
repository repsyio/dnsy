# Database optimisation and performance analysis (DNSY-62)

- **Date:** 2026-10-21, against `main` at `237751b` (DNSY-1..58, 69, 70 merged)
- **Kind:** read-only pass; no product code changed. Benchmark scripts are in the appendices,
  not in the repo.
- **Inputs:** `crates/dnsy-store/migrations/*.sql`, every SQL string in `crates/` (grep for
  `prepare`, `prepare_cached`, `execute`, `query_row`, `execute_batch`), `EXPLAIN QUERY PLAN`
  for every statement, the design spec (5.2 "Where state lives", "Query logging"), the plan's
  migration table, the DNSY-68 comment thread, `docs/book/src/{query-log,backup-restore}.md`.
- **Engine:** rusqlite 0.40.2 `bundled` = SQLite 3.53.2 (`ENABLE_DBSTAT_VTAB`, `ENABLE_STAT4`,
  `TEMP_STORE=1`, `DEFAULT_WAL_AUTOCHECKPOINT=1000`). All measurements below used the same
  bundled library (a scratch Rust crate, appendix A) or the release `dnsy` binary itself.
- **Machine:** 24 cores, 30 GiB RAM, NVMe, Linux 7.0. Other analyses and builds ran
  concurrently; every number is the median of repeated runs (20 reps at 1M rows, 5 reps at 10M
  rows, 10 reps over REST) and CPU timings should be read with about +-20 % noise.
- **Datasets:** synthetic query logs of 100k, 1M and 10M rows spread over 30 days, written
  through the writer's own statements (500-row `BEGIN IMMEDIATE` batches, minute and hour
  rollups), with a Zipf name distribution over 200k names, 2k clients, 55 % cache answers, 8 %
  blocked. The top-N rollup came out pessimistic (70 % of names in an hour are distinct, 0.92
  `stats_top_hour` rows per query); real resolver traffic repeats names more, so the rollup
  figures are an upper bound and the raw-row figures are exact.
- **Effort scale:** S = under a day, M = 1-3 days, L = about a week.

## 1. Summary

The schema is small and sound: every lookup on the auth, filter, upstream, key and certificate
tables is a primary-key or unique-index probe (all under 10 us at any size), foreign keys are
indexed, WAL is on, writes take the lock up front (`BEGIN IMMEDIATE`), migrations are
checksummed and transactional. The query log writer sustains far more than the 5k QPS target:
the bundled SQLite ingests 142k rows/s with rollups in the generator, and the real pipeline
logged 10k q/s with zero drops and a WAL that stayed at 5 MiB.

The problems are all in the query-log and rollup read paths and in what happens as the log grows:

| # | Finding | Severity | Effort | Measured gain |
| --- | --- | --- | --- | --- |
| F1 | Keyset cursor is not used as an index bound: paging deeper costs O(rows above the cursor). Page in the middle of 10M rows: 124 ms; with a filter, 273 ms. One-line fix (tighten `to_ms` to the cursor) | high | S | 124 ms -> 0.025 ms (5000x); 273 ms -> 0.76 ms (360x) |
| F2 | Filtering by `client` scans the whole log (no index): 1.6 s per page at 10M rows, 1.6 s even when the client has no rows; `source`/`rcode`/`dnssec` filters on rare values scan too (`source=refused` deep page 273 ms) | high | S + migration | client: 1.6 s -> 0.009 ms with `query_log(client, ts_ms, id)` (+296 MiB at 10M); rare outcomes: 273 ms -> 24 ms with a 24 MiB partial index |
| F3 | Top-N over `stats_top_hour` is O(rows in range): top domains for 30 days takes 1.8 s at 10M (7 d: 390 ms, 24 h: 52 ms); a kind-first covering index does not help (the cost is the GROUP BY) | high | M + migration | needs a daily rollup or per-hour cap; 24 h and 7 d are fine today |
| F4 | Retention purge of `stats_top_hour` uses `hour + 3600 <= ?` (not sargable): full scan of the rollup every hour (190-250 ms at 9M rows), and a lowered retention deletes everything in one transaction (7 days of 10M = 1.26 s write lock, 298 MiB WAL) | medium | S | 19 ms -> 6 ms (`hour < ? - 3600`); batching bounds the lock to tens of ms |
| F5 | `stats_minute` is never purged: 17 rows per minute, 36 B each = 26 MiB per 30 days, 320 MiB per year, forever | medium | S | bounded size |
| F6 | No size-based retention or sampling: 102 B per logged query (80 B row + 22 B index) plus 12-38 B of rollups; 1M queries/day at 30 days is 3.4-4.2 GiB, 5k QPS sustained is 44 GiB per day | medium | M | operators can cap the file |
| F7 | Every session-authenticated API request is a write transaction (`UPDATE sessions SET last_seen_at`), contending with the log writer and fsyncing (`synchronous=FULL`) | low | S | measured 0.19 vs 0.16 ms per request; the exposure is queueing behind long purges (F4) |
| F8 | Summary/timeseries ship every minute row to Rust: 713k rows (30 d) per dashboard call; SQL-side aggregation is not faster (252 ms vs 118 ms decode), a daily rollup is | medium | M + migration | 30 d summary below 10 ms with a `stats_day` table |
| F9 | `dropped` counter of the writer is not exposed anywhere (the book says it is), and a failed flush drops the whole batch without counting it | low | S | observability |
| F10 | Pragmas left at defaults: `synchronous=FULL` (fsync on every commit in WAL), no `journal_size_limit` (WAL stays 298 MiB after a big purge), no `PRAGMA optimize`/`ANALYZE` ever (no `sqlite_stat1`, so any added index relies on default costs) | low | S | commit p50 1.7 ms -> 0.18 ms for small batches with NORMAL; WAL shrinks after checkpoint |
| F11 | Reader pool is round-robin over 4 mutexes, not "first free": slow scans park unrelated reads behind them | medium | S | first page p95 0.5 ms -> 8.6 s (max 21.7 s) with four LIKE scans in flight |
| F12 | Operations gaps: no `dnsy db check` (integrity), `dnsy migrate --status` fails on a read-only directory (WAL needs `-shm`), file copy without `-wal` silently loses recent rows (happened during this analysis), expired sessions are only deleted lazily | low | S | - |
| F13 | Text enumerations in `query_log` (`transport`, `source`, `dnssec`) and the dotted client string cost 21-27 % of the table | low | L + rebuild migration | 75.5 MiB -> 59.9 MiB (ints) -> 54.8 MiB (ints + binary client) per 1M rows |

Already good (section 8): point lookups, write batching, the single-writer design, migration
safety, online backup guidance, the keyset design itself, 24-hour dashboards (all under 2 ms at
10M rows over the raw SQL), purge of the raw log (333k rows in 95 ms), startup on a 10M-row
database (20 ms), online backup of 1.36 GiB in 1 s, `integrity_check` in 4.6 s.

## 2. Schema inventory

### 2.1 Tables and indexes (migrations 0001-0009)

| Table | Rowid / PK | Indexes (beyond PK) | Notes |
| --- | --- | --- | --- |
| `users` | `id INTEGER PRIMARY KEY` | `username COLLATE NOCASE UNIQUE` (autoindex) | `role` CHECK, `disabled_at` added by 0009 |
| `api_tokens` | `id INTEGER PRIMARY KEY` (random 53-bit id chosen by the app) | `api_tokens_user(user_id)` | FK `users ON DELETE CASCADE`, `secret_sha256 BLOB` |
| `sessions` | `id_sha256 BLOB PRIMARY KEY` (rowid table, so PK is an autoindex) | `sessions_user(user_id)` | FK cascade; candidate `WITHOUT ROWID` |
| `login_attempts` | `id INTEGER PRIMARY KEY` | `login_attempts_key(username, ip, at)` | covering for the throttle count |
| `query_log` | `id INTEGER PRIMARY KEY AUTOINCREMENT` | `query_log_ts(ts_ms, id)` | 12 columns, 4 TEXT enumerations, no FK |
| `stats_minute` | `(minute, dimension, key)` WITHOUT ROWID | - | 17 rows per minute in practice |
| `stats_top_hour` | `(hour, kind, key)` WITHOUT ROWID | - | unbounded by distinct keys per hour |
| `acl_rules` | `id INTEGER PRIMARY KEY` | partial unique `acl_rules_cidr`, `acl_rules_cert` | CHECK shape per kind |
| `rate_limits` | `id = 1` | - | singleton |
| `upstream_groups` | `name TEXT PRIMARY KEY` (rowid table) | partial unique `upstream_groups_default` | |
| `upstreams` | `id INTEGER PRIMARY KEY` | `UNIQUE(group_name, url)`, `UNIQUE(group_name, position)` | FK by `group_name`, covered by the unique indexes |
| `dnssec_keys` | `id INTEGER PRIMARY KEY` | `dnssec_keys_zone(zone, role, state)` | private key BLOB, wiped on removal |
| `blocklists` | `id INTEGER PRIMARY KEY` | `name UNIQUE`, `location UNIQUE` | |
| `custom_rules` | `id INTEGER PRIMARY KEY` | `UNIQUE(kind, domain)` | |
| `client_certs` | `id INTEGER PRIMARY KEY` | `sha256 UNIQUE` | DNSY-68 note: ids are reused after delete |
| `schema_migrations` | `version INTEGER PRIMARY KEY` | - | runner's own |

Schema review notes:

- **Types and constraints.** Time is unix seconds (`INTEGER`) everywhere except `query_log.ts_ms`
  (milliseconds) and `stats_*` (bucket start in seconds); consistent and compact. Hashes and keys
  are `BLOB`, not hex text. CHECK constraints enumerate every role/kind/state. No `STRICT` tables;
  nothing in the code relies on type affinity coercion, so `STRICT` would be a free hardening for
  new tables only (existing ones cannot be altered in place).
- **WITHOUT ROWID** is used where it pays (`stats_minute`, `stats_top_hour`: composite key, no
  secondary index). The copy experiment confirms it is size-neutral for `stats_minute` (24.8 MiB
  vs 24.0 MiB as a rowid table) but saves the extra autoindex seek. `sessions` (32-byte blob PK,
  one secondary index) is the only other candidate; it is tiny, not worth a rebuild.
- **Index coverage.** Every point lookup is covered (section 3). Missing: anything on
  `query_log` beyond time, which is F2. Redundant: none. `upstreams`'s FK is covered by the
  leading column of both unique indexes.
- **Column order** in `query_log` is fine for SQLite (nullable `principal`/`source_detail` cost one
  header byte when NULL). The AUTOINCREMENT on `query_log.id` costs one `sqlite_sequence` update
  per batch; it is harmless and keeps ids monotonic for the cursor even if the newest rows were
  ever deleted.
- **Text vs integer enumerations** (F13): `transport`, `source`, `dnssec` are 3-13 byte strings
  per row; `client` is dotted text (10.5 bytes average, 39 for IPv6). Measured on 1M rows:
  table 75.5 MiB as is, 59.9 MiB with integer codes (-21 %), 54.8 MiB with integer codes and a
  4/16-byte binary client (-27 %). This needs a table rebuild migration and touches every
  reader/writer of the log; it is the lowest priority item here.

### 2.2 Migration runner (`crates/dnsy-store/src/migrate.rs`)

- Embedded SQL, SHA-256 checksum per file stored in `schema_migrations`; an edited applied
  migration or an unknown (newer) migration refuses to start with a clear message. Verified by
  `edited_migration_fails` and `unknown_migration_refuses`.
- Set-based: every known-but-missing version is applied in version order, each in its own
  `BEGIN IMMEDIATE` transaction, so a failing migration rolls back cleanly
  (`failed_migration_rolls_back`). No down migrations by design (restore from backup).
- `applied()` runs `CREATE TABLE IF NOT EXISTS schema_migrations` outside the transaction and is
  called twice per `run` (verify, then pending); harmless.
- Startup cost on a 10M-row, 1.36 GiB database: `dnsy user list` (opens the store, sets WAL,
  verifies all nine checksums) 20 ms; `dnsy migrate --status` 20 ms. Adding an index migration
  changes that: `CREATE INDEX query_log(client, ts_ms, id)` took 6.8 s at 10M rows (about 20 s
  at 30M), during which the server has not started yet. Acceptable with a log line, but the
  follow-up story must say so in the release notes.

## 3. Statement inventory and query plans

All plans from `EXPLAIN QUERY PLAN` on the 100k dataset (plans are size-independent here because
no `ANALYZE` has ever run, so there is no `sqlite_stat1`). Full output in appendix B.

| Site | Statement (abridged) | Plan | Verdict |
| --- | --- | --- | --- |
| observe `search` first page | `... ORDER BY ts_ms DESC, id DESC LIMIT 101` | SCAN USING INDEX `query_log_ts` (stops after 101) | fine |
| observe `search` with cursor | `WHERE (ts_ms < ? OR (ts_ms = ? AND id < ?)) ORDER BY ...` | SCAN USING INDEX `query_log_ts` from the newest row | **F1**: walks every row newer than the cursor |
| observe `search` time range | `WHERE ts_ms >= ? AND ts_ms < ?` | SEARCH `query_log_ts (ts_ms>? AND ts_ms<?)` | fine |
| observe `search` client | `WHERE client = ?` | SCAN USING INDEX `query_log_ts`, filter per row | **F2** |
| observe `search` domain | `WHERE qname LIKE '%x%' ESCAPE '\'` | SCAN USING INDEX `query_log_ts` | inherent for infix LIKE; bounded by time range in the UI |
| observe `search` qtype/rcode/source/dnssec | `WHERE col = ?` | SCAN USING INDEX `query_log_ts` | fine for common values (first 101 matches come fast), **F2** for rare ones |
| observe `minute_rows` | `WHERE minute >= ? AND minute < ? ORDER BY minute` | SEARCH PRIMARY KEY range | fine; volume is the issue (**F8**) |
| observe `top` | `WHERE kind = ? AND hour >= ? AND hour < ? GROUP BY key ORDER BY c DESC` | SEARCH PRIMARY KEY (hour range), temp B-tree for GROUP BY and ORDER BY | **F3** |
| observe `purge_before` | `DELETE FROM query_log WHERE ts_ms < ?` | SEARCH `query_log_ts (ts_ms<?)` | fine |
| observe `purge_before` | `DELETE FROM stats_top_hour WHERE hour + 3600 <= ?` | SCAN `stats_top_hour` | **F4** |
| writer `flush` | 1 INSERT per event, 1 upsert per minute key, 1 upsert per hour key, all `prepare_cached` | n/a | fine |
| auth `verify_at` (tokens) | `JOIN users ... WHERE t.id = ?` | rowid probe x2 | fine; `last_used_at` written at most every 60 s |
| auth `validate_at` (sessions) | `JOIN users ... WHERE s.id_sha256 = ?` then `UPDATE sessions` | autoindex probe + write | **F7** |
| auth `check_throttle` | `COUNT(*), MIN(at) WHERE username = ? AND ip = ? AND at > ?` | COVERING INDEX `login_attempts_key` | fine |
| auth `record_failure` | `DELETE ... WHERE at <= ?` then INSERT | SCAN `login_attempts` (table is tiny, self-pruning) | fine |
| auth `verify_password` | `WHERE username = ?` | autoindex (NOCASE) probe | fine |
| auth `list` tokens | `WHERE user_id = ? ORDER BY created_at DESC, id DESC` | index + temp B-tree sort | fine (tens of rows) |
| auth users `list` | `ORDER BY username COLLATE NOCASE` | autoindex scan | fine |
| filter sources/rules/acl, resolver groups, certs | `SELECT ... ORDER BY id` | SCAN | fine (loaded into memory, tens of rows) |
| keystore (8 statements) | `WHERE zone = ? [AND state IN (...)]`, `WHERE id = ?`, `DISTINCT zone` | `dnssec_keys_zone` probe / covering scan | fine |
| keystore `import` dup check | `EXISTS (... zone = ? AND algorithm = ? AND public_key = ? ...)` | `dnssec_keys_zone (zone=?)` | fine |
| api `readyz` | `SELECT 1` on a reader | constant | fine |

Code-level observations:

- Every statement is parameterised; the only dynamic SQL is the `search` WHERE builder (clauses
  are string constants, values are bound) and `format!("SELECT {COLUMNS} ...")` with constant
  column lists. No injection surface.
- `prepare` (uncached) is used for the list queries in auth/filter/resolver/keystore; they run
  rarely. The hot paths (`flush`, `minute_rows`, `top`) use `prepare_cached`. `search` must
  `prepare` because its SQL varies; SQLite's parse cost is about 20 us, negligible against the
  queries themselves.
- `Store::read` and `Store::write` each `spawn_blocking`; nothing holds a connection across an
  `.await`.

## 4. Connection and pragma configuration (`crates/dnsy-store/src/store.rs`)

| Setting | Value | Assessment |
| --- | --- | --- |
| `journal_mode` | WAL (set on the writer at open; persistent) | right |
| `synchronous` | 2 = FULL (default) | in WAL mode, NORMAL is durable against process crash and only risks the last transactions on power loss, never corruption. Measured (E5): 500-row batches 121k -> 148k rows/s; 20-row batches commit p50 1.7 ms -> 0.18 ms. Low priority because the writer commits once per 500 events or per second (ten commits per second at 5k q/s), but every session touch (F7) and every retention pass pays an fsync today |
| `busy_timeout` | 5000 ms on every connection | right for CLI-beside-server |
| `foreign_keys` | ON per connection | right (SQLite default is off) |
| `cache_size` | -2000 (2 MiB) | fine: E3 shows a 256 MiB cache does not speed the full scans (page cache does the work) |
| `mmap_size` | 0 | fine: 2 GiB mmap changed the 10M LIKE scan from 1770 ms to 1718 ms (noise) |
| `temp_store` | file | fine: `MEMORY` was not faster for the top-N GROUP BY |
| `journal_size_limit` | -1 (none) | **F10**: after the 7-day purge the WAL was 298 MiB and stays that size on disk; `journal_size_limit = 64 MiB` truncates it at the next checkpoint |
| `wal_autocheckpoint` | 1000 pages (4 MiB), PASSIVE | adequate: under 10k q/s logging the WAL oscillated between 4.9 and 5.5 MiB (L2). A long read (a 2-20 s LIKE scan) delays the reset: the WAL then grows by what is committed meanwhile (about 1 MiB per 10k logged queries) and is reset by the next checkpoint after the read ends; the 16 MiB WAL left after the live run came from exactly that |
| `auto_vacuum` | NONE | right for an append-and-purge log: freed pages are reused by the next hour's inserts (freelist after a 1-day purge: 44 MiB, reused). `VACUUM` of the 7-day-purged file took 3.2 s and shrank 1.43 GiB to 1.01 GiB; offer it as `dnsy db vacuum`, never automatic |
| `optimize`/`ANALYZE` | never | **F10**: `ANALYZE` at 10M rows took 2.1-3.5 s; `PRAGMA optimize` after it 0 ms. Run `PRAGMA optimize` on close and once a day so the planner has `sqlite_stat1` once more indexes exist |
| `secure_delete` | off | right (the key store wipes the private key column explicitly) |
| Pool | 1 writer + 4 read-only `NO_MUTEX` connections, `Mutex` each, round-robin | **F11**: round-robin assigns the next read to reader `n % 4` even when it is busy; four slow scans stall everything. A `Semaphore`-guarded free list (or `tokio::sync::Mutex` try-lock first) fixes it in a few lines |
| Writes | `BEGIN IMMEDIATE` (DNSY-56 fix) | right: verified by `a_second_writer_waits_instead_of_failing_on_a_stale_snapshot`; L4/R4 below show the CLI committing beside the server under load |

## 5. Measurements

### 5.1 Size and growth model

Measured file layout (`dbstat`, 4 KiB pages, after `wal_checkpoint(TRUNCATE)`):

| Rows | File | `query_log` | `query_log_ts` | `stats_top_hour` | `stats_minute` |
| --- | --- | --- | --- | --- | --- |
| 100k / 30 d | 24.6 MiB | 7.5 MiB | 2.0 MiB | 7.2 MiB (202k rows) | 7.7 MiB (244k rows) |
| 1M / 30 d | 171 MiB | 75.5 MiB | 20.6 MiB | 58.5 MiB (1.65M rows) | 16.6 MiB (488k rows) |
| 10M / 30 d | 1364 MiB | 763 MiB (80.0 B/row) | 211 MiB (22.1 B/row) | 365 MiB (41.5 B/row, 0.92 rows/query) | 24.8 MiB (713k rows, 36 B/row) |

Model (B = bytes):

- Raw log: **102 B per logged query** (row 80 + index 22; average qname 19 chars, client 10.5).
  With the client index of F2: +30 B per query.
- `stats_top_hour`: 41.5 B per distinct (hour, kind, key). Synthetic worst case 0.92 rows per
  query = 38 B/query; a typical home/office resolver (names repeat, few clients) is nearer 0.3 =
  12 B/query. Purged with the raw log.
- `stats_minute`: bounded by minutes x keys, about 17 keys per minute: **0.88 MiB per day, 26 MiB
  per 30 days, 320 MiB per year**, never purged (F5).
- Totals (30-day retention, steady state):

| Load | Raw rows kept | Raw + index | `stats_top_hour` | File size |
| --- | --- | --- | --- | --- |
| 1M queries total | 1M | 97 MiB | 11-36 MiB | 0.13-0.17 GiB (measured 0.17) |
| 10M queries total | 10M | 0.97 GiB | 0.11-0.36 GiB | 1.1-1.4 GiB (measured 1.36) |
| 100M queries total | 100M | 9.5 GiB | 1.1-3.5 GiB | 11-13 GiB |
| 1M queries/day (Jira case) | 30M | 2.9 GiB | 0.34-1.1 GiB | **3.3-4.0 GiB** plus a WAL of up to 1 h of writes |
| 5k QPS sustained | 13G | 1.2 TiB | - | not viable: 44 GiB/day; needs sampling or size-based retention (F6) |

Fragmentation: the hourly purge frees one hour of pages which the next hour reuses; file size
plateaus at the 30-day high-water mark. After a lowered retention the freelist stays (354 MiB
after a 7-day purge) until a `VACUUM` (3.2 s at 1.4 GiB, needs 2x disk).

### 5.2 Query latency in-process (same SQLite build, cold planner, warm page cache)

p50 in ms; 1M = 20 reps, 10M = 5 reps.

| Query | 1M | 10M | Note |
| --- | --- | --- | --- |
| search: first page, no filter | 0.028 | 0.024 | |
| search: cursor page in the middle | 15.8 | **124.5** | F1 |
| search: 24 h range | 0.021 | 0.025 | |
| search: `client =` (common) | 129.7 | **1590** | F2, returns 0 rows: synthetic clients differ from the probe, which makes this the worst case |
| search: `client =` with 7 d range | 30.9 | 394.5 | F2 |
| search: `client =` (absent) | 127.4 | **1605** | F2 |
| search: `domain LIKE %github%` | 0.20 | 0.30 | common substring: first 101 come fast |
| search: `domain LIKE %nosuch%` | 150.2 | **1775** | full scan; inherent |
| search: `source = blocked`, 24 h | 0.14 | 0.23 | |
| search: `rcode = SERVFAIL` (1 %) | 1.6 | 1.4 | |
| search: `dnssec = bogus` (1 %) | 1.2 | 1.7 | |
| search: `source = refused`, deep page, 30 d | 29.0 | **273.6** | F1 + F2 |
| stats: minute rows 24 h | 1.0 | 1.4 | 16-24k rows |
| stats: minute rows 30 d (iterate only) | 32.6 | 46.3 | 488k-713k rows; 117.5 ms with columns decoded |
| stats: top qname 24 h | 6.5 | 52.6 | F3 |
| stats: top qname 7 d | 55.7 | 392.4 | F3 |
| stats: top qname 30 d | 249.8 | **1792** | F3 |
| stats: top client 24 h | 4.4 | 12.8 | |
| stats: top blocked 24 h | 1.8 | 12.0 | |
| auth/filter/resolver/keystore/certs (16 statements) | 0.001 | 0.001 | all probes |
| retention: count rows to purge (1 d) | 0.46 | 5.0 | |
| retention: `stats_top_hour` count with `hour + 3600 <=` | 31.7 | **189.9** | F4 |

### 5.3 What the candidate changes measured (10M dataset, scratch copies)

| Change | Query | Before | After |
| --- | --- | --- | --- |
| **F1** cursor also bounds `ts_ms` (`ts_ms <= cursor.ts`, plan becomes `SEARCH (ts_ms<?)`) | cursor page in the middle | 124.5 ms | **0.025 ms** |
| same | `source = refused` deep page 30 d | 273.6 ms | **0.76 ms** |
| row-value cursor `(ts_ms, id) < (?, ?)` alone | cursor page | 124.5 ms | 0.049 ms (SQLite >= 3.15 uses it as a bound) but **1089 ms** once an explicit range is also present (the planner prefers the range); so bound `to_ms` explicitly whichever form is used |
| **F2** `CREATE INDEX query_log_client ON query_log(client, ts_ms, id)` (6.8 s to build, +296 MiB = +39 % of the table) | `client =` common / rare 7 d / absent | 1590 / 394 / 1605 ms | **0.009 / 0.010 / 0.008 ms** |
| **F2** partial `CREATE INDEX query_log_rare ON query_log(ts_ms, id) WHERE source IN ('blocked','refused','error') OR rcode NOT IN (0, 3)` (2.3 s, +23.7 MiB) | `source = refused` deep page | 273.6 ms | **24.0 ms** |
| **F3** covering `stats_top_hour(kind, hour, key, count)` (3.7 s, +331 MiB) | top qname 30 d | 1792 ms | 1851 ms: **no gain**, the GROUP BY over 7M keys is the cost |
| **F4** `hour < ? - 3600` | purge count on `stats_top_hour` | 189.9 ms | **19.1 ms** (5.9 ms once the planner has stats) |
| **F8** `GROUP BY dimension, key` in SQL | summary 30 d | 117.5 ms (rows decoded in Rust) | 252 ms: **worse**; timeseries 30 d/1 h in SQL 209 ms. A `stats_day` rollup is the fix |
| **F10** `synchronous = NORMAL` | 100k rows, 500-row batches / 20-row batches | 121k rows/s, p50 3.7 ms / 8.4k rows/s, p50 1.7 ms | 148k rows/s, p50 2.4 ms / 54k rows/s, p50 0.18 ms |
| `cache_size = 256 MiB` | LIKE full scan | 1770 ms | 2399 ms (noise; no gain) |
| `mmap_size = 2 GiB` | LIKE full scan / client absent | 1770 / 1605 ms | 1718 / 1524 ms (no gain) |
| `temp_store = MEMORY` | top qname 7 d | 408 ms | 645 ms (no gain) |

### 5.4 The real binary: REST, writer under DNS load, shutdown

Release build, 10M-row database, token auth, sequential requests from a Python client (so the
numbers include HTTP, JSON and the API's redaction pass).

| REST case (10M rows, idle server, 10 reps) | p50 ms | p95 ms | Note |
| --- | --- | --- | --- |
| `GET /querylog?limit=100` first page | 0.51 | 1.06 | |
| `GET /querylog` cursor page (second page) | 0.48 | 0.55 | page 2 is cheap; F1 is about deep pages |
| `GET /querylog` 24 h range | 0.44 | 0.52 | |
| `GET /querylog?client=10.0.0.0` | 2995 | 13391 | F2; the p95 outliers coincide with another benchmark running on the same host |
| `GET /querylog?client=192.0.2.1` (no rows) | 2665 | 19944 | F2 |
| `GET /querylog?domain=github` | 960 | 1098 | 0.3 ms in-process on the pristine file: the 850k rows logged by the load test sit on top and match no filter, so every filtered page first walks them (same mechanism as F1/F2) |
| `GET /querylog?domain=nosuchname` | 3105 | 15152 | full scan |
| `GET /querylog?source=blocked` 24 h | 254 | 1211 | same 850k-row effect |
| `GET /querylog?outcome=SERVFAIL` | 1188 | 1318 | same |
| `GET /querylog?dnssec=bogus` | 853 | 1320 | same |
| `GET /stats/summary` 24 h / 7 d / 30 d | 10.0 / 60.5 / 245 | 10.5 / 66.3 / 277 | F8: linear in minute rows |
| `GET /stats/timeseries` 24 h at 5 m / 30 d at 1 h | 6.1 / 174 | 6.4 / 183 | F8 |
| `GET /stats/top-domains` 24 h / 30 d | 70.7 / 1870 | 71.2 / 1924 | F3 |
| `GET /stats/top-clients` 24 h | 16.4 | 16.7 | |
| `GET /stats/top-blocked` 30 d | 433 | 442 | F3 |
| `GET /users` with a bearer token | 0.16 | 0.50 | read path |
| `GET /users` with a session cookie | 0.19 | 0.40 | write path (F7): 0.03 ms dearer at idle, 0.33 vs 0.33 ms while 5k q/s are being logged |

While 5k q/s were being logged (5 reps): first page 0.57 ms, `client=` absent 2544 ms, summary
24 h 8.4 ms, top domains 24 h 71.9 ms, `/users` 0.33 ms, so the writer's batched commits (ten per second at 5k q/s, one
500-row batch each) do not disturb reads.

Writer under UDP load (`udpload.py`, 8 sender threads, random names under a local authoritative
wildcard zone so every query is answered and logged; `channel_capacity` 10k, `max_batch` 500,
`flush_interval` 1 s):

| Target q/s | Achieved | Answered | Rows logged | Drops | DNS p50 / p99 (ms) | WAL before -> after |
| --- | --- | --- | --- | --- | --- | --- |
| 2000 | 1999 | 100 % | 30000 of 30000 | 0 | 0.083 / 1.66 | 0.2 -> 4.9 MiB |
| 5000 | 4999 | 100 % | 75000 of 75000 | 0 | 0.026 / 0.075 | 4.9 -> 5.2 MiB |
| 10000 | 9994 | 100 % | 150000 of 150000 | 0 | 0.027 / 0.76 | 5.2 -> 5.5 MiB |
| 20000 | 19991 | 100 % | 300000 of 300000 | 0 | 0.024 / 0.65 | 5.5 -> 5.5 MiB |

The generator ceiling (in-process, batches of 500 with rollups) is 142k rows/s at 10M rows and
159k rows/s at 1M, so the writer has about 25x headroom over 5k QPS on this hardware; the bound
in practice is the DNS front end, not SQLite. Loss on crash: at most one flush interval (1 s or
500 events) plus whatever is in the channel; on SIGTERM the remaining events are flushed with a
10 s cap (`FLUSH_WAIT`). Measured: SIGTERM sent while 10k q/s were arriving; the process exited in 18 ms and the 4899 rows that were in flight at the signal were all in the file afterwards (count and max id advanced by the same amount).

CLI beside the server: `dnsy token create` while the server logged 5k q/s committed in 10 ms end to end (process start, migration verification, `BEGIN IMMEDIATE`, commit), without a `database is locked` error on either side.

### 5.5 Backup, integrity, failure modes

| Check | Result |
| --- | --- |
| Online backup API (`sqlite3_backup`, 1000 pages per step) of 1.36 GiB | 0.99 s, consistent copy; `cp` of the main file 0.34 s but **not** consistent (see below) |
| `PRAGMA quick_check` / `integrity_check` at 10M rows | 2.7 s / 4.6 s |
| File copy without `-wal` | silently loses every committed-but-not-checkpointed transaction. It happened during this analysis: the user and token created by the CLI sat in a 8 KiB WAL and the copy of `dnsy.db` had neither. The book documents `.backup` correctly; a `dnsy db backup <file>` command (online backup API, no `sqlite3` binary needed) would remove the trap |
| Corrupt page inside a table | `dnsy user list`: "sqlite error: database disk image is malformed", exit 1; `dnsy migrate --status` still reports all applied (it only reads `schema_migrations`). No integrity command exists to point at the file |
| Corrupt header | "sqlite error: file is not a database", exit 1 |
| Read-only data directory | `dnsy user list` and `dnsy migrate --status` both fail with "attempt to write a readonly database": a WAL-mode file cannot be opened read-only without a writable `-shm` unless opened with `immutable=1`; `--status` should use that |
| Disk full | not simulated (needs a mount). From the code: `flush` returns an error, the writer logs `query log flush failed` with the batch size and **drops the batch without incrementing `dropped`** (F9); the DNS path is unaffected; the retention task keeps failing hourly; the API returns 500 on writes. No crash, no corruption (SQLite guarantees), but no backpressure signal either |
| Concurrent CLI + server | `BEGIN IMMEDIATE` plus `busy_timeout` 5 s on both sides; `token create` beside a server logging 5k q/s took 10 ms, no errors on either side |

## 6. Findings in detail (ordered by gain over effort)

### F1. Cursor pages walk every newer row (high, S)

- **Evidence:** `crates/dnsy-observe/src/query.rs` adds
  `(ts_ms < ? OR (ts_ms = ? AND id < ?))` for `after` but keeps `to_ms` as supplied (or
  unbounded). The planner then does `SCAN query_log USING INDEX query_log_ts` from the newest
  row and discards rows until it passes the cursor: page k costs k pages. Middle page at 10M
  rows: 124.5 ms; with `source = refused` 273.6 ms; at 30M rows (1M/day retention) about 400 ms
  and 800 ms. The UI's "next page" button and the live tail (which passes `from_ms` but no
  cursor and filters `id > last_id` in Rust) both hit this.
- **Change (code only):** in `search`, when `q.after` is `Some(c)`, add the clause
  `ts_ms <= ?` with `c.ts_ms` (or fold it into `to_ms = min(to_ms, c.ts_ms + 1)`), keeping the
  existing OR clause for the tie-break. Measured: 124.5 ms -> 0.025 ms, 273.6 ms -> 0.76 ms.
  Optionally switch the tie-break to the row-value form `(ts_ms, id) < (?, ?)`, which is
  clearer; it is *not* sufficient alone when a range is present (1089 ms, see 5.3).
- **Risk:** none; the result set is identical. Add a test asserting the plan contains
  `SEARCH ... (ts_ms<?)` via `EXPLAIN QUERY PLAN` so it cannot regress.
- **Migration impact:** none.

### F2. No index for `client`; rare-value filters scan (high, S + migration)

- **Evidence:** `client =` is a full index scan at any size: 1.59 s at 10M for a client with no
  rows, 0.39 s with a 7-day range. `source`, `rcode`, `dnssec`, `qtype` filters are scans too,
  which is fine for common values (first 101 matches arrive in under 2 ms) and poor for the
  values operators actually search for (`refused`, `error`, `bogus`, `SERVFAIL`) once combined
  with paging: 273 ms per page at 10M.
- **Change:**
  - `0010_querylog_client_index.sql`:
    `CREATE INDEX query_log_client ON query_log (client, ts_ms, id);`
    Measured 1590 ms -> 0.009 ms; +296 MiB at 10M (+30 B per row, 29 % more file); build
    6.8 s at 10M. The order `(client, ts_ms, id)` serves both the equality and the
    `ORDER BY ts_ms DESC, id DESC`, so no sort.
  - `0011_querylog_rare_index.sql`:
    `CREATE INDEX query_log_rare ON query_log (ts_ms, id) WHERE source IN ('blocked', 'refused', 'error') OR rcode NOT IN (0, 3);`
    Measured 273.6 ms -> 24.0 ms for `source = refused`, +23.7 MiB. The planner uses a partial
    index only when the WHERE clause implies the index predicate, so `search` must emit the
    predicate verbatim when the requested `source`/`outcome` is in the set (a small match in the
    clause builder).
  - Alternative to 0011 with no schema change: when `source`/`outcome` names a rare value and
    no `from` is given, the API could default the range to 7 days; cheaper but changes
    semantics.
- **Risk:** the client index roughly doubles the write amplification of the log (two indexes
  instead of one); the generator still did 142k rows/s with one index, so headroom remains. The
  startup pause while the index builds (6.8 s at 10M, roughly 20 s at 30M) must be logged
  ("applying migration 0010, this can take a minute on a large query log").
- **Migration impact:** two new files; the plan's migration table must be extended (0010, 0011
  are not pre-assigned yet).

### F3. Top-N over 30 days is O(rows) (high, M + migration)

- **Evidence:** `top` groups every `stats_top_hour` row in the range: 52 ms (24 h), 392 ms
  (7 d), 1.8 s (30 d) at 10M queries / 9.2M rollup rows. A kind-first covering index removed the
  filter cost but not the GROUP BY (1851 ms). `temp_store = MEMORY` did not help. The web
  dashboard's 30-day preset therefore holds one of the four readers for about 2 s per widget
  (three widgets: domains, blocked, clients).
- **Change:** a daily rollup fed by a compaction step and a cap on the hourly table:
  - `0012_stats_top_day.sql`:
    ```sql
    CREATE TABLE stats_top_day (
        day   INTEGER NOT NULL,
        kind  TEXT    NOT NULL,
        key   TEXT    NOT NULL,
        count INTEGER NOT NULL,
        PRIMARY KEY (day, kind, key)
    ) WITHOUT ROWID;
    ```
  - Once an hour (in the retention task) fold every completed day older than 48 h:
    `INSERT INTO stats_top_day SELECT day, kind, key, sum(count) FROM stats_top_hour WHERE hour < :cutoff GROUP BY (hour / 86400) * 86400, kind, key ORDER BY sum(count) DESC LIMIT 5000 per (day, kind)` (window function `row_number() OVER (PARTITION BY day, kind ORDER BY sum(count) DESC)` <= 5000), then delete those hours. Keeping the top 5000 per day per kind bounds the table at 15k rows per day while keeping the exact answer for any top-100 request (the API caps `limit` at 100 and a key outside a day's top 5000 cannot reach the top 100 of a 31-day sum unless it is in the top of at least one day; document the approximation).
  - `top` then reads `stats_top_day` for whole days plus `stats_top_hour` for the partial days
    at both ends: at most 2 x 24 hourly buckets + 31 daily buckets of 5000 rows = 155k rows
    worst case, about 30 ms.
- **Risk:** rollup correctness around the day boundary (test with events straddling midnight
  UTC); the fold must run inside one write transaction per day to stay crash-safe.
- **Migration impact:** one new table; `stats_top_hour` retention becomes 48 h regardless of
  `retention_days`, which also removes most of its 365 MiB.

### F4. `stats_top_hour` purge is not sargable and purges are unbatched (medium, S)

- **Evidence:** `DELETE FROM stats_top_hour WHERE hour + 3600 <= ?1` scans the table every
  hour: 190-250 ms at 9.2M rows, 200 ms of write lock in the measured 1-day purge (881 ms total
  commit). A retention lowered through `PATCH /settings` (30 -> 7 days at 10M rows) deletes
  7.7M rows in one transaction: measured 7 days = 2.33M rows in 1.26 s with a 298 MiB WAL; 23
  days would be about 4 s and 1 GiB of WAL, during which the query-log writer blocks (its
  channel holds 10k events = 2 s at 5k QPS, so events are dropped).
- **Change (code only):** `WHERE hour < ?1 - 3600` (19 ms -> 6 ms with stats); delete in
  batches: `DELETE FROM query_log WHERE rowid IN (SELECT rowid FROM query_log WHERE ts_ms < ?1 LIMIT 50000)` in a loop of separate transactions until `changes() = 0`, same for the rollup
  by `(hour, kind, key)` ranges. 50k rows took about 15 ms in the measurements, so each lock is
  short and the writer interleaves.
- **Risk:** none functionally; the retention test needs a case with more rows than one batch.
- **Migration impact:** none.

### F5. `stats_minute` grows forever (medium, S)

- **Evidence:** 17 rows per minute (total, 4 rcodes, 7 sources, 5 dnssec), 36 B each: 713k
  rows / 24.8 MiB per 30 days, 320 MiB and 9M rows per year. `purge_before` and the book say
  "minute rollups are small and kept". The summary/timeseries range is capped at 366 days, so
  nothing can read older rows anyway.
- **Change (code only):** purge `stats_minute WHERE minute < now - max(retention, 400 days)`,
  or introduce `querylog.stats_retention_days` (default 400) in `[querylog]` and `PATCH /settings`.
  Together with F8's `stats_day` the minute table can follow the raw retention.
- **Migration impact:** none.

### F6. Retention is time-only; no size cap or sampling (medium, M)

- **Evidence:** 102 B per logged query. 1M queries/day at 30 days = 3.3-4.0 GiB (fine on a
  server, surprising on a Raspberry Pi SD card); 5k QPS sustained = 44 GiB/day, which the Jira
  scope names as the write target. Nothing stops the file from filling the disk; when it does,
  every write fails and the log stops silently (5.5).
- **Change:** `[querylog] max_size_mb` (default 0 = unlimited): the retention task reads
  `page_count * page_size - freelist_count * page_size` after each purge and, while above the
  cap, purges the oldest day; plus a `/readyz` warning `querylog_disk_full` when a flush fails
  with `SQLITE_FULL`. Sampling (`[querylog] sample = 1/N`) is the other half for high-QPS
  deployments; rollups must still count every query, so sampling applies to the raw INSERT only
  (the `flush` function already separates the two).
- **Migration impact:** none.

### F7. Session validation is a write per request (low, S)

- **Evidence:** `SessionService::validate_at` runs inside `store.write` and always executes
  `UPDATE sessions SET last_seen_at = ?` (no granularity, unlike tokens' 60 s
  `LAST_USED_GRANULARITY_SECS`). Every UI request therefore takes the write mutex, waits behind
  a running log flush (up to one 500-row batch, about 3 ms, or a purge, up to seconds) and
  fsyncs (`synchronous=FULL`). Measured cost is small on NVMe: `GET /users` 0.19 ms with a cookie against 0.16 ms with a token at idle, 0.33 ms against 0.33 ms under 5k q/s of logging; the risk is a UI request stuck behind a multi-second purge (F4), not throughput, so this is low severity once F4 is batched.
- **Change (code only):** read on a reader; only write when `now - last_seen_at >= 60` (same
  pattern as tokens). Keeps the 30-minute idle timeout semantics within a minute.
- **Risk:** none; adjust the `validate` tests that assert `last_seen_at == now`.
- **Migration impact:** none.

### F8. Summary and timeseries ship every minute row (medium, M + migration)

- **Evidence:** `minute_rows` returns 713k rows for a 30-day summary (16k for 24 h); decoding
  them costs 118 ms in-process and over REST the 30-day summary takes 245 ms and the 30-day timeseries 174 ms (24 h: 10 ms and 6 ms). SQL-side aggregation
  was slower (252 ms, temp B-tree over 713k rows), so the fix is fewer rows, not a different
  query.
- **Change:** `0013_stats_day.sql`: `stats_day(day, dimension, key, count, latency_sum_us, latency_max_us) PRIMARY KEY (day, dimension, key) WITHOUT ROWID`, folded from `stats_minute` by the same hourly compaction as F3 for days older than 48 h; `summary` and `timeseries` with buckets >= 1 day read `stats_day` for whole days and `stats_minute` for the edges (at most 2 x 1440 x 17 + 31 x 17 rows = 49k rows, about 8 ms). Buckets under one day over long ranges still read minute rows, which is the correct cost for that request.
- **Migration impact:** one new table.

### F9. Dropped events are invisible (low, S)

- **Evidence:** `QueryLogWriter::dropped()` is only read by tests; nothing in `dnsy-api`
  exposes it (no `/metrics`, not in `/readyz` or `/stats/summary`); the book claims "the dropped
  counter is exposed by the writer". A failed flush logs `dropped = n` but does not add to the
  counter.
- **Change (code only):** count failed flushes into the same `AtomicU64`, expose
  `querylog_dropped` (and `querylog_flush_errors`) in `/stats/summary` or `/readyz` warnings and
  the UI header.

### F10. Pragma tuning (low, S)

- `PRAGMA synchronous = NORMAL` on the writer (WAL makes it crash-safe; measured in 5.3).
- `PRAGMA journal_size_limit = 67108864` on the writer (truncates the WAL after a checkpoint;
  the 298 MiB WAL after a big purge otherwise persists on disk).
- `PRAGMA optimize` on the writer when the server stops and once a day from the retention task;
  it runs `ANALYZE` only on tables whose indexes need it, and with F2's indexes the planner
  should choose from statistics rather than defaults (the measured 19 ms -> 6 ms purge count
  difference came from stats alone).
- Not worth it (measured): `cache_size`, `mmap_size`, `temp_store`, a larger `page_size`.

### F11. Round-robin readers (medium, S)

- **Evidence:** `Store::read` picks `readers[next % 4]` and locks that `std::sync::Mutex`; if a
  1.8 s LIKE scan runs on reader 2, every fourth read waits behind it. Measured over REST: with four `domain=nosuchname` scans in flight, ten first-page requests had p50 2 ms but p95 8.6 s and max 21.7 s; alone they take 0.5 ms.
- **Change:** a `tokio::sync::Semaphore(4)` plus a `Mutex<Vec<Connection>>` free list (take any
  idle connection), or `try_lock` each reader in turn before blocking.

### F12. Operations gaps (low, S each)

- `dnsy db check` (`quick_check` 2.7 s, `integrity_check` 4.6 s at 10M rows), `dnsy db vacuum`
  (3.2 s, needs 2x free disk), `dnsy db backup <file>` using `rusqlite::backup` (0.99 s for
  1.36 GiB, consistent, no `sqlite3` binary needed, works beside the running server).
- `dnsy migrate --status` should open with `?immutable=1` (or copy to a temp file) so it works
  on a read-only directory and on a database that is still being written by another process.
- Delete expired sessions in the hourly retention task
  (`DELETE FROM sessions WHERE last_seen_at < now - 1800 OR created_at < now - 43200`); today
  a session row only disappears when its id is presented again.
- `client_certs` ids are reused after delete (DNSY-68 note): `INTEGER PRIMARY KEY AUTOINCREMENT`
  needs a table rebuild; a UUID/text id is the cheaper fix at API level.

### F13. Dictionary-encode the log row (low, L + rebuild migration)

- **Evidence:** 75.5 MiB -> 59.9 MiB per 1M rows with integer codes for `transport`, `source`,
  `dnssec`; 54.8 MiB with a 4/16-byte binary `client` as well (which also makes the F2 index
  smaller and makes "client = prefix" range queries possible).
- **Change:** `CREATE TABLE query_log_v2 ... ; INSERT INTO ... SELECT; DROP; RENAME` migration
  (minutes at 30M rows; the server is down meanwhile) plus mapping functions in `dnsy-observe`.
  Only worth doing together with another rebuild (F2 could be done inside the same migration).

## 7. Proposed migration files

Numbers 0010-0013 are not in the plan's pre-assigned table yet; the follow-up stories must add
them there before merging. Each is one statement set, applied in its own transaction by the
existing runner; none needs data backfill except 0012/0013's first compaction, which the hourly
task performs incrementally.

```sql
-- 0010_querylog_client_index.sql (F2). Builds in about 0.7 s per million rows.
CREATE INDEX query_log_client ON query_log (client, ts_ms, id);
```

```sql
-- 0011_querylog_rare_index.sql (F2). Partial: rows operators search for by outcome.
CREATE INDEX query_log_rare ON query_log (ts_ms, id)
    WHERE source IN ('blocked', 'refused', 'error') OR rcode NOT IN (0, 3);
```

```sql
-- 0012_stats_top_day.sql (F3). Per-day top-N, folded from stats_top_hour after 48 h.
CREATE TABLE stats_top_day (
    day   INTEGER NOT NULL,
    kind  TEXT    NOT NULL,
    key   TEXT    NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (day, kind, key)
) WITHOUT ROWID;
```

```sql
-- 0013_stats_day.sql (F8). Per-day counters, folded from stats_minute after 48 h.
CREATE TABLE stats_day (
    day            INTEGER NOT NULL,
    dimension      TEXT    NOT NULL,
    key            TEXT    NOT NULL,
    count          INTEGER NOT NULL,
    latency_sum_us INTEGER NOT NULL,
    latency_max_us INTEGER NOT NULL,
    PRIMARY KEY (day, dimension, key)
) WITHOUT ROWID;
```

Rollback: none of these can be reverted by the runner (by design). 0010/0011 can be dropped by
a later migration without data loss; 0012/0013 can be dropped as long as `stats_top_hour` and
`stats_minute` retention has not been shortened yet, so the stories should land the tables and
reads first and shorten the hourly/minute retention in a later release.

## 8. Verified fine

- Every auth, filter, upstream, DNSSEC-key and certificate statement is an index probe
  (`EXPLAIN QUERY PLAN`, section 3) and measured at 1 us; token verify and session lookup are
  two rowid/autoindex probes.
- Foreign keys are enabled per connection and every FK column is indexed; cascades on user
  delete are correct.
- `BEGIN IMMEDIATE` for all writes, `busy_timeout` 5 s on both sides: the CLI commits beside a
  server logging 5k q/s (5.4).
- Write batching: 500 events or 1 s, all through `prepare_cached`, rollups aggregated in memory
  before the upserts (one statement per distinct key, not per event). 142k rows/s in-process;
  10k q/s end to end with zero drops and a 5 MiB WAL.
- Shutdown flush: background tasks are aborted before the engine is dropped so the writer
  channel closes; the final flush is bounded by 10 s; measured 18 ms with 4899 rows in flight, none lost.
- Keyset pagination is stable under concurrent inserts (`pagination_is_stable`) and the
  `(ts_ms, id)` order matches the index; `ts_ms` and `id` were co-monotonic in all 10M generated
  rows, so the tie-break rarely does work but is needed for same-millisecond rows.
- `LIKE` patterns are escaped (`%`, `_`, `\`), limits are clamped (search 500, top 100, range
  366 days), and the `qname` is lower-cased on write so the search needs no `COLLATE`.
- Purging the raw log is cheap (333k rows in 95 ms, 2.3M rows in 616 ms) because the delete
  walks `query_log_ts`; freed pages are reused, so the file plateaus.
- Migrations: checksum verified on every start, unknown newer migrations refused, each applied
  in its own transaction and rolled back on failure, set-based convergence for out-of-order
  merges; startup on a 10M-row file is 20 ms.
- Backup: the book recommends `.backup` (online backup API); `rusqlite`'s backup API produces the
  same consistent copy in 1 s per 1.4 GiB. The encrypted DNSSEC key bundle export/import path
  reads keys with plain `SELECT ... WHERE state != 'removed'` and re-seals in memory; no
  database-level concern.
- Private keys are wiped (`private_key = x''`) rather than deleted, and `secure_delete` is not
  needed because the wiped value overwrites the cell in place in the WAL and main file on
  checkpoint (page-level; a forensic concern only for the WAL before its reset, which is the
  same exposure as the unencrypted mode the server already warns about).
- `synchronous=FULL` is safe, just slower than necessary; `auto_vacuum=NONE` is the right
  choice for this workload; 2 MiB `cache_size` is enough because the OS page cache does the
  rest (verified: 256 MiB cache and 2 GiB mmap did not change scan times).
- Corruption and read-only failures surface as clear SQLite error strings at startup rather
  than as silent misbehaviour.

## 9. Proposed follow-up stories

| # | Title | Acceptance criteria | Estimate |
| --- | --- | --- | --- |
| S1 | Bound the query-log cursor by time (F1) | `search` adds `ts_ms <= cursor.ts_ms`; a test asserts the plan is `SEARCH query_log_ts (ts_ms<?)` with a cursor and that paging 10k generated rows returns the same ids as before. Middle-page latency at 1M rows under 1 ms in a benchmark test. | 2 pt |
| S2 | Index the query log for client and rare outcomes (F2, 0010-0011) | Migrations 0010/0011 added to the plan table and runner; `search` emits the partial-index predicate for rare sources/rcodes; `EXPLAIN QUERY PLAN` tests for `client =` and `source = refused`; startup logs a line while building; book page updated with the size cost. | 3 pt |
| S3 | Sargable, batched retention purge (F4) | `stats_top_hour` purge uses `hour < ? - 3600`; purges run in batches of at most 50k rows per transaction; a test with 120k old rows shows at least three commits and the writer inserting between them; lowering retention via `PATCH /settings` no longer drops events at 5k QPS in the e2e load check. | 2 pt |
| S4 | Bound `stats_minute` and expired sessions (F5, F12) | Retention task deletes `stats_minute` older than `max(retention, 400 d)` and expired sessions; tests for both; book updated ("minute rollups are kept 400 days"). | 1 pt |
| S5 | Session touch granularity (F7) | `validate` is a read unless `last_seen_at` is older than 60 s; existing idle/absolute timeout tests pass; a test proves no write transaction for a second request within 60 s (count `sqlite3_total_changes`). | 1 pt |
| S6 | Daily rollups for top-N and summary (F3, F8, 0012-0013) | Tables added; hourly compaction folds days older than 48 h and trims `stats_top_hour`; `top`, `summary`, `timeseries` read daily rows for whole days; rollup-correctness test comparing against the raw log across a midnight boundary; 30-day top domains at 10M generated rows under 50 ms in a benchmark test. | 8 pt |
| S7 | Expose dropped and failed flushes (F9) | Failed flushes increment the counter; `/stats/summary` (or `/readyz` warnings) carries `querylog_dropped` and `querylog_flush_errors`; UI shows a badge; book corrected. | 2 pt |
| S8 | Pragma tuning and `PRAGMA optimize` (F10) | Writer sets `synchronous=NORMAL`, `journal_size_limit=64 MiB`; `PRAGMA optimize` on shutdown and daily; a test reads the pragmas back; WAL file shrinks after a purge in a test. | 1 pt |
| S9 | Free-list reader pool (F11) | `Store::read` takes any idle reader; a test runs one 500 ms read and asserts 8 concurrent fast reads finish under 50 ms. | 2 pt |
| S10 | `dnsy db check|vacuum|backup` and read-only `migrate --status` (F12) | Three subcommands with tests (corrupted file detected, vacuum shrinks a purged file, backup opens and passes `quick_check` while the server runs); `migrate --status` works on a read-only directory; book pages for backup and troubleshooting updated. | 3 pt |
| S11 | Size cap and sampling for the query log (F6) | `[querylog] max_size_mb` and `sample`; retention task enforces the cap by purging oldest days; rollups still count every query under sampling; `/readyz` warns on `SQLITE_FULL`; tests for both. | 5 pt |
| S12 | Compact query-log row encoding (F13) | Rebuild migration to integer enumerations and binary client, mapping in `dnsy-observe`, API output unchanged; size per 1M rows at least 20 % smaller in the benchmark test. Only after S2 and S6. | 8 pt |

Suggested order: S1, S3, S5, S8 (one day together), then S2, S4, S7, S9, S10, then S6 and S11,
S12 last or never.

## Appendix A. Benchmark tool (scratch crate, outside the repo)

`Cargo.toml`:

```toml
[package]
name = "benchtool"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
rusqlite = { version = "0.40.2", features = ["bundled", "backup"] }
```

`src/main.rs` (the data generator replays the writer's statements; `queries()` is the statement
inventory; `queries2()` holds the rewritten candidates; `bench` prints p50/p95/max over `reps`):

```rust
//! Scratch benchmark tool for the DNSY-62 database analysis (not part of the repo).
//! Uses the same rusqlite/bundled SQLite as dnsy (0.40.2 / SQLite 3.53.2).
use rusqlite::{params, Connection, TransactionBehavior};
use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

// Small deterministic PRNG (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    // Zipf-ish: rank = floor(n * u^s), heavy head.
    fn zipf(&mut self, n: u64, s: f64) -> u64 {
        let u = self.f64();
        ((n as f64) * u.powf(s)) as u64 % n
    }
}

fn open(path: &str) -> Connection {
    let c = Connection::open(path).unwrap();
    c.pragma_update(None, "journal_mode", "WAL").unwrap();
    c.pragma_update(None, "foreign_keys", true).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    if let Ok(v) = std::env::var("BENCH_SYNC") {
        c.pragma_update(None, "synchronous", v).unwrap();
    }
    if let Ok(v) = std::env::var("BENCH_CACHE") {
        c.pragma_update(None, "cache_size", v).unwrap();
    }
    if let Ok(v) = std::env::var("BENCH_TEMP") {
        c.pragma_update(None, "temp_store", v).unwrap();
    }
    if let Ok(v) = std::env::var("BENCH_MMAP") {
        c.pragma_update(None, "mmap_size", v).unwrap();
    }
    c
}

const SOURCES: &[(&str, u64)] = &[
    ("cache", 55),
    ("upstream", 25),
    ("blocked", 8),
    ("authoritative", 6),
    ("cache_stale", 3),
    ("refused", 2),
    ("error", 1),
];
const DNSSEC: &[(&str, u64)] = &[("insecure", 60), ("secure", 30), ("unchecked", 8), ("bogus", 1), ("indeterminate", 1)];
const TRANSPORT: &[(&str, u64)] = &[("udp", 85), ("tcp", 3), ("dot", 7), ("doh", 5)];
const QTYPES: &[(u16, u64)] = &[(1, 55), (28, 30), (65, 10), (12, 2), (16, 1), (15, 1), (33, 1)];
const RCODES: &[(u16, u64)] = &[(0, 88), (3, 10), (2, 1), (5, 1)];

fn pick<'a, T: Copy>(rng: &mut Rng, table: &'a [(T, u64)]) -> T {
    let total: u64 = table.iter().map(|(_, w)| w).sum();
    let mut r = rng.below(total);
    for (v, w) in table {
        if r < *w {
            return *v;
        }
        r -= w;
    }
    table[0].0
}

const TLDS: &[&str] = &["com", "net", "org", "io", "de", "co.uk", "cloud", "app"];
const WORDS: &[&str] = &[
    "www", "api", "cdn", "static", "img", "mail", "login", "shop", "news", "video", "ads", "track",
    "metrics", "edge", "assets", "media", "auth", "push", "sync", "update", "example", "google",
    "cloudfront", "akamai", "fastly", "github", "apple", "microsoft", "amazon", "netflix",
];

fn qname(rng: &mut Rng, n_domains: u64) -> String {
    let rank = rng.zipf(n_domains, 2.2);
    let mut r = Rng(rank.wrapping_mul(0x9E3779B97F4A7C15) | 1);
    let labels = 2 + r.below(3);
    let mut parts = Vec::new();
    for i in 0..labels {
        if i == labels - 1 {
            parts.push(TLDS[r.below(TLDS.len() as u64) as usize].to_string());
        } else if r.below(3) == 0 {
            parts.push(format!("{}{}", WORDS[r.below(WORDS.len() as u64) as usize], rank % 9973));
        } else {
            parts.push(WORDS[r.below(WORDS.len() as u64) as usize].to_string());
        }
    }
    parts.join(".") + "."
}

fn client(rng: &mut Rng, n_clients: u64) -> String {
    let c = rng.zipf(n_clients, 1.5);
    if c % 10 == 0 {
        format!("2001:db8:{:x}:{:x}::{:x}", c / 65536, c % 65536, (c * 7) % 65536)
    } else {
        format!("10.{}.{}.{}", (c >> 16) & 255, (c >> 8) & 255, c & 255)
    }
}

#[derive(Default)]
struct Agg {
    count: i64,
    sum: i64,
    max: i64,
}

/// Insert `rows` query-log rows spread over `days` days ending now, replaying the writer's
/// batch logic (500-row IMMEDIATE transactions, minute and hour rollups).
fn gen(db: &str, rows: u64, days: f64, batch: usize) {
    let mut c = open(db);
    let mut rng = Rng(0xDEADBEEFCAFEBABE);
    let end = now_ms();
    let span = (days * 86_400_000.0) as i64;
    let start = end - span;
    let n_domains = 200_000;
    let n_clients = 2_000;
    let t0 = Instant::now();
    let mut done = 0u64;
    let mut batch_times = Vec::new();
    while done < rows {
        let n = batch.min((rows - done) as usize);
        let tb = Instant::now();
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
        let mut minute: BTreeMap<(i64, &str, String), Agg> = BTreeMap::new();
        let mut top: BTreeMap<(i64, &str, String), i64> = BTreeMap::new();
        {
            let mut ins = tx
                .prepare_cached(
                    "INSERT INTO query_log (ts_ms, client, transport, principal, qname, qtype, rcode,
                                    source, source_detail, dnssec, latency_us)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )
                .unwrap();
            for i in 0..n {
                let k = done + i as u64;
                // Monotonic time with jitter; a mild diurnal wave on density is skipped for
                // simplicity: uniform spread.
                let ts = start + ((k as i128 * span as i128) / rows as i128) as i64;
                let qn = qname(&mut rng, n_domains);
                let cl = client(&mut rng, n_clients);
                let tr = pick(&mut rng, TRANSPORT);
                let src = pick(&mut rng, SOURCES);
                let ds = pick(&mut rng, DNSSEC);
                let qt = pick(&mut rng, QTYPES);
                let rc = pick(&mut rng, RCODES);
                let lat: i64 = match src {
                    "cache" | "authoritative" | "blocked" | "refused" => 20 + rng.below(400) as i64,
                    _ => 2_000 + rng.below(60_000) as i64,
                };
                let detail: Option<String> = match src {
                    "upstream" => Some(if rng.below(2) == 0 { "1.1.1.1:53".into() } else { "9.9.9.9:853".into() }),
                    "blocked" => Some(if rng.below(3) == 0 { "stevenblack".into() } else { "oisd".into() }),
                    _ => None,
                };
                let principal: Option<&str> = if tr == "doh" { Some("token:3") } else if tr == "dot" && rng.below(2) == 0 { Some("cert:ab12") } else { None };
                ins.execute(params![ts, cl, tr, principal, qn, qt, rc, src, detail, ds, lat]).unwrap();
                let m = ts.div_euclid(60_000) * 60;
                let h = ts.div_euclid(3_600_000) * 3600;
                for (dim, key) in [("total", String::new()), ("rcode", rc.to_string()), ("source", src.to_owned()), ("dnssec", ds.to_owned())] {
                    let a = minute.entry((m, dim, key)).or_default();
                    a.count += 1;
                    a.sum += lat;
                    a.max = a.max.max(lat);
                }
                if src == "blocked" {
                    *top.entry((h, "blocked", qn.clone())).or_default() += 1;
                }
                *top.entry((h, "qname", qn)).or_default() += 1;
                *top.entry((h, "client", cl)).or_default() += 1;
            }
        }
        {
            let mut up = tx.prepare_cached(
                "INSERT INTO stats_minute (minute, dimension, key, count, latency_sum_us, latency_max_us)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (minute, dimension, key) DO UPDATE SET
             count = count + excluded.count,
             latency_sum_us = latency_sum_us + excluded.latency_sum_us,
             latency_max_us = max(latency_max_us, excluded.latency_max_us)",
            ).unwrap();
            for ((m, d, k), a) in &minute {
                up.execute(params![m, d, k, a.count, a.sum, a.max]).unwrap();
            }
            let mut ut = tx.prepare_cached(
                "INSERT INTO stats_top_hour (hour, kind, key, count) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (hour, kind, key) DO UPDATE SET count = count + excluded.count",
            ).unwrap();
            for ((h, k, key), n) in &top {
                ut.execute(params![h, k, key, n]).unwrap();
            }
        }
        tx.commit().unwrap();
        batch_times.push(tb.elapsed());
        done += n as u64;
        if done % 1_000_000 == 0 {
            eprintln!("  {done} rows, {:.0} rows/s", done as f64 / t0.elapsed().as_secs_f64());
        }
    }
    let el = t0.elapsed();
    batch_times.sort();
    let p = |q: f64| batch_times[((batch_times.len() - 1) as f64 * q) as usize];
    println!(
        "gen {rows} rows in {:.1}s = {:.0} rows/s; batch({batch}) commit p50 {:?} p95 {:?} max {:?}",
        el.as_secs_f64(),
        rows as f64 / el.as_secs_f64(),
        p(0.5),
        p(0.95),
        batch_times.last().unwrap()
    );
    c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
    sizes(db);
}

fn sizes(db: &str) {
    let c = open(db);
    let ps: i64 = c.pragma_query_value(None, "page_size", |r| r.get(0)).unwrap();
    let pc: i64 = c.pragma_query_value(None, "page_count", |r| r.get(0)).unwrap();
    let fl: i64 = c.pragma_query_value(None, "freelist_count", |r| r.get(0)).unwrap();
    let av: i64 = c.pragma_query_value(None, "auto_vacuum", |r| r.get(0)).unwrap();
    let counts: Vec<(String, i64)> = ["query_log", "stats_minute", "stats_top_hour"]
        .iter()
        .map(|t| (t.to_string(), c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0)).unwrap()))
        .collect();
    println!(
        "size: page_size {ps} pages {pc} = {:.1} MiB, freelist {fl} pages ({:.1} MiB), auto_vacuum {av}, rows {counts:?}",
        (ps * pc) as f64 / 1048576.0,
        (ps * fl) as f64 / 1048576.0
    );
    // Per-table/index page counts via dbstat when available.
    let stat: Result<Vec<(String, i64, i64)>, _> = (|| {
        let mut st = c.prepare("SELECT name, sum(pgsize), count(*) FROM dbstat GROUP BY name ORDER BY 2 DESC")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))?;
        rows.collect::<Result<Vec<_>, _>>()
    })();
    match stat {
        Ok(rows) => {
            for (n, b, p) in rows {
                println!("  {n:<24} {:>9.1} MiB {p:>9} pages", b as f64 / 1048576.0);
            }
        }
        Err(_) => println!("  (dbstat not available)"),
    }
}

fn queries(c: &Connection) -> Vec<(&'static str, String, Vec<rusqlite::types::Value>)> {
    use rusqlite::types::Value as V;
    let now = now_ms();
    let (min_ts, max_ts): (i64, i64) = c
        .query_row("SELECT min(ts_ms), max(ts_ms) FROM query_log", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap_or((0, now));
    let mid = (min_ts + max_ts) / 2;
    let mid_id: i64 = c
        .query_row("SELECT id FROM query_log WHERE ts_ms >= ?1 ORDER BY ts_ms, id LIMIT 1", [mid], |r| r.get(0))
        .unwrap_or(0);
    let day = 86_400_000;
    let sel = "SELECT id, ts_ms, client, transport, principal, qname, qtype, rcode, source, source_detail, dnssec, latency_us FROM query_log";
    let order = "ORDER BY ts_ms DESC, id DESC LIMIT 101";
    vec![
        ("search: first page, no filter", format!("{sel} {order}"), vec![]),
        ("search: cursor page (middle)", format!("{sel} WHERE (ts_ms < ? OR (ts_ms = ? AND id < ?)) {order}"), vec![V::Integer(mid), V::Integer(mid), V::Integer(mid_id)]),
        ("search: last 24h range", format!("{sel} WHERE ts_ms >= ? AND ts_ms < ? {order}"), vec![V::Integer(max_ts - day), V::Integer(max_ts + 1)]),
        ("search: client = (common)", format!("{sel} WHERE client = ? {order}"), vec![V::Text("10.0.0.0".into())]),
        ("search: client = (rare, 7d)", format!("{sel} WHERE ts_ms >= ? AND ts_ms < ? AND client = ? {order}"), vec![V::Integer(max_ts - 7 * day), V::Integer(max_ts + 1), V::Text("10.0.7.209".into())]),
        ("search: client = (absent)", format!("{sel} WHERE client = ? {order}"), vec![V::Text("192.0.2.1".into())]),
        ("search: domain LIKE %github%", format!("{sel} WHERE qname LIKE ? ESCAPE '\\' {order}"), vec![V::Text("%github%".into())]),
        ("search: domain LIKE %nosuch%", format!("{sel} WHERE qname LIKE ? ESCAPE '\\' {order}"), vec![V::Text("%nosuchname%".into())]),
        ("search: source = blocked, 24h", format!("{sel} WHERE ts_ms >= ? AND ts_ms < ? AND source = ? {order}"), vec![V::Integer(max_ts - day), V::Integer(max_ts + 1), V::Text("blocked".into())]),
        ("search: rcode = SERVFAIL (rare)", format!("{sel} WHERE rcode = ? {order}"), vec![V::Integer(2)]),
        ("search: dnssec = bogus (rare)", format!("{sel} WHERE dnssec = ? {order}"), vec![V::Text("bogus".into())]),
        ("search: qtype = 65 + source cache + 24h", format!("{sel} WHERE ts_ms >= ? AND ts_ms < ? AND qtype = ? AND source = ? {order}"), vec![V::Integer(max_ts - day), V::Integer(max_ts + 1), V::Integer(65), V::Text("cache".into())]),
        ("search: source = refused, last page of 30d", format!("{sel} WHERE ts_ms >= ? AND ts_ms < ? AND source = ? AND (ts_ms < ? OR (ts_ms = ? AND id < ?)) {order}"), vec![V::Integer(min_ts), V::Integer(max_ts + 1), V::Text("refused".into()), V::Integer(min_ts + day), V::Integer(min_ts + day), V::Integer(0)]),
        ("stats: minute rows 24h (summary/timeseries)", "SELECT minute, dimension, key, count, latency_sum_us, latency_max_us FROM stats_minute WHERE minute >= ?1 AND minute < ?2 ORDER BY minute".into(), vec![V::Integer((max_ts - day) / 1000), V::Integer(max_ts / 1000 + 60)]),
        ("stats: minute rows 30d", "SELECT minute, dimension, key, count, latency_sum_us, latency_max_us FROM stats_minute WHERE minute >= ?1 AND minute < ?2 ORDER BY minute".into(), vec![V::Integer((max_ts - 30 * day) / 1000), V::Integer(max_ts / 1000 + 60)]),
        ("stats: top qname 24h", "SELECT key, sum(count) AS c FROM stats_top_hour WHERE kind = ?1 AND hour >= ?2 AND hour < ?3 GROUP BY key ORDER BY c DESC, key ASC LIMIT ?4".into(), vec![V::Text("qname".into()), V::Integer((max_ts - day) / 1000), V::Integer(max_ts / 1000 + 3600), V::Integer(10)]),
        ("stats: top qname 7d", "SELECT key, sum(count) AS c FROM stats_top_hour WHERE kind = ?1 AND hour >= ?2 AND hour < ?3 GROUP BY key ORDER BY c DESC, key ASC LIMIT ?4".into(), vec![V::Text("qname".into()), V::Integer((max_ts - 7 * day) / 1000), V::Integer(max_ts / 1000 + 3600), V::Integer(10)]),
        ("stats: top qname 30d", "SELECT key, sum(count) AS c FROM stats_top_hour WHERE kind = ?1 AND hour >= ?2 AND hour < ?3 GROUP BY key ORDER BY c DESC, key ASC LIMIT ?4".into(), vec![V::Text("qname".into()), V::Integer((max_ts - 30 * day) / 1000), V::Integer(max_ts / 1000 + 3600), V::Integer(10)]),
        ("stats: top client 24h", "SELECT key, sum(count) AS c FROM stats_top_hour WHERE kind = ?1 AND hour >= ?2 AND hour < ?3 GROUP BY key ORDER BY c DESC, key ASC LIMIT ?4".into(), vec![V::Text("client".into()), V::Integer((max_ts - day) / 1000), V::Integer(max_ts / 1000 + 3600), V::Integer(10)]),
        ("stats: top blocked 24h", "SELECT key, sum(count) AS c FROM stats_top_hour WHERE kind = ?1 AND hour >= ?2 AND hour < ?3 GROUP BY key ORDER BY c DESC, key ASC LIMIT ?4".into(), vec![V::Text("blocked".into()), V::Integer((max_ts - day) / 1000), V::Integer(max_ts / 1000 + 3600), V::Integer(10)]),
        ("auth: token verify", "SELECT t.user_id, t.secret_sha256, t.scopes, u.role, t.expires_at, t.revoked_at, t.last_used_at, u.disabled_at FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.id = ?1".into(), vec![V::Integer(1)]),
        ("auth: session lookup", "SELECT s.user_id, s.created_at, s.last_seen_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_sha256 = ?1 AND u.disabled_at IS NULL".into(), vec![V::Blob(vec![0u8; 32])]),
        ("auth: throttle count", "SELECT COUNT(*), MIN(at) FROM login_attempts WHERE username = ?1 AND ip = ?2 AND at > ?3".into(), vec![V::Text("admin".into()), V::Text("10.0.0.1".into()), V::Integer(0)]),
        ("auth: throttle sweep", "SELECT count(*) FROM login_attempts WHERE at <= ?1".into(), vec![V::Integer(0)]),
        ("auth: verify_password by username", "SELECT id, username, role, created_at, updated_at, password_hash FROM users WHERE username = ?1".into(), vec![V::Text("admin".into())]),
        ("auth: tokens of user", "SELECT id, name, scopes, created_at, expires_at, last_used_at, revoked_at FROM api_tokens WHERE user_id = ?1 ORDER BY created_at DESC, id DESC".into(), vec![V::Integer(1)]),
        ("filter: blocklists list", "SELECT id, name FROM blocklists ORDER BY id".into(), vec![]),
        ("filter: custom rules", "SELECT kind, domain FROM custom_rules ORDER BY id".into(), vec![]),
        ("filter: acl rules", "SELECT id, kind, cidr, cert_sha256, action, comment FROM acl_rules ORDER BY id".into(), vec![]),
        ("resolver: upstreams", "SELECT group_name, url, weight FROM upstreams ORDER BY group_name, position".into(), vec![]),
        ("dnssec: keys of zone", "SELECT id FROM dnssec_keys WHERE zone = ?1 AND state IN ('published', 'active', 'retired') ORDER BY id".into(), vec![V::Text("example.com.".into())]),
        ("dnssec: distinct zones", "SELECT DISTINCT zone FROM dnssec_keys ORDER BY zone".into(), vec![]),
        ("dnssec: import dup check", "SELECT EXISTS (SELECT 1 FROM dnssec_keys WHERE zone = ?1 AND algorithm = ?2 AND public_key = ?3 AND state != 'removed')".into(), vec![V::Text("example.com.".into()), V::Integer(13), V::Blob(vec![])]),
        ("certs: allowlist", "SELECT id, sha256, label, enabled, expires_at, created_at FROM client_certs ORDER BY id".into(), vec![]),
        ("retention: purge query_log (count)", "SELECT count(*) FROM query_log WHERE ts_ms < ?1".into(), vec![V::Integer(min_ts + day)]),
        ("retention: purge top_hour (count)", "SELECT count(*) FROM stats_top_hour WHERE hour + 3600 <= ?1".into(), vec![V::Integer((min_ts + day) / 1000)]),
    ]
}

fn queries2(c: &Connection) -> Vec<(&'static str, String, Vec<rusqlite::types::Value>)> {
    use rusqlite::types::Value as V;
    let now = now_ms();
    let (min_ts, max_ts): (i64, i64) = c
        .query_row("SELECT min(ts_ms), max(ts_ms) FROM query_log", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap_or((0, now));
    let mid = (min_ts + max_ts) / 2;
    let mid_id: i64 = c
        .query_row("SELECT id FROM query_log WHERE ts_ms >= ?1 ORDER BY ts_ms, id LIMIT 1", [mid], |r| r.get(0))
        .unwrap_or(0);
    let day = 86_400_000;
    let sel = "SELECT id, ts_ms, client, transport, principal, qname, qtype, rcode, source, source_detail, dnssec, latency_us FROM query_log";
    let order = "ORDER BY ts_ms DESC, id DESC LIMIT 101";
    vec![
        ("V cursor page (row-value)", format!("{sel} WHERE (ts_ms, id) < (?, ?) {order}"), vec![V::Integer(mid), V::Integer(mid_id)]),
        ("V cursor page (row-value) + source refused 30d", format!("{sel} WHERE ts_ms >= ? AND ts_ms < ? AND source = ? AND (ts_ms, id) < (?, ?) {order}"), vec![V::Integer(min_ts), V::Integer(max_ts + 1), V::Text("refused".into()), V::Integer(min_ts + day), V::Integer(0)]),
        ("V purge top_hour sargable (count)", "SELECT count(*) FROM stats_top_hour WHERE hour < ?1 - 3600".into(), vec![V::Integer((min_ts + day) / 1000)]),
        ("V summary 24h aggregated in SQL", "SELECT dimension, key, sum(count), sum(latency_sum_us), max(latency_max_us) FROM stats_minute WHERE minute >= ?1 AND minute < ?2 GROUP BY dimension, key".into(), vec![V::Integer((max_ts - day) / 1000), V::Integer(max_ts / 1000 + 60)]),
        ("V summary 30d aggregated in SQL", "SELECT dimension, key, sum(count), sum(latency_sum_us), max(latency_max_us) FROM stats_minute WHERE minute >= ?1 AND minute < ?2 GROUP BY dimension, key".into(), vec![V::Integer((max_ts - 30 * day) / 1000), V::Integer(max_ts / 1000 + 60)]),
        ("V timeseries 30d/1h aggregated in SQL", "SELECT (minute / 3600) * 3600 AS b, sum(CASE WHEN dimension = 'total' THEN count END), sum(CASE WHEN dimension = 'source' AND key = 'blocked' THEN count END), sum(CASE WHEN dimension = 'source' AND key IN ('cache', 'cache_stale') THEN count END), max(CASE WHEN dimension = 'total' THEN latency_max_us END) FROM stats_minute WHERE minute >= ?1 AND minute < ?2 GROUP BY b ORDER BY b".into(), vec![V::Integer((max_ts - 30 * day) / 1000), V::Integer(max_ts / 1000 + 60)]),
        ("V top qname 30d (reads kind-first index if present)", "SELECT key, sum(count) AS c FROM stats_top_hour WHERE kind = ?1 AND hour >= ?2 AND hour < ?3 GROUP BY key ORDER BY c DESC, key ASC LIMIT ?4".into(), vec![V::Text("qname".into()), V::Integer((max_ts - 30 * day) / 1000), V::Integer(max_ts / 1000 + 3600), V::Integer(10)]),
        ("V count rows (page footer)", "SELECT count(*) FROM query_log".into(), vec![]),
        ("V2 OR-cursor + explicit ts<=cursor + source refused 30d", format!("{sel} WHERE ts_ms >= ? AND ts_ms <= ? AND source = ? AND (ts_ms < ? OR (ts_ms = ? AND id < ?)) {order}"), vec![V::Integer(min_ts), V::Integer(min_ts + day), V::Text("refused".into()), V::Integer(min_ts + day), V::Integer(min_ts + day), V::Integer(0)]),
        ("V2 row-value + explicit ts<=cursor + source refused 30d", format!("{sel} WHERE ts_ms >= ? AND ts_ms <= ? AND source = ? AND (ts_ms, id) < (?, ?) {order}"), vec![V::Integer(min_ts), V::Integer(min_ts + day), V::Text("refused".into()), V::Integer(min_ts + day), V::Integer(0)]),
        ("V2 row-value + explicit ts<=cursor, no filter (middle)", format!("{sel} WHERE ts_ms <= ? AND (ts_ms, id) < (?, ?) {order}"), vec![V::Integer(mid), V::Integer(mid), V::Integer(mid_id)]),
        ("V2 minute rows 30d, columns decoded", "SELECT minute, dimension, key, count, latency_sum_us, latency_max_us FROM stats_minute WHERE minute >= ?1 AND minute < ?2 ORDER BY minute".into(), vec![V::Integer((max_ts - 30 * day) / 1000), V::Integer(max_ts / 1000 + 60)]),
        ("V2 summary 30d aggregated in SQL (repeat)", "SELECT dimension, key, sum(count), sum(latency_sum_us), max(latency_max_us) FROM stats_minute WHERE minute >= ?1 AND minute < ?2 GROUP BY dimension, key".into(), vec![V::Integer((max_ts - 30 * day) / 1000), V::Integer(max_ts / 1000 + 60)]),
    ]
}

fn bench2(db: &str, reps: usize, only: Option<&str>) {
    let c = open(db);
    for (name, sql, args) in queries2(&c) {
        if let Some(o) = only {
            if !name.contains(o) {
                continue;
            }
        }
        let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let plan: Vec<String> = st.query_map(rusqlite::params_from_iter(args.clone()), |r| r.get::<_, String>(3)).unwrap().map(Result::unwrap).collect();
        let mut times = Vec::with_capacity(reps);
        let mut n = 0usize;
        for _ in 0..reps {
            let t = Instant::now();
            let mut st = c.prepare_cached(&sql).unwrap();
            let mut rows = st.query(rusqlite::params_from_iter(args.clone())).unwrap();
            n = 0;
            let decode = name.contains("decoded");
            while let Some(r) = rows.next().unwrap() {
                if decode {
                    let _row: (i64, String, String, i64, i64, i64) = (r.get(0).unwrap(), r.get(1).unwrap(), r.get(2).unwrap(), r.get(3).unwrap(), r.get(4).unwrap(), r.get(5).unwrap());
                }
                n += 1;
            }
            times.push(t.elapsed());
        }
        times.sort();
        let p = |q: f64| times[((times.len() - 1) as f64 * q) as usize].as_secs_f64() * 1000.0;
        println!("{name:<52} {:>9.3} / {:>9.3} / {:>9.3}   rows {n}   plan: {}", p(0.5), p(0.95), p(1.0), plan.join(" | "));
    }
}

fn eqp(db: &str) {
    let c = open(db);
    for (name, sql, args) in queries(&c) {
        println!("## {name}\n   {}", sql.split_whitespace().collect::<Vec<_>>().join(" "));
        let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let rows = st
            .query_map(rusqlite::params_from_iter(args), |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(3)?)))
            .unwrap();
        for r in rows {
            let (_id, _parent, detail) = r.unwrap();
            println!("   -> {detail}");
        }
    }
}

fn bench(db: &str, reps: usize, only: Option<&str>) {
    let c = open(db);
    let cs: i64 = c.pragma_query_value(None, "cache_size", |r| r.get(0)).unwrap();
    println!("cache_size {cs}; reps {reps}; times in ms (p50 / p95 / max), rows returned");
    for (name, sql, args) in queries(&c) {
        if let Some(o) = only {
            if !name.contains(o) {
                continue;
            }
        }
        let mut times = Vec::with_capacity(reps);
        let mut n = 0usize;
        for _ in 0..reps {
            let t = Instant::now();
            let mut st = c.prepare_cached(&sql).unwrap();
            let mut rows = st.query(rusqlite::params_from_iter(args.clone())).unwrap();
            n = 0;
            while let Some(_r) = rows.next().unwrap() {
                n += 1;
            }
            times.push(t.elapsed());
        }
        times.sort();
        let p = |q: f64| times[((times.len() - 1) as f64 * q) as usize].as_secs_f64() * 1000.0;
        println!("{name:<46} {:>9.3} / {:>9.3} / {:>9.3}   rows {n}", p(0.5), p(0.95), p(1.0));
    }
}

/// Time the retention purge of the oldest `days` days inside a transaction that is rolled back,
/// so it can be repeated. Then do one real purge (committed) and report the file sizes.
fn purge(db: &str, days: f64, commit: bool) {
    let mut c = open(db);
    let (min_ts, _max_ts): (i64, i64) = c
        .query_row("SELECT min(ts_ms), max(ts_ms) FROM query_log", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    let cutoff = min_ts + (days * 86_400_000.0) as i64;
    let t = Instant::now();
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
    let rows = tx.execute("DELETE FROM query_log WHERE ts_ms < ?1", [cutoff]).unwrap();
    let t_del = t.elapsed();
    let top = tx.execute("DELETE FROM stats_top_hour WHERE hour + 3600 <= ?1", [cutoff.div_euclid(1000)]).unwrap();
    let t_top = t.elapsed() - t_del;
    if commit {
        tx.commit().unwrap();
    } else {
        tx.rollback().unwrap();
    }
    let total = t.elapsed();
    println!(
        "purge {days} days: query_log {rows} rows in {:.1} ms, stats_top_hour {top} rows in {:.1} ms, total incl. {} {:.1} ms",
        t_del.as_secs_f64() * 1000.0,
        t_top.as_secs_f64() * 1000.0,
        if commit { "commit" } else { "rollback" },
        total.as_secs_f64() * 1000.0
    );
    if commit {
        let wal = std::fs::metadata(format!("{db}-wal")).map(|m| m.len()).unwrap_or(0);
        println!("  wal after purge: {:.1} MiB", wal as f64 / 1048576.0);
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
        sizes(db);
    }
}

fn sql(db: &str, stmt: &str) {
    let c = open(db);
    let t = Instant::now();
    c.execute_batch(stmt).unwrap();
    println!("ok in {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
}

fn pragmas(db: &str) {
    let c = open(db);
    for p in ["journal_mode", "synchronous", "page_size", "cache_size", "mmap_size", "temp_store", "journal_size_limit", "wal_autocheckpoint", "auto_vacuum", "foreign_keys", "busy_timeout", "secure_delete", "locking_mode"] {
        let v: rusqlite::types::Value = c.pragma_query_value(None, p, |r| r.get(0)).unwrap();
        println!("{p} = {v:?}");
    }
    let v: String = c.query_row("SELECT sqlite_version()", [], |r| r.get(0)).unwrap();
    println!("sqlite_version = {v}");
    let opts: Vec<String> = c.prepare("PRAGMA compile_options").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    println!("compile_options = {}", opts.join(" "));
}

fn integrity(db: &str) {
    let c = open(db);
    let t = Instant::now();
    let r: String = c.query_row("PRAGMA quick_check", [], |r| r.get(0)).unwrap();
    println!("quick_check: {r} in {:.2}s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let r: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    println!("integrity_check: {r} in {:.2}s", t.elapsed().as_secs_f64());
}

fn backup(db: &str, dest: &str) {
    let src = open(db);
    let mut dst = Connection::open(dest).unwrap();
    let t = Instant::now();
    let b = rusqlite::backup::Backup::new(&src, &mut dst).unwrap();
    b.run_to_completion(1000, Duration::from_millis(0), None).unwrap();
    println!("online backup in {:.2}s -> {:.1} MiB", t.elapsed().as_secs_f64(), std::fs::metadata(dest).unwrap().len() as f64 / 1048576.0);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("gen") => gen(&a[2], a[3].parse().unwrap(), a.get(4).map_or(30.0, |d| d.parse().unwrap()), a.get(5).map_or(500, |b| b.parse().unwrap())),
        Some("sizes") => sizes(&a[2]),
        Some("eqp") => eqp(&a[2]),
        Some("bench2") => bench2(&a[2], a.get(3).map_or(10, |r| r.parse().unwrap()), a.get(4).map(String::as_str)),
        Some("bench") => bench(&a[2], a.get(3).map_or(20, |r| r.parse().unwrap()), a.get(4).map(String::as_str)),
        Some("purge") => purge(&a[2], a[3].parse().unwrap(), a.get(4).is_some_and(|c| c == "commit")),
        Some("sql") => sql(&a[2], &a[3]),
        Some("pragmas") => pragmas(&a[2]),
        Some("integrity") => integrity(&a[2]),
        Some("backup") => backup(&a[2], &a[3]),
        _ => eprintln!("usage: benchtool gen|sizes|eqp|bench|purge|sql|pragmas|integrity|backup ..."),
    }
}
```

Datasets: `cp template.db qN.db && benchtool gen qN.db <rows> 30` where `template.db` is a
database created by `dnsy user create` (so `schema_migrations` matches the binary). Runs:
`benchtool eqp`, `benchtool bench <db> <reps> [filter]`, `benchtool bench2`, `benchtool purge
<db> <days> [commit]`, `benchtool sizes`, `benchtool pragmas`, `benchtool integrity`,
`benchtool backup <db> <dest>`; `BENCH_SYNC`, `BENCH_CACHE`, `BENCH_MMAP`, `BENCH_TEMP` override
pragmas.

## Appendix B. Experiment driver

```bash
#!/bin/bash
# Schema/pragma experiments for DNSY-62 on scratch copies. Output: experiments.log
B=/home/firat/.cache/dnsy-bench
T=/home/firat/.cache/dnsy-target/DNSY-62/benchtool/release/benchtool
cd $B
exec > $B/experiments.log 2>&1
set -x
echo "=== E1 rewritten queries, baseline schema (q10m)"
$T bench2 $B/q10m.db 5

echo "=== E2 extra indexes on a copy of q10m"
cp $B/q10m.db $B/q10m_idx.db
$T sql $B/q10m_idx.db "CREATE INDEX query_log_client ON query_log(client, ts_ms, id);"
$T sql $B/q10m_idx.db "CREATE INDEX stats_top_hour_kind ON stats_top_hour(kind, hour, key, count);"
$T sql $B/q10m_idx.db "ANALYZE;"
$T sql $B/q10m_idx.db "PRAGMA wal_checkpoint(TRUNCATE);"
$T sizes $B/q10m_idx.db | head -8
$T bench $B/q10m_idx.db 5 "search: client"
$T bench $B/q10m_idx.db 5 "stats: top"
$T bench $B/q10m_idx.db 5 "retention"
$T bench2 $B/q10m_idx.db 5
$T eqp $B/q10m_idx.db | grep -A3 -E "client|top qname 24h"

echo "=== E2b partial index for rare sources / rcodes"
$T sql $B/q10m_idx.db "CREATE INDEX query_log_rare ON query_log(ts_ms, id) WHERE source IN ('blocked','refused','error') OR rcode NOT IN (0,3);"
$T sql $B/q10m_idx.db "ANALYZE;"
$T sizes $B/q10m_idx.db | grep -E "query_log_rare|^size"
$T bench $B/q10m_idx.db 5 "source = refused"
$T bench $B/q10m_idx.db 5 "rcode = SERVFAIL"
$T bench2 $B/q10m_idx.db 5 | grep refused
$T eqp $B/q10m_idx.db | grep -A2 -E "refused|SERVFAIL"
rm -f $B/q10m_idx.db*

echo "=== E3 cache_size / mmap on full scans (q10m)"
$T bench $B/q10m.db 5 "LIKE %nosuch"
BENCH_CACHE=-262144 $T bench $B/q10m.db 5 "LIKE %nosuch"
BENCH_MMAP=2147483648 $T bench $B/q10m.db 5 "LIKE %nosuch"
BENCH_MMAP=2147483648 $T bench $B/q10m.db 5 "client = (absent)"
BENCH_MMAP=2147483648 $T bench $B/q10m.db 5 "top qname 30d"

echo "=== E4 dictionary-encoded copy of query_log (q1m)"
cp $B/q1m.db $B/q1m_enc.db
$T sql $B/q1m_enc.db "CREATE TABLE ql2 (id INTEGER PRIMARY KEY, ts_ms INTEGER NOT NULL, client TEXT NOT NULL, transport INTEGER NOT NULL, principal TEXT, qname TEXT NOT NULL, qtype INTEGER NOT NULL, rcode INTEGER NOT NULL, source INTEGER NOT NULL, source_detail TEXT, dnssec INTEGER NOT NULL, latency_us INTEGER NOT NULL);
INSERT INTO ql2 SELECT id, ts_ms, client, CASE transport WHEN 'udp' THEN 0 WHEN 'tcp' THEN 1 WHEN 'dot' THEN 2 ELSE 3 END, principal, qname, qtype, rcode, CASE source WHEN 'authoritative' THEN 0 WHEN 'cache' THEN 1 WHEN 'cache_stale' THEN 2 WHEN 'upstream' THEN 3 WHEN 'blocked' THEN 4 WHEN 'refused' THEN 5 ELSE 6 END, source_detail, CASE dnssec WHEN 'unchecked' THEN 0 WHEN 'secure' THEN 1 WHEN 'insecure' THEN 2 WHEN 'bogus' THEN 3 ELSE 4 END, latency_us FROM query_log;
CREATE INDEX ql2_ts ON ql2(ts_ms, id);
CREATE TABLE ql3 (id INTEGER PRIMARY KEY, ts_ms INTEGER NOT NULL, client BLOB NOT NULL, transport INTEGER NOT NULL, principal TEXT, qname TEXT NOT NULL, qtype INTEGER NOT NULL, rcode INTEGER NOT NULL, source INTEGER NOT NULL, source_detail TEXT, dnssec INTEGER NOT NULL, latency_us INTEGER NOT NULL);
INSERT INTO ql3 SELECT id, ts_ms, CASE WHEN instr(client, ':') THEN zeroblob(16) ELSE zeroblob(4) END, transport, principal, qname, qtype, rcode, source, source_detail, dnssec, latency_us FROM ql2;
PRAGMA wal_checkpoint(TRUNCATE);"
$T sizes $B/q1m_enc.db | grep -E "^size|query_log |ql2 |ql3 |query_log_ts|ql2_ts"
rm -f $B/q1m_enc.db*

echo "=== E5 synchronous FULL vs NORMAL, batch 500 and 20 (100k rows)"
for sync in FULL NORMAL; do for batch in 500 20; do
  cp $B/template.db $B/sync.db; rm -f $B/sync.db-wal $B/sync.db-shm
  echo "sync=$sync batch=$batch"; BENCH_SYNC=$sync $T gen $B/sync.db 100000 1 $batch | head -1
done; done
rm -f $B/sync.db*

echo "=== E6 WITHOUT ROWID stats_minute vs rowid copy, and ANALYZE time (q10m copy)"
cp $B/q10m.db $B/q10m_an.db
$T sql $B/q10m_an.db "ANALYZE;"
$T sql $B/q10m_an.db "PRAGMA optimize;"
$T sql $B/q10m_an.db "CREATE TABLE sm_rowid (minute INTEGER NOT NULL, dimension TEXT NOT NULL, key TEXT NOT NULL, count INTEGER NOT NULL, latency_sum_us INTEGER NOT NULL, latency_max_us INTEGER NOT NULL, PRIMARY KEY (minute, dimension, key)); INSERT INTO sm_rowid SELECT * FROM stats_minute; PRAGMA wal_checkpoint(TRUNCATE);"
$T sizes $B/q10m_an.db | grep -E "stats_minute|sm_rowid"
rm -f $B/q10m_an.db*

echo "=== E7 online backup, file copy, integrity (q10m)"
$T backup $B/q10m.db $B/q10m_backup.db
rm -f $B/q10m_backup.db
/usr/bin/time -f "cp: %e s" cp $B/q10m.db $B/q10m_cp.db
rm -f $B/q10m_cp.db
$T integrity $B/q10m.db

echo "=== E8 VACUUM after 7-day purge (q10m_purge)"
ls -la $B/q10m_purge.db
/usr/bin/time -f "vacuum: %e s" $T sql $B/q10m_purge.db "VACUUM;"
ls -la $B/q10m_purge.db
rm -f $B/q10m_purge.db*
echo "=== done"
```

## Appendix C. Live measurements

UDP load generator:

```python
#!/usr/bin/env python3
"""Minimal DNS UDP load generator: N worker threads, each with its own socket, sending
random A queries under bench.test. at a target aggregate rate for a duration. Prints achieved
send rate, response rate and latency percentiles."""
import random, socket, struct, sys, threading, time

HOST, PORT = "127.0.0.1", int(sys.argv[1])
RATE = int(sys.argv[2])          # target queries/s (aggregate)
SECS = float(sys.argv[3])
THREADS = int(sys.argv[4]) if len(sys.argv) > 4 else 8
UNIQUE = int(sys.argv[5]) if len(sys.argv) > 5 else 50000


def build(qid, name):
    hdr = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".") if l) + b"\x00"
    return hdr + q + struct.pack(">HH", 1, 1)


def worker(idx, out):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    s.connect((HOST, PORT))
    rnd = random.Random(idx)
    per = RATE / THREADS
    interval = 1.0 / per
    sent = recv = 0
    lats = []
    t_end = time.perf_counter() + SECS
    nxt = time.perf_counter()
    while time.perf_counter() < t_end:
        now = time.perf_counter()
        if now < nxt:
            time.sleep(min(nxt - now, 0.002))
            continue
        nxt += interval
        name = f"h{rnd.randrange(UNIQUE)}.bench.test."
        qid = rnd.randrange(65536)
        t0 = time.perf_counter()
        s.send(build(qid, name))
        sent += 1
        try:
            s.recv(512)
            recv += 1
            lats.append(time.perf_counter() - t0)
        except socket.timeout:
            pass
    out[idx] = (sent, recv, lats)


outs = [None] * THREADS
ths = [threading.Thread(target=worker, args=(i, outs)) for i in range(THREADS)]
t0 = time.perf_counter()
for t in ths:
    t.start()
for t in ths:
    t.join()
el = time.perf_counter() - t0
sent = sum(o[0] for o in outs)
recv = sum(o[1] for o in outs)
lats = sorted(l for o in outs for l in o[2])
p = lambda q: lats[int((len(lats) - 1) * q)] * 1000 if lats else float("nan")
print(f"target {RATE} q/s x {SECS}s: sent {sent} ({sent/el:.0f}/s), answered {recv} ({recv/el:.0f}/s), "
      f"lost {sent-recv}, latency ms p50 {p(0.5):.3f} p95 {p(0.95):.3f} p99 {p(0.99):.3f} max {p(1.0):.3f}")
```

REST latency client:

```python
#!/usr/bin/env python3
"""REST latency bench against a running dnsy API: p50/p95/max over N sequential requests."""
import json, sys, time, urllib.request

BASE = sys.argv[1].rstrip("/")
TOKEN = open(sys.argv[2]).read().split("secret (shown once): ")[1].split()[0]
REPS = int(sys.argv[3]) if len(sys.argv) > 3 else 20
ONLY = sys.argv[4] if len(sys.argv) > 4 else None
now = int(time.time() * 1000)
day = 86_400_000


def get(path):
    req = urllib.request.Request(BASE + path, headers={"Authorization": "Bearer " + TOKEN})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status, r.read()


# Prime: find the time span of the data from the first page.
st, body = get("/api/v1/querylog?limit=1")
first = json.loads(body)
newest = first["items"][0]["ts_ms"] if first.get("items") else now
cursor = None
st, body = get("/api/v1/querylog?limit=100")
page = json.loads(body)
cursor = page.get("next_cursor")

cases = [
    ("GET /querylog (first page, 100)", "/api/v1/querylog?limit=100"),
    ("GET /querylog cursor page", f"/api/v1/querylog?limit=100&cursor={cursor}"),
    ("GET /querylog 24h range", f"/api/v1/querylog?limit=100&from={newest-day}&to={newest+1}"),
    ("GET /querylog client=10.0.0.0", "/api/v1/querylog?limit=100&client=10.0.0.0"),
    ("GET /querylog client=192.0.2.1 (absent)", "/api/v1/querylog?limit=100&client=192.0.2.1"),
    ("GET /querylog domain=github", "/api/v1/querylog?limit=100&domain=github"),
    ("GET /querylog domain=nosuchname", "/api/v1/querylog?limit=100&domain=nosuchname"),
    ("GET /querylog source=blocked 24h", f"/api/v1/querylog?limit=100&source=blocked&from={newest-day}&to={newest+1}"),
    ("GET /querylog outcome=SERVFAIL", "/api/v1/querylog?limit=100&outcome=SERVFAIL"),
    ("GET /querylog dnssec=bogus", "/api/v1/querylog?limit=100&dnssec=bogus"),
    ("GET /stats/summary 24h", f"/api/v1/stats/summary?from={newest-day}&to={newest+1}"),
    ("GET /stats/summary 7d", f"/api/v1/stats/summary?from={newest-7*day}&to={newest+1}"),
    ("GET /stats/summary 30d", f"/api/v1/stats/summary?from={newest-30*day}&to={newest+1}"),
    ("GET /stats/timeseries 24h/5m", f"/api/v1/stats/timeseries?from={newest-day}&to={newest+1}&bucket=300"),
    ("GET /stats/timeseries 30d/1h", f"/api/v1/stats/timeseries?from={newest-30*day}&to={newest+1}&bucket=3600"),
    ("GET /stats/top-domains 24h", f"/api/v1/stats/top-domains?from={newest-day}&to={newest+1}&limit=10"),
    ("GET /stats/top-domains 30d", f"/api/v1/stats/top-domains?from={newest-30*day}&to={newest+1}&limit=10"),
    ("GET /stats/top-clients 24h", f"/api/v1/stats/top-clients?from={newest-day}&to={newest+1}&limit=10"),
    ("GET /stats/top-blocked 30d", f"/api/v1/stats/top-blocked?from={newest-30*day}&to={newest+1}&limit=10"),
    ("GET /users (session-less token path)", "/api/v1/users"),
]
# Session path: login once, then GET /users with the cookie (each request slides last_seen_at).
import http.cookiejar
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
req = urllib.request.Request(BASE + "/api/v1/auth/login", data=json.dumps({"username": "bench", "password": "bench-password-1234"}).encode(), headers={"Content-Type": "application/json"}, method="POST")
try:
    opener.open(req, timeout=30).read()
    def get_session(path):
        with opener.open(BASE + path, timeout=120) as r:
            return r.status, r.read()
    cases.append(("GET /users (session cookie path)", "/api/v1/users"))
    SESSION_CASE = "GET /users (session cookie path)"
except Exception as e:
    print("login failed:", e)
    SESSION_CASE = None

print(f"{'case':<42} {'p50':>9} {'p95':>9} {'max':>9}  bytes")
for name, path in cases:
    if ONLY and ONLY not in name:
        continue
    ts = []
    size = 0
    for _ in range(REPS):
        t0 = time.perf_counter()
        st, body = (get_session if name == SESSION_CASE else get)(path)
        ts.append(time.perf_counter() - t0)
        size = len(body)
        if st != 200:
            print(name, "status", st, body[:200])
            break
    ts.sort()
    p = lambda q: ts[int((len(ts) - 1) * q)] * 1000
    print(f"{name:<42} {p(0.5):>9.2f} {p(0.95):>9.2f} {p(1.0):>9.2f}  {size}")
```

Driver (server started with a config pointing at a data dir holding the 10M-row database, a
`bench.test.` zone with a wildcard A record, API on `127.0.0.1:15380`, DNS on `127.0.0.1:15353`):

```bash
#!/bin/bash
# Live server measurements: REST latency on the 10M DB, query-log writer under UDP load,
# shutdown flush. Output: live.log
B=/home/firat/.cache/dnsy-bench
DNSY=/home/firat/.cache/dnsy-target/DNSY-62/release/dnsy
CFG=$B/live/dnsy.toml
DB=$B/live/data/dnsy.db
cd $B
exec > $B/live.log 2>&1
set -x
count() { python3 -I -c "import sqlite3,sys; c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); print(c.execute('select count(*), max(id) from query_log').fetchone())" $DB; }
walsize() { ls -la $DB-wal 2>/dev/null | awk '{print $5}'; }

echo "=== L0 startup time of a CLI command (opens store, verifies migrations) on 10M DB"
rm -f $DB $DB-wal $DB-shm; cp $B/q10m.db $DB
/usr/bin/time -f "user list on 10M db: %e s" $DNSY --config $CFG user list
/usr/bin/time -f "migrate --status on 10M db: %e s" $DNSY --config $CFG migrate --status | tail -1

echo "=== L1 serve on 10M DB: REST latency, idle"
$DNSY --config $CFG serve --ready-file $B/live/ready.json &
PID=$!
for i in $(seq 1 100); do [ -s $B/live/ready.json ] && break; sleep 0.2; done
cat $B/live/ready.json
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 10

echo "=== L2 UDP load on the 10M DB server (writer throughput and drops)"
for rate in 2000 5000 10000 20000; do
  before=$(count); w0=$(walsize)
  python3 -I $B/udpload.py 15353 $rate 15 8
  sleep 2.5
  after=$(count); w1=$(walsize)
  echo "rate=$rate rows before=$before after=$after wal_before=$w0 wal_after=$w1"
done

echo "=== L3 REST latency while 5000 q/s are being logged"
python3 -I $B/udpload.py 15353 5000 40 8 &
LOAD=$!
sleep 3
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "GET /querylog (first"
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "client=192.0.2.1"
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "summary 24h"
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "top-domains 24h"
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "GET /users"
wait $LOAD

echo "=== L4 CLI write beside the running server under load"
python3 -I $B/udpload.py 15353 5000 10 8 &
LOAD=$!
sleep 2
/usr/bin/time -f "token create beside server: %e s" $DNSY --config $CFG token create --user bench --name beside --scope api:read | head -1
wait $LOAD

echo "=== L5 shutdown: flush time and final counts"
python3 -I $B/udpload.py 15353 10000 5 8 &
sleep 4
before=$(count)
T0=$(date +%s.%N)
kill -TERM $PID
wait $PID
T1=$(date +%s.%N)
echo "shutdown took $(echo "$T1 - $T0" | bc) s; rows before SIGTERM=$before after=$(count)"
ls -la $DB $DB-wal $DB-shm 2>/dev/null
echo "=== done"
```

REST re-run with a valid token (the first run's token was lost to the WAL-less copy, section 5.5):

```bash
#!/bin/bash
# Re-run of the REST cases with a user/token present in the 10M DB. Output: live2.log
B=/home/firat/.cache/dnsy-bench
DNSY=/home/firat/.cache/dnsy-target/DNSY-62/release/dnsy
CFG=$B/live/dnsy.toml
DB=$B/live/data/dnsy.db
cd $B
exec > $B/live2.log 2>&1
set -x
DNSY_PASSWORD=bench-password-1234 $DNSY --config $CFG user create bench --role admin
$DNSY --config $CFG token create --user bench --name api --scope admin --scope api:read --scope api:write > $B/live/token.txt
rm -f $B/live/ready.json
$DNSY --config $CFG serve --ready-file $B/live/ready.json &
PID=$!
for i in $(seq 1 100); do [ -s $B/live/ready.json ] && break; sleep 0.2; done
echo "=== R1 REST latency, idle, 10M DB (10 reps)"
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 10
echo "=== R2 REST latency while 5000 q/s are being logged (5 reps)"
python3 -I $B/udpload.py 15353 5000 45 8 &
LOAD=$!
sleep 3
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "GET /querylog (first"
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "absent"
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "summary 24h"
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "top-domains 24h"
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 5 "GET /users"
wait $LOAD
echo "=== R3 concurrent slow + fast reads (reader pool round-robin): 4 slow LIKE scans in flight, then first-page latency"
for i in 1 2 3 4; do python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 3 "domain=nosuchname" > $B/live/slow$i.log 2>&1 & done
sleep 0.5
python3 -I $B/restbench.py http://127.0.0.1:15380 $B/live/token.txt 10 "GET /querylog (first"
wait
cat $B/live/slow1.log | tail -1
echo "=== R4 CLI write beside the running server under load"
python3 -I $B/udpload.py 15353 5000 10 8 &
LOAD=$!
sleep 2
/usr/bin/time -f "token create beside server: %e s" $DNSY --config $CFG token create --user bench --name beside --scope api:read | head -1
wait $LOAD
kill -TERM $PID
wait $PID
echo "=== done"
```
