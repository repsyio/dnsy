# Query log and stats

DNSY records every answered query. Events pass through a bounded channel (10,000 events) to a
batched SQLite writer (up to 500 events or 1 second per batch). When the channel is full, events are
dropped and counted instead of slowing DNS. A batch that fails to write (disk full, locked or
read-only database) counts its events as dropped as well and increments a flush-error counter.
`GET /api/v1/stats/summary` reports both since the server started, as `querylog_dropped` and
`querylog_flush_errors`; watch them for gaps in the log.

## Sampling, size cap and a full disk

- `[querylog] sample = N` keeps one raw `query_log` row in N queries (default 1: all). Only raw rows
  are sampled: minute rollups and hourly top-N counts include every query, so the stats endpoints
  stay exact while the log grows N times slower. Searching the log shows the sample; at high QPS use
  100 or more. `0` is treated as `1`.
- `[querylog] max_size_mb = M` (default 0: unlimited) caps the live data in the database (used pages,
  not the file size; freed pages are reused). After each retention pass, while the data exceeds the
  cap, the oldest UTC day of raw rows is deleted. Rollups are kept. Today's rows are never purged;
  if only today remains, a warning is logged. The cap is read at startup.
- When a write fails with `SQLITE_FULL`, the events of that batch are dropped and counted, the log
  warns once, and `/readyz` reports the warning `querylog_disk_full` (the status stays 200). The
  warning clears after the next successful write; free disk space or lower `retention_days` or
  `max_size_mb`.

## What is stored

Per query: time, client address, transport, principal, query name (lowercased), type, response code,
answer source (`authoritative`, `cache`, `cache_stale`, `upstream`, `blocked`, `refused`, `error`;
with the upstream address or blocklist name as detail), DNSSEC status and latency in microseconds.

With client redaction enabled, only the /24 (IPv4) or /48 (IPv6) network address is stored, in the
log and in the rollups.

## Rollups and stats

Per minute: counts by response code, answer source and DNSSEC status, plus latency sum and maximum.
Per hour: top query names, top blocked names and top clients. The summary reports the cache hit
ratio (`cache` plus `cache_stale` answers over those plus `upstream` answers), stale answers, and
secure and bogus counts. Rollup buckets are whole minutes or hours, so a range includes any bucket
it touches.

## Searching

Filter by time range, client, query-name substring, type, response code, answer source and DNSSEC
status. Results are newest first with keyset pagination: pass the returned cursor to get the next
page; pages stay stable while new rows arrive, and every page costs the same however deep it is
(the cursor bounds the index range).

Three indexes serve the searches:

| Index | Serves | Size at 10 million rows |
| --- | --- | --- |
| `query_log_ts (ts_ms, id)` | time ranges, paging, unfiltered newest-first | in the base table size |
| `query_log_client (client, ts_ms, id)` (migration 0010) | `client =` | about 296 MiB, builds in about 7 s |
| `query_log_rare (ts_ms, id)` partial (migration 0011) | source `blocked`, `refused`, `error` and response codes other than NOERROR and NXDOMAIN | about 24 MiB, builds in about 2 s |

On a 10 million row log a middle cursor page went from 125 ms to 0.03 ms, `client =` from 1.6 s
to 0.01 ms and a deep `source = refused` page from 274 ms to 24 ms (measurements in the database
analysis). Other filters (query name substring, type, DNSSEC status, common sources) still scan the
time index, which is fast for common values and slow for values that almost never match.

The first start after an upgrade builds the two indexes while holding the database: about 7 s per
10 million rows for the client index. The server logs `applying migration 0010, this can take a
while on a large query log` before it starts and does not accept connections until it finishes.
The indexes add write work per logged query (two indexes instead of one) and file size
(about 30 percent for the client index).

## Reading it over the API

`GET /api/v1/querylog` searches with the filters above and a cursor, and
`GET /api/v1/querylog/stream` tails new rows as server-sent events (operator or admin, at most 4
streams per user and 16 overall). `GET /api/v1/stats/*` serves the summary, timeseries and top lists, and
`GET /api/v1/cache` the live cache counters. See [REST API](rest-api.md). The API applies client
redaction again on output and replaces anything shaped like a token with `[redacted]`.

## In the web UI

The query log page (`/query-log`, see [Web UI](web-ui.md#query-log)) is a front end for the search
and the live tail: filters, a cursor-paged table, a detail drawer and a tail toggle.

## Retention

A background task, once an hour, deletes raw rows older than the retention period, hourly top-N
rollups that end before it, and expired sessions. Minute rollups are kept 400 days, or the
retention period when that is longer (the stats range is capped at 366 days, so nothing reads
older ones).

Deletes run in transactions of at most 50 000 rows, so lowering the retention on a large log
(`PATCH /settings`) never blocks the query-log writer for more than a few milliseconds at a time
and the write-ahead log stays small. The task also runs `PRAGMA optimize` once a day (and the
server once more on shutdown) so SQLite refreshes planner statistics only where needed.
