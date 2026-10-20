# Query log and stats

DNSY records every answered query. Events pass through a bounded channel (10,000 events) to a
batched SQLite writer (up to 500 events or 1 second per batch). When the channel is full, events are
dropped and counted instead of slowing DNS; the dropped counter is exposed by the writer.

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
page; pages stay stable while new rows arrive.

## Reading it over the API

`GET /api/v1/querylog` searches with the filters above and a cursor, and
`GET /api/v1/querylog/stream` tails new rows as server-sent events (operator or admin, at most 16
streams). `GET /api/v1/stats/*` serves the summary, timeseries and top lists, and
`GET /api/v1/cache` the live cache counters. See [REST API](rest-api.md). The API applies client
redaction again on output and replaces anything shaped like a token with `[redacted]`.

## In the web UI

The query log page (`/query-log`, see [Web UI](web-ui.md#query-log)) is a front end for the search
and the live tail: filters, a cursor-paged table, a detail drawer and a tail toggle.

## Retention

A background task deletes raw rows older than the retention period, and hourly top-N rollups that
end before it. Minute rollups are small and kept.
