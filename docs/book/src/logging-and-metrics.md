# Logging and metrics

DNSY has three sources of operational data: process logs, the query log with its statistics, and
the health endpoints.

## Process logs

Logs go to stderr through `tracing`. `[logging] level` selects `trace`, `debug`, `info`, `warn` or
`error`; `format = "json"` writes one JSON object per line for a log shipper, `pretty` is for
terminals. Tokens, `Authorization` headers, cookies, DoH path tokens, passwords and the DNSSEC key
passphrase are never logged. A reload that fails (`SIGHUP`, certificate or zone change) keeps the
previous state and logs the reason at `warn`.

Under systemd the logs are in the journal (`journalctl -u dnsy`); in a container they are the
container's stderr.

## Query log and statistics

Every answered query becomes one event: time, client, transport, principal, name, type, response
code, answer source, DNSSEC status and latency. Events are written to SQLite in batches and kept for
`[querylog] retention_days`; `redact_client_ip` stores only the client network. See
[Query log and stats](query-log.md) for the fields, rollups and the filter syntax.

The statistics endpoints are the metrics interface:

| Endpoint | What it gives |
| --- | --- |
| `GET /api/v1/stats/summary` | totals, blocked ratio, cache hit ratio, answers by source and DNSSEC status, latency |
| `GET /api/v1/stats/timeseries` | counts per minute or hour bucket |
| `GET /api/v1/stats/top-domains`, `top-blocked`, `top-clients` | ranked lists |
| `GET /api/v1/cache` | live cache counters |
| `GET /api/v1/dnssec/status` | validation mode, trusted clock, secure and bogus counts of the last 24 hours |
| `GET /api/v1/upstream-groups/{name}/health` | per-upstream health |
| `GET /api/v1/querylog/stream` | live tail as server-sent events |

```sh
curl -s -H "Authorization: Bearer $DNSY_TOKEN" http://127.0.0.1:5380/api/v1/stats/summary | jq
```

There is no Prometheus `/metrics` endpoint in this release. Poll the summary endpoint (it is cheap:
it reads precomputed rollups) or scrape the JSON with an exporter of your own.

## Health

`GET /healthz` is liveness (the process runs). `GET /readyz` is readiness: 200 when the database
answers, 503 otherwise, and a `warnings` list such as `dnssec_clock_untrusted` while the system
clock is earlier than the build time. Neither needs credentials.

## What to alert on

- `/readyz` not 200.
- Cache hit ratio dropping, or upstream health below the number of configured upstreams.
- `bogus` answers rising in `/dnssec/status` (a broken signed zone or a clock problem).
- Query log events dropped (the writer's counter) under load.
