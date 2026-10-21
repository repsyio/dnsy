# Operations

## Signals

| Signal | Effect |
| --- | --- |
| `SIGTERM`, `SIGINT` | graceful shutdown: listeners stop accepting, in-flight queries finish (5 s), the API closes, the query log is flushed, then the process exits 0 |
| `SIGHUP` | reload without a restart: zone files, TLS certificates for DoT/DoH, the DoT client CA bundle, blocklists and custom rules, the DNSSEC trust anchors (inline and `trust_anchor_file`, re-read from `dnsy.toml`) and a pass of DNSSEC re-signing |

Zone files and certificates are also watched on disk, so `SIGHUP` is a "do it now". Other changes to
`dnsy.toml` (listen addresses, limits, logging, `doh.path`) need a restart; limits, block mode, cache and retention can also be changed through `PATCH /settings` without one. A reload that fails keeps
the previous state and logs the reason.

## Logging

See also [Logging and metrics](logging-and-metrics.md).

Logs go to stderr through `tracing`. `[logging] level` is `trace` to `error`; `format = "json"`
writes one JSON object per line for log shippers. Tokens, `Authorization` headers, cookies,
DoH path tokens, passwords and the DNSSEC key passphrase are never logged.

## Health

`GET /healthz` answers while the process runs. `GET /readyz` answers 200 when the database
works and 503 otherwise; point load balancers and orchestrators at it.

## Background work

`serve` runs these tasks for you: blocklist refresh, zone hot reload, re-signing of DNSSEC zones
(every minute it checks for changed zones, expiring signatures and key state changes), the key
rollover timer (advances key states per the zone policy), client-certificate allowlist refresh
and query-log retention (`[querylog] retention_days`).

## Query log, stats and cache

The query log and stats live in SQLite and are served by the API and UI. Flush the cache from
the UI or the command line:

```sh
dnsy cache flush --token "$DNSY_TOKEN"                    # everything
dnsy cache flush example.com --subtree --token "$DNSY_TOKEN"
```

Dropped queries (ACL `drop`, UDP rate limiting) get no reply on UDP and TCP; over DoH they
become `403`.

## Backups

See [Backup and restore](backup-restore.md) for the procedure; in short:

Stop writing, or use SQLite's online backup, and copy `<data_dir>/dnsy.db` (with its `-wal`
file). It holds users, tokens, rules, upstream groups and DNSSEC private keys; protect the
copy like the keys themselves. Without `DNSY_DNSSEC_PASSPHRASE` or `key_passphrase_file` the
keys are stored unencrypted. Zone files are plain JSON in `[zones] dir`; back them up too.

## Upgrades and migrations

See [Upgrade and migrations](upgrade.md). In short:

`dnsy serve` and `dnsy migrate` apply pending migrations on start. `dnsy migrate --status`
lists applied and pending migrations without touching the database. Migrations are never
edited after release; a database newer than the binary is refused. Back up before upgrading.

## Benchmarks

`just bench` builds the release `dnsy`, starts it against a fake upstream and prints a table of
throughput and latency: UDP cache hit, UDP cache miss (every name unique), TCP (one persistent
connection, 64 clients, 64 clients with 16 queries pipelined) and DoH (HTTP/1.1 and h2, POST).
Pin CPUs for stable numbers, for example `taskset -c 0-5 just bench`; the server and the load
generator share the machine, so compare runs on the same host only. Reference numbers on a
24-thread workstation, unpinned: UDP hit about 310k QPS, TCP persistent connection p50 18 us,
TCP pipeline 16 at 64 clients about 426k QPS.

TCP and DoT listeners set `TCP_NODELAY` and write each length-prefixed answer in a single write,
so a client reusing a connection no longer waits for a delayed ACK (about 41 ms per answer
before). `just bench-micro` runs the criterion micro-benchmarks (codec, cache lookup).

## Building with the UI

`just build` produces the release binary with the web UI embedded (see [Install](install.md)).
