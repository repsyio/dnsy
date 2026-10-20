# Configuration reference

DNSY reads a single TOML file (`dnsy.toml`). Every key is optional, unknown keys are errors, and a
complete annotated example lives in `examples/dnsy.toml`. Any key can be overridden from the
environment as `DNSY_SECTION__KEY` (sections separated by a double underscore), for example
`DNSY_CACHE__SERVE_STALE__ENABLED=false` or `DNSY_DNS__UDP='["127.0.0.1:5353"]'`. Values are read
as TOML (numbers, booleans, arrays) and fall back to plain strings.

| Section | Keys (defaults) |
| --- | --- |
| `server` | `data_dir` (`/var/lib/dnsy`) |
| `dns` | `udp`, `tcp` listen lists (`0.0.0.0:53`; empty disables) |
| `dot` | `listen` (off), `cert`, `key`, `client_ca`, `mtls` = `off`/`optional`/`required` |
| `doh` | `listen` (off), `cert`, `key`, `path` (`/dns-query`), `require_token` (true) |
| `api` | `listen` (`127.0.0.1:5380`), `tls_cert`, `tls_key`, `public_url` |
| `zones` | `dir` (`/var/lib/dnsy/zones`) |
| `resolver` | `timeout_ms` (2000), `attempts` (2), `upstreams` (seed upstreams) |
| `cache` | `enabled` (true), `max_entries` (100000), `min_ttl` (0), `max_ttl` (86400), `negative_max_ttl` (3600), `servfail_ttl` (5), `bogus_ttl` (60) |
| `cache.serve_stale` | `enabled` (true), `max_stale` (86400), `answer_ttl` (30), `client_timeout_ms` (1800) |
| `cache.prefetch` | `enabled` (true), `min_hits` (5), `remaining_ttl_pct` (10) |
| `dnssec` | `validation` = `off`/`permissive`/`strict` (`strict`), `trust_anchors` (root KSK-2017 and KSK-2024 DS), `trust_anchor_file`, `negative_trust_anchors`, `clock_skew_s` (300), `key_passphrase_file` |
| `filter` | `block_mode` = `null_ip`/`nxdomain`/`refused`, `blocklists`, `refresh_interval` (seconds, 86400) |
| `limits` | `per_client_qps` (0 = unlimited), `tcp_idle_ms` (10000), `max_tcp_conns` (1024) |
| `querylog` | `enabled` (true), `retention_days` (30), `redact_client_ip` (false) |
| `logging` | `level` = `trace`..`error` (`info`), `format` = `pretty`/`json` |

The DNSSEC key passphrase can also be supplied in the `DNSY_DNSSEC_PASSPHRASE` environment variable.

## Validation rules

- `dot.listen` needs `dot.cert` and `dot.key`; `dot.mtls` other than `off` needs `dot.client_ca`.
- `doh.listen` needs `doh.cert` and `doh.key`; `doh.path` starts with `/`.
- `api.tls_cert` and `api.tls_key` are set together.
- `cache.min_ttl` must not exceed `cache.max_ttl`; `cache.max_entries` is at least 1;
  `cache.prefetch.remaining_ttl_pct` is 1 to 100.
- Trust anchors are DS records: `keytag algorithm digest-type digest-hex`. With validation on, at
  least one trust anchor (or a `trust_anchor_file`) is required.
