# Configuration reference

DNSY reads a single TOML file (`dnsy.toml`). Every key is optional, unknown keys are errors, and a
complete annotated example lives in `examples/dnsy.toml`. Any key can be overridden from the
environment as `DNSY_SECTION__KEY` (sections separated by a double underscore), for example
`DNSY_CACHE__SERVE_STALE__ENABLED=false` or `DNSY_DNS__UDP='["127.0.0.1:5353"]'`. Values are read
as TOML (numbers, booleans, arrays) and fall back to plain strings.

| Section | Keys (defaults) |
| --- | --- |
| `server` | `data_dir` (`/var/lib/dnsy`), `udp_sockets_per_address` (available parallelism on Linux, 1 elsewhere; see [Operations](operations.md)) |
| `dns` | `udp`, `tcp` listen lists (`0.0.0.0:53`; empty disables) |
| `dot` | `listen` (off), `cert`, `key`, `client_ca`, `client_crl`, `mtls` = `off`/`optional`/`required` |
| `doh` | `listen` (off), `cert`, `key`, `path` (`/dns-query`), `require_token` (true), `trusted_proxies` (empty; CIDRs whose `X-Forwarded-For` is honoured, see [Security](security.md)) |
| `api` | `listen` (`127.0.0.1:5380`), `tls_cert`, `tls_key`, `public_url`, `secure_cookies` (`auto`, `true` or `false`; see [Security](security.md)), `login_hash_per_client` (16), `login_hash_wait_ms` (5000; see [Authentication](auth.md)), `max_conns` (256), `max_conns_per_client` (64), `trusted_proxies` (empty; CIDRs whose `X-Forwarded-For` is honoured, see [Security](security.md)) |
| `zones` | `dir` (`/var/lib/dnsy/zones`) |
| `resolver` | `timeout_ms` (2000), `attempts` (2), `upstreams` (seed upstreams), `case_randomization` (false; 0x20, see [Resolver](resolver.md)) |
| `cache` | `enabled` (true), `max_entries` (100000), `min_ttl` (0), `max_ttl` (86400), `negative_max_ttl` (3600), `servfail_ttl` (5), `bogus_ttl` (60) |
| `cache.serve_stale` | `enabled` (true), `max_stale` (86400), `answer_ttl` (30), `client_timeout_ms` (1800) |
| `cache.prefetch` | `enabled` (true), `min_hits` (5), `remaining_ttl_pct` (10) |
| `dnssec` | `validation` = `off`/`permissive`/`strict` (`strict`), `trust_anchors` (root KSK-2017 and KSK-2024 DS), `trust_anchor_file`, `negative_trust_anchors`, `clock_skew_s` (300), `key_passphrase_file` |
| `filter` | `block_mode` = `null_ip`/`nxdomain`/`refused`, `blocklists`, `refresh_interval` (seconds, 86400) |
| `limits` | `per_client_qps` (50; 0 = unlimited), `open_resolver` (false), `tcp_idle_ms` (10000), `max_tcp_conns` (1024), `max_conns_per_client` (16), `udp_in_flight` (4096), `udp_in_flight_per_client` (64), `rate_limit_slip` (2; 0 = never; see [Security](security.md)) |

| `filter` | `block_mode` = `null_ip`/`nxdomain`/`refused`, `blocklists`, `refresh_interval` (seconds, 86400), `response_ip_blocklist` (CIDRs; see [Filtering](filtering.md#response-ip-policy)) |
| `limits` | `per_client_qps` (50; 0 = unlimited), `open_resolver` (false), `tcp_idle_ms` (10000), `max_tcp_conns` (1024), `max_conns_per_client` (16), `udp_in_flight` (4096), `udp_in_flight_per_client` (64; see [Security](security.md)) |
| `querylog` | `enabled` (true), `retention_days` (30), `redact_client_ip` (false) |

| `limits` | `per_client_qps` (50; 0 = unlimited), `open_resolver` (false), `tcp_idle_ms` (10000), `max_tcp_conns` (1024) |
| `querylog` | `enabled` (true), `retention_days` (30), `redact_client_ip` (false), `sample` (1), `max_size_mb` (0) |
| `logging` | `level` = `trace`..`error` (`info`), `format` = `pretty`/`json` |

**Behaviour change: private-only by default.** With `limits.open_resolver = false` (the default)
DNSY answers only loopback, RFC 1918, 100.64.0.0/10, ULA (`fc00::/7`) and link-local clients and
refuses every other source address. ACL rules stored through the API still apply and win by
longest prefix, so `203.0.113.0/24 allow` admits that network. Set `open_resolver = true` to
restore the old allow-all behaviour; that is only sensible together with a non-zero
`per_client_qps` (now 50 by default; `0` disables the limit) and ACL rules. `dnsy serve` and
`dnsy config check` warn when a non-loopback listener runs with `open_resolver = true` and
`per_client_qps = 0`.

The DNSSEC key passphrase can also be supplied in the `DNSY_DNSSEC_PASSPHRASE` environment variable.

## Validation rules

- `dot.listen` needs `dot.cert` and `dot.key`; `dot.mtls` other than `off` needs `dot.client_ca`.
- `doh.listen` needs `doh.cert` and `doh.key`; `doh.path` starts with `/`.
- `api.tls_cert` and `api.tls_key` are set together.
- `cache.min_ttl` must not exceed `cache.max_ttl`; `cache.max_entries` is at least 1;
  `cache.prefetch.remaining_ttl_pct` is 1 to 100.
- Trust anchors are DS records: `keytag algorithm digest-type digest-hex`. With validation on, at
  least one trust anchor (or a `trust_anchor_file`) is required.
