# Troubleshooting

Start with `dnsy config check`, `curl -s http://127.0.0.1:5380/readyz` and the server's stderr
(raise `[logging] level` to `debug` temporarily).

## The server does not start

| Symptom | Cause and fix |
| --- | --- |
| `permission denied` binding port 53 or 853 | privileged ports need `CAP_NET_BIND_SERVICE` or root; grant the capability, or listen on a high port and forward |
| `address already in use` | another resolver (`systemd-resolved`, `dnsmasq`) holds the port; stop it or change `[dns]` |
| a config error naming a key | unknown keys and invalid combinations are errors; run `dnsy config check`, see [Configuration reference](configuration.md#validation-rules) |
| `database disk image is malformed`, or sudden query-log or login errors after a crash or disk fault | run `dnsy db check --full`; if it reports problems, stop the server and restore the last `dnsy db backup` (see [Backup and restore](backup-restore.md)) |
| `dnsy db vacuum` says the database is open in another process | the server holds it; stop `dnsy serve` first (backup and check do not need that) |
| `dnsy migrate --status` shows older state than the server reports | it reads without the `-wal` file (so it works on a read-only directory); recent migrations appear after the next checkpoint or a server stop |
| database refused as newer than the binary | run the binary version that wrote it, or restore a backup; see [Upgrade](upgrade.md) |

## Clients get errors

| Symptom | Cause and fix |
| --- | --- |
| `REFUSED` | the client is blocked by an ACL rule, the query has RD=0 (DNSY only offers recursion), or the client is over its rate limit on TCP/DoT |
| no reply at all over UDP | an ACL `drop` rule, or the rate limit (UDP over the limit is dropped) |
| `SERVFAIL` with EDE 22 or 23 | no upstream reachable (22) or an unusable upstream response (23); check [Upstreams](resolver.md) and `GET /api/v1/upstream-groups/{name}/health` |
| `SERVFAIL` with EDE 6, 7, 8, 9, 10 or 12 | DNSSEC validation failed; see below |
| a blocked name answers `0.0.0.0` | that is `filter.block_mode = "null_ip"`; EDE 15 (list) or 17 (custom rule) says why |
| a zone edit does not show | local zones bypass the cache, so check the zone's `load_error` in `GET /api/v1/zones` |

## DNSSEC

- Compare with a non-validating query: `dig +cd @127.0.0.1 name`. If that works and the plain query
  fails, the data is bogus (broken signatures, expired RRSIGs, a stale DS at the parent).
- EDE 7 and 8 (expired or not yet valid) usually mean a wrong clock, on the server or at the
  signer. Until the system clock passes the build time DNSY does not validate at all and
  `/readyz` reports `dnssec_clock_untrusted`.
- A zone you sign yourself fails everywhere when the DS at the registrar does not match
  `dnsy dnssec keys ds <zone>`.
- To keep one broken name working while you fix it, add a negative trust anchor
  (`PATCH /api/v1/settings/dnssec`, or the DNSSEC page); it is runtime-only.

See the [DNSSEC operator guide](dnssec-operator-guide.md) for key and DS procedures.

## DoT, DoH and the API

| Symptom | Cause and fix |
| --- | --- |
| TLS handshake fails on DoT with mTLS | the client certificate is not signed by `dot.client_ca`, has expired, or (with `mtls = "required"`) is missing; see [DoT and mTLS](dot.md) |
| DoH answers 401 | no token, or a rejected one; 403 means the token lacks `dns:query`; 429 means too many rejected tokens from that address |
| DoH answers 404 | the path differs from `[doh] path`; a path token goes after it: `/dns-query/<token>` |
| the UI paths answer 404 | the binary was built without the `embed-ui` feature; use `just build` ([Install](install.md)) |
| API answers 403 on a POST from a script using cookies | cookie sessions need the `X-CSRF-Token` header; use a bearer token for scripts |
| login answers 429 | five failed logins in 15 minutes for that user and address; wait for `Retry-After` |

## Still stuck

Search the [FAQ](faq.md) and the [glossary](glossary.md), then open an issue at
<https://github.com/repsyio/dnsy/issues> with the version (`dnsy version`), the relevant log lines
(secrets are never logged, but check anyway) and the query you ran. Report security problems
privately, see [Security](security.md).
