# Security

This page summarises the threat model and the controls that address it. The detailed behaviour is
on the pages linked in each row.

## Reporting a vulnerability

Report vulnerabilities privately to <security@repsy.io>. Do not open a public issue. Reports are
acknowledged within a few working days. The policy is in `SECURITY.md` in the repository.

## Threat model

| Threat | Controls |
| --- | --- |
| Open resolver and amplification | the private-only default ACL (`open_resolver`), per-client rate limiting, REFUSED for RD=0 queries, minimal FORMERR responses, UDP responses capped at the client's EDNS size (max 1232), DoH tokens ([Filtering](filtering.md), [Architecture](architecture.md)) |
| Cache poisoning | responses are scrubbed to in-bailiwick data, a mismatched question is discarded, cache keys include DO and CD, DNSSEC validation in `strict` mode by default ([Architecture](architecture.md), [DNSSEC](dnssec.md)) |
| DNSSEC attacks | work limits against KeyTrap-style and NSEC3 cost attacks, algorithm checks, signature validity windows, a clock-safety guard ([DNSSEC](dnssec.md)) |
| DNS rebinding | response-IP policy replaces answers pointing into listed networks |
| Credential theft | passwords hashed, tokens stored as SHA-256 of the secret and compared in constant time, sessions stored hashed, login throttling, HttpOnly SameSite=Strict cookies with double-submit CSRF ([Users, tokens and sessions](auth.md)) |
| Secret leakage | tokens, `Authorization`, cookies, DoH path tokens, passwords and the DNSSEC passphrase never reach logs, the query log, API responses or error bodies ([Logging and metrics](logging-and-metrics.md)) |
| Key theft at rest | DNSSEC private keys encrypted with a passphrase when one is configured ([DNSSEC](dnssec.md#encryption-at-rest)) |
| SSRF through blocklist fetch | blocklist URLs to private or loopback addresses are refused unless an admin allows them ([Filtering](filtering.md#url-safety-ssrf)) |
| Path traversal | zone file names are derived from validated zone names only ([Zones](zones.md)) |
| XSS in the UI | strict CSP (`default-src 'self'`, no inline script or style) ([Web UI](web-ui.md#strict-csp)) |
| Unauthorised client on DoT | optional or required mTLS with a client CA and a certificate allowlist ([DoT and mTLS](dot.md)) |

## Hardening checklist

- Run as a dedicated non-root user with `CAP_NET_BIND_SERVICE`.
- Keep `[api] listen` on loopback or put it behind a TLS terminator; set `api.tls_cert` and
  `api.tls_key` to serve TLS directly.
- Set a DNSSEC key passphrase before enabling signing.
- Leave `doh.require_token = true` on public listeners.
- DNSY is private-only by default: `limits.open_resolver = false` serves only loopback, RFC 1918,
  100.64.0.0/10, ULA and link-local clients, and `limits.per_client_qps` defaults to 50. Setting
  `open_resolver = true` makes the server answer the whole internet; do that only with ACL rules
  and a non-zero `per_client_qps`. `dnsy serve` and `dnsy config check` warn about an open,
  unlimited non-loopback listener. This was an open, unlimited forwarder before; see the
  changelog.
- Protect backups: they contain password hashes and DNSSEC keys ([Backup and restore](backup-restore.md)).
- Keep the binary current ([Upgrade](upgrade.md)).

## Third-party crates

Everything on the network path is Rust. Crates worth knowing about when you audit:

- `ring` is the only source of cryptographic primitives (TLS through `rustls`, DNSSEC signatures
  and digests, tokens). It is maintained by a small team and releases are infrequent; if that
  stops being acceptable the exit is `aws-lc-rs`, which is a dependency decision for a later release.
- `rust-embed` embeds the web UI and has a single maintainer. It does one thing (include files at
  compile time) and cannot be replaced cheaply without a build script, so it is accepted and
  watched through `cargo deny` advisories.
- `rusqlite` bundles SQLite, compiled from source with the system C compiler.
- `reqwest` fetches blocklists over HTTPS with the bundled `webpki-roots` trust anchors;
  certificate verification is always on.
- mTLS subjects in logs come from a small DER walk in `dnsy-server`, not an X.509 library; it
  only reads the common name and text subject alternative names, bounds the result and replaces
  control characters. Chain and validity checks stay in `rustls`.

`just check` runs `cargo deny` (advisories, licenses, bans) and `cargo audit` (advisory only: a
finding is printed but does not fail the recipe).

## Known limits

- Settings changed through `PATCH /settings*` are runtime-only (the rate limit excepted).
