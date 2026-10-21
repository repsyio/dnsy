# Security

This page summarises the threat model and the controls that address it. The detailed behaviour is
on the pages linked in each row.

## Reporting a vulnerability

Report vulnerabilities privately to <security@repsy.io>. Do not open a public issue. Reports are
acknowledged within a few working days. The policy is in `SECURITY.md` in the repository.

## Threat model

| Threat | Controls |
| --- | --- |
| Open resolver and amplification | the private-only default ACL (`open_resolver`), per-client rate limiting, both applied before any reply (FORMERR, NOTIMP and BADVERS included, so a dropped client gets nothing and error replies count against the limit), REFUSED for RD=0 queries, RFC 8482 minimal ANY for local zones and REFUSED ANY for forwarded names, REFUSED AXFR/IXFR, minimal FORMERR responses, UDP responses capped at the client's EDNS size (max 1232), DoH tokens ([Filtering](filtering.md), [Architecture](architecture.md)) |
| Cache poisoning | random CSPRNG query IDs and random source ports on connected sockets; pooled upstream sockets rotate after 16 queries, 5 s or 2 s idle and drop queued datagrams before reuse, so a learnt port helps an attacker only inside that window ([Resolver](resolver.md#upstream-client)); responses are scrubbed to in-bailiwick data, a question that does not match byte for byte is discarded, cache keys include DO and CD, DNSSEC validation in `strict` mode by default ([Architecture](architecture.md), [DNSSEC](dnssec.md)) |
| Upstream exhaustion by slow names | identical concurrent cache misses share one upstream exchange, and at most 256 requests wait on one; further identical misses get SERVFAIL (EDE 22) at once instead of holding a listener slot ([Resolver](resolver.md#cache)) |
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
- Behind a TLS-terminating reverse proxy set `[api] secure_cookies = true`: the session and CSRF
  cookies then carry `Secure` and responses send `Strict-Transport-Security`, even though DNSY
  itself speaks plain HTTP to the proxy. `auto` (the default) follows `api.tls_cert`; `false`
  turns both off. DNSY does not read `X-Forwarded-For`, so login throttling and the query log see
  the proxy's address; trusted-proxy support is planned after 1.0.
- Set a DNSSEC key passphrase before enabling signing.
- Leave `doh.require_token = true` on public listeners.
- DNSY is private-only by default: `limits.open_resolver = false` serves only loopback, RFC 1918,
  100.64.0.0/10, ULA and link-local clients, and `limits.per_client_qps` defaults to 50. Setting
  `open_resolver = true` makes the server answer the whole internet; do that only with ACL rules
  and a non-zero `per_client_qps`. `dnsy serve` and `dnsy config check` warn about an open,
  unlimited non-loopback listener. This was an open, unlimited forwarder before; see the
  changelog.
- Connection and in-flight caps are on by default: each of TCP, DoT and DoH has one pool of
  `limits.max_tcp_conns` (1024) shared by all its listen addresses, and one client (IPv4 address
  or IPv6 `/64`) may hold `limits.max_conns_per_client` (16) of them, so a single source cannot
  take every slot. When a pool is full, the connection that has been idle longest (no request in
  flight) is closed to make room for the new one, as BIND does with `tcp-clients`. Only
  connections that finished their TLS handshake (DoT, DoH) or sent a complete query (plain TCP)
  can be chosen, and never one that proved an identity (an mTLS client certificate, a DoH token),
  so a flood of connections that never get that far cannot push out working or authenticated ones.
  A client that already holds its whole share never evicts anyone, one client (IPv4 address or
  IPv6 `/64`) recycles at most one connection per second, and at most 32 newcomers wait for a
  recycled slot at once. The recycled connection is dropped immediately, abandoning any unflushed
  output, so a peer that stopped reading cannot hold the slot. If nothing can be recycled the new
  connection is closed at accept. The accept loop never waits for any of this. UDP is bounded by
  `limits.udp_in_flight` (4096) requests in flight with `limits.udp_in_flight_per_client` (64)
  per client; excess datagrams are dropped. The API listener closes connections that send nothing
  or an incomplete request head within 30 s, closes connections (HTTP/1.1 or HTTP/2, pings notwithstanding) that have had no request in progress for 30 s, serves at most `api.max_conns` (256) connections (and `api.max_conns_per_client` (64) per client address, so one address cannot lock out the admin API) and
  answers 408 to a request whose handler takes longer than 30 s (the live-tail stream is exempt).
  UDP slots are keyed on the unauthenticated source address, so a spoofed source can occupy that
  address's share for the milliseconds a request is in flight; spoofed floods stay bounded by the
  global pool, the rate limiter and the private-only default ACL.
  The rate limiter drops over-limit UDP queries, but a spoofed flood from a victim's address would
  then silence the victim too. So one over-limit UDP query in `limits.rate_limit_slip` (2; 0
  disables) is answered with a minimal reply (the question, TC=1, no records, no larger than the
  query), and a real client falls back to TCP, where it is limited per connection rather than
  starved. Per-client buckets live in sharded tables of bounded size; when a shard is full the least
  recently used of 8 randomly sampled buckets is evicted, so a flood of new spoofed addresses costs
  constant work per packet instead of a scan of the shard.
  Behind a NAT or proxy many users share one address: raise `max_conns_per_client` for DoT/DoH
  front-ends that multiplex many users.
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

- Upstream UDP sockets are pooled for speed. Inside one socket's rotation window (at most 16
  queries or 5 s) its source port is fixed, so an off-path attacker who learnt it guesses only
  the 16-bit ID (about 1 in 65536 per forged answer instead of about 1 in 2^31). DNSSEC `strict`
  validation is the second line of defence for signed zones; see
  [Resolver](resolver.md#upstream-client) for the numbers.

- Live tail (`/querylog/stream`) allows 4 streams per user and 16 overall, with 2 of the 16
  reserved for admins.
- Settings changed through `PATCH /settings*` are runtime-only (the rate limit excepted).
