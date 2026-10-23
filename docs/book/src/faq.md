# FAQ

**Is DNSY a recursive resolver?** No. It is a forwarding, caching, validating resolver: it asks
upstream resolvers (that do the recursion) and validates DNSSEC itself. It also serves local zones
authoritatively. See [Resolver, upstreams and cache](resolver.md).

**Does it depend on a DNS library?** No. The wire format, DNSSEC and everything else are written in
the repository; only raw crypto primitives come from `ring`. See [Architecture](architecture.md).

**Which database does it use?** An embedded SQLite file (bundled, no server to run) for users,
tokens, rules, keys and the query log. Zones are plain JSON files. See
[Backup and restore](backup-restore.md).

**Can I use it as an ad blocker?** Yes: add blocklist sources (hosts, domain list or adblock
format) and custom block or allow rules. See [Filtering](filtering.md).

**Does it validate DNSSEC by default?** Yes, in `strict` mode with the root trust anchors built in.
`permissive` serves bogus answers marked as such, `off` disables validation. See [DNSSEC](dnssec.md).

**Can it sign my zones?** Yes: ECDSA P-256 (13) and Ed25519 (15), NSEC or NSEC3, automatic
re-signing and key rollover. You publish the DS record at the registrar yourself. See
[DNSSEC](dnssec.md) and the [operator guide](dnssec-operator-guide.md).

**Do I need a certificate for DoT and DoH?** Yes, both are off until you set `listen` together with
a certificate and key. Certificates reload on `SIGHUP` or when the file changes. See
[DoT and mTLS](dot.md) and [DoH and tokens](doh.md).

**Why does DoH want a token?** `doh.require_token` defaults to true so a public DoH endpoint does
not become an open resolver. Tokens can travel in a header or in the URL path for clients that
cannot set headers.

**Can I change settings in the UI and keep them?** Rules, blocklists, ACL, upstream groups, users
and tokens are stored in the database and survive restarts. Some settings changed through
`PATCH /api/v1/settings` (block mode, cache, retention) and `PATCH /api/v1/settings/dnssec` apply
at once but are runtime-only: after a restart the `dnsy.toml` values return. The per-client rate
limit is the exception that is persisted. Put lasting values in the configuration file.

**Is there a Prometheus endpoint?** Not in this release; see [Logging and metrics](logging-and-metrics.md).

**Does the query log show full answers?** Not yet. The log stores the response code, the answer
source, DNSSEC status and latency per query, but not the answer records or Extended DNS Error codes,
and the UI has no one-click block or allow buttons on log rows; add rules on the Filtering page.

**Which platforms are supported?** Linux is the primary target; the code is portable and release
binaries for Linux (x86_64 and aarch64), macOS (Intel and Apple silicon) and Windows (x86_64) are
published with every release; see [Releases](release.md).

**Where do I report a security issue?** Privately, see [Security](security.md).
