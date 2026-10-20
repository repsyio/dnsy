# Filtering

Blocklists and the allowlist are described elsewhere; this page covers client ACLs and rate limits (`dnsy-filter`). In the request pipeline the ACL runs first, then the rate limiter, then blocklists.

## Client ACL

An ACL is an ordered-by-specificity set of rules plus a configurable default action (default `allow`). Each rule maps a match to an action:

| Action | Effect |
| --- | --- |
| `allow` | process the request |
| `refuse` | answer REFUSED |
| `drop` | send no reply |

Rule matches:

- **CIDR**, IPv4 or IPv6 (`10.0.0.0/8`, `2001:db8::/32`). Host bits are ignored. IPv4-mapped IPv6 clients (`::ffff:a.b.c.d`) are matched as IPv4.
- **Client certificate**, by SHA-256 fingerprint, for mTLS-authenticated DoT clients.

Resolution: a client-certificate rule matching the request principal wins; otherwise the longest matching prefix wins; equal prefixes resolve to the stricter action (`drop` over `refuse` over `allow`); with no match the default applies. Rules are stored in the `acl_rules` table (migration `0004`); a duplicate network or fingerprint is rejected.

## Rate limiting

Each client gets a token bucket refilling at `qps` tokens per second with a burst of `2 x qps`. Clients are keyed by IPv4 `/32` and IPv6 `/64` (a subscriber controls a whole `/64`, so per-address keys would be trivially bypassed). Checking and taking a token is one atomic step, and the number of tracked clients is bounded: when the table is full, fully refilled buckets are discarded first, then the least recently seen one.

Over the limit, UDP queries are dropped silently (a reply to a spoofed source address would amplify an attack); TCP, DoT and DoH queries get REFUSED. A `qps` of `0` disables limiting. The limit is stored in the `rate_limits` table.
