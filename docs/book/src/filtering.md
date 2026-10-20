# Filtering

This page covers client ACLs, rate limits and blocklists (`dnsy-filter`). In the request pipeline the ACL runs first, then the rate limiter, then blocklists and the allowlist.

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

## Blocklists

A list source is parsed in one of three formats (or `auto`, which detects the format line by line):

| Format | Example | Notes |
| --- | --- | --- |
| hosts | `0.0.0.0 ads.example.com` | any IP address, one or more names per line; `localhost` style entries are ignored |
| domains | `ads.example.com`, `*.ads.example.com` | one name per line; a leading `*.` is the same as the bare name |
| adblock subset | `||ads.example.com^`, `@@||ok.example.com^` | `||name^` blocks, `@@||name^` allows; nothing else of the syntax is supported |

`#` and `!` start comments, `[Adblock ...]` headers are skipped, and a UTF-8 BOM and CRLF line endings are tolerated. Internationalised names must already be punycode (`xn--...`); a name with non-ASCII bytes is invalid. Invalid lines (bad characters, IP-address-only lines, bad UTF-8, over-long lines) are counted in the parse statistics and never abort loading.

### Matching

Every entry is a suffix: blocking `example.com` blocks `example.com` and everything below it, but not `notexample.com`. Matching is ASCII case-insensitive. The most specific rule does not matter for blocking; **the allowlist always wins**: an allow entry (adblock `@@||` or a custom allow rule) on the queried name or any parent makes the verdict `Allow`, even if a longer or shorter block entry exists. Custom block rules are reported as list `custom`.

### Block responses

| Mode | Answer |
| --- | --- |
| `NxDomain` | NXDOMAIN |
| `NullIp` | `0.0.0.0` for A, `::` for AAAA, empty NOERROR for other types |
| `Refused` | REFUSED |
| `CustomIp` | operator addresses; a family without an address answers empty NOERROR |

When the query carried EDNS, the response includes an Extended DNS Error (RFC 8914): code 15 (Blocked) for blocklist matches, 17 (Filtered) for custom rules. Synthesised answers use a TTL of 60 s.

### Limits

Memory and input are bounded while building a filter: at most 5,000,000 entries (block plus allow, duplicates not counted) and 64 MiB per list source by default, and lines over 2048 bytes are skipped without being buffered. Exceeding a limit fails the build with an error, so the previous filter stays in use. There is no regular-expression support. Loading lists from files or URLs on a schedule, and their persistence, arrive with DNSY-27.
