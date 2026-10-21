# Filtering

This page covers client ACLs, rate limits and blocklists (`dnsy-filter`). In the request pipeline the ACL runs first, then the rate limiter, then blocklists and the allowlist.

## Client ACL

An ACL is an ordered-by-specificity set of rules plus a configurable default action (default `allow` for an `Acl` built directly; the server builds it private-only unless `[limits] open_resolver = true`: loopback, RFC 1918, 100.64/10, ULA and link-local are allowed and everything else is refused, with stored rules still winning by longest prefix). Each rule maps a match to an action:

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

## Response-IP policy

An upstream answer whose A or AAAA record lies inside a listed network is blocked: the client gets the configured block response with EDE 15 (Blocked), and the query log records the source `blocked` with list `response-ip`. This stops DNS rebinding to internal ranges and known-bad addresses. IPv4-mapped IPv6 addresses are matched as IPv4. The check also applies to cached answers, so a change takes effect at once.

The list starts from `[filter] response_ip_blocklist` (CIDRs or single addresses; an invalid entry fails config validation). `PUT /api/v1/response-ip` replaces the whole list live and stores it in the `response_ip_policy` table (migration `0015`); once stored, the list wins over the file after a restart, like the rate limit. An empty list disables the policy. Reading needs `api:read`; changing needs `api:write` (operator or admin).

```toml
[filter]
response_ip_blocklist = ["10.0.0.0/8", "192.168.0.0/16", "fc00::/7"]
```

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

Memory and input are bounded while building a filter: at most 5,000,000 entries (block plus allow, duplicates not counted) and 64 MiB per list source by default, and lines over 2048 bytes are skipped without being buffered. Exceeding a limit fails the build with an error, so the previous filter stays in use. There is no regular-expression support.

## List sources

A source is a local file path or an `http(s)` URL, with a name, a format (`auto`, `hosts`, `domains`, `adblock`), an enabled flag and a refresh interval in seconds. Sources and custom rules are stored in the `blocklists` and `custom_rules` tables (migration `0007`); on first start, `[filter] blocklists` seeds the table and `refresh_interval` becomes each seeded source's interval. Any other scheme (`ftp://`, `file://`) and URLs with embedded credentials are refused.

### Refresh and atomic swap

Creating an enabled source through `POST /blocklists` fetches it immediately (as re-enabling does)
and the response shows the result; a failed first fetch is recorded in `last_status` and the
scheduler retries.

Each refresh fetches one source, then builds a complete new filter from every loaded list plus the custom rules on a blocking thread, and swaps it in with a single pointer store. Queries read the active filter without locking. If the fetch fails, the list holds no usable entry (for example an HTML error page), or the build exceeds a limit, nothing changes: the previous filter and the previous copy of that list stay active, and the failure is recorded in the source's `last_status` (`ok`, `not modified` or `error: ...`).

URL sources use `ETag` / `Last-Modified` for conditional requests (`If-None-Match`, `If-Modified-Since`); a `304` keeps the held list. Validators are only sent while the process holds the matching copy in memory, so after a restart the first fetch is unconditional. Persisted `etag`, `last_modified`, `last_fetched` and `entries` are informational.

### Schedule

A source is refreshed when it has never been fetched or its due time has passed. After a success the next refresh is due `interval` plus up to 10% random jitter later, so lists do not refresh in lockstep; after a failure the retry comes after at most five minutes (plus jitter). The scheduler takes an injectable `Clock`, so tests drive it without sleeping.

### URL safety (SSRF)

- Only `http` and `https`. TLS certificates are verified against the built-in web PKI roots; no proxy from the environment is used.
- URLs must be ASCII: internationalised host names are not supported (write the punycode `xn--` form) and user info is refused. A host ending in a numeric label is an IPv4 address read the way browsers read it (`127.1`, `0x7f.0.0.1` and `2130706433` are all `127.0.0.1`), so the address checks below see the address actually dialled; a malformed one is refused.
- Requests are plain HTTP/1.1, one request per connection, dialled only to the checked addresses.
- The host is resolved once and every address must be public. Loopback, private, link-local (including cloud metadata `169.254.169.254`), unique-local, carrier-grade NAT, multicast, reserved and documentation ranges are refused, as are IPv6 forms that embed them (IPv4-mapped, NAT64, 6to4). The connection is pinned to the checked addresses, so a second lookup cannot return a different answer.
- Redirects are followed by hand, at most 5, each hop re-checked; a redirect to another scheme or from `https` to `http` is refused. The `Location` must be an absolute `http(s)` URL or an absolute path (`/list.txt`); relative and scheme-relative (`//host/x`) locations are refused.
- A source with `allow_private` set skips the address check, for lists served from the local network. It is off by default.
- At most 50 MB per list (checked against `Content-Length` and while streaming; compressed encodings are not requested) and 30 s for the whole fetch, including redirects.
- Files are read with the same size cap.

## Managing filtering through the API

ACL rules, the rate limit, blocklist sources and custom rules can be changed at runtime with the
[REST API](rest-api.md#filtering-upstreams-client-certificates-and-settings) and are active
immediately (the ACL is rebuilt and swapped, the blocklist filter is rebuilt off the hot path). The
block mode is a runtime setting (`PATCH /settings`, `filter.block_mode`). Creating a source whose
location is a file path or a non-public address needs the `admin` scope and `allow_private`; see
URL safety above.

## Web UI

The Filtering page (`/filtering`) manages both halves of the policy without touching the config
file:

- **Blocklist sources**: add a source by name, URL or file path and format (`auto`, `hosts`,
  `domains`, `adblock`); the table shows the entry count, the last fetch time and status, and lets
  you enable or disable a source, refresh it now (the outcome and entry count are shown) or remove
  it after confirming. Admins also see an "Allow private targets and local files" checkbox that
  sends `allow_private`, needed for file paths and private addresses.
- **Custom rules**: add a `block` or `allow` rule for a domain (it covers the name and everything below it); remove a rule after
  confirming. Allow rules win over blocklists, as described above.

The API has no endpoint to test a domain against the filters, so the page has no "test a domain"
box; query the server with `dig` instead.
