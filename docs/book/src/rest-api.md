# REST API

The API lives under `/api/v1`. The rendered reference (Redoc) is on the docs site at
[/rest-api/](../rest-api/); the machine-readable OpenAPI 3.1 document is served at `/api/openapi.json` and
checked in as `openapi/dnsy.json`.

## Probes

| Path | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz` | none | the process is up |
| `GET /readyz` | none | the database answers and every DNSSEC zone can be signed (503 otherwise; a signing failure reads `dnssec_signing_failed`) |
| `GET /api/v1/version` | none | server version |

## Authentication

Every other endpoint needs one of:

- **Bearer token**: `Authorization: Bearer dnsy_...`. The token must carry the scope the endpoint
  needs (`api:read`, `api:write`, `admin`) and its owner's role must still allow it.
- **Session cookie**: the `dnsy_session` cookie set by the web UI login. The user's role must allow
  the scope (viewer: read; operator: read and write; admin: everything).

Cookie requests with an unsafe method (anything but `GET`, `HEAD`, `OPTIONS`) must also send an
`X-CSRF-Token` header equal to the `dnsy_csrf` cookie (double submit); otherwise the answer is 403.
Bearer requests need no CSRF token.

Credentials are never logged: request tracing records only method, path, status and latency.

## Auth, users and tokens

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/login` | none | `{username, password}`; sets `dnsy_session` (HttpOnly) and `dnsy_csrf` cookies, both `SameSite=Strict` (and `Secure` over TLS). Answers 401 on bad credentials, 429 when throttled |
| `POST /api/v1/auth/logout` | session | ends the session and clears the cookies (204) |
| `GET /api/v1/auth/me` | read | the caller and how it authenticated (`session` or `token`) |
| `POST /api/v1/auth/bootstrap` | none | `{code, username, password}`; creates the first admin with the one-time code printed at startup. 401 for a wrong or expired code, 409 once any user exists |
| `PUT /api/v1/auth/me/password` | session | `{current_password, new_password}`; ends every session of the user and returns fresh cookies for this client |
| `GET/POST /api/v1/users` | admin | list, create `{username, password, role}` |
| `GET/PATCH/DELETE /api/v1/users/{id}` | admin | PATCH takes `role`, `password` and/or `disabled`. `disabled: true` blocks login, ends the user's sessions and makes their tokens fail (401) until `disabled: false`; users show `disabled` and `disabled_at`. 409 when it would remove, demote or disable the last active admin |
| `GET/POST /api/v1/tokens` | read / session | list own tokens (admins: all); create `{name, scopes, expires_at?}` |
| `DELETE /api/v1/tokens/{id}` | read | revoke an own token (admins: any); other users' tokens answer 404 |

Passwords are at least 8 characters. Changing a user's password or role, and deleting a user, ends
that user's sessions; a deleted user's tokens stop working immediately. A token only works while its
owner's *current* role still allows the scope it is used for, so a demoted user's old admin token
gets 403.

The token secret is returned only in the `POST /tokens` response (`token`); listings contain
metadata only. Creating a token and changing a password need a session, so a leaked token cannot
mint further tokens or lock the owner out.

## Zones, records and export

Zones are the JSON files of the zones directory; the API reads and writes them through the same
validation as hot reload, so a write the API accepts is a file the server loads. Zone routes
answer 503 when no zones directory is attached.

| Endpoint | Scope | Purpose |
| --- | --- | --- |
| `GET /api/v1/zones` | read | list zones: name, serial, record count, `dnssec_enabled`, `load_error` |
| `POST /api/v1/zones` | write | `{name, default_ttl, soa, records}`; 201 with `ETag`. The records must include an apex NS |
| `GET /api/v1/zones/{name}` | read | settings and SOA, `record_count`, `load_error`; `ETag` header |
| `PUT /api/v1/zones/{name}` | write | replace settings and records (`default_ttl, soa, records`); keeps the DNSSEC policy |
| `DELETE /api/v1/zones/{name}` | write | delete the zone and its file (204) |
| `GET /api/v1/zones/{name}/records` | read | paged: `limit` (default 100, max 1000), `offset`, `type`, `name`; returns `{items, total, limit, offset}` |
| `POST /api/v1/zones/{name}/records` | write | `{name, type, ttl?, value}`; 201 with the record |
| `PUT /api/v1/zones/{name}/records/{id}` | write | replace a record |
| `DELETE /api/v1/zones/{name}/records/{id}` | write | delete a record (204) |
| `GET /api/v1/zones/{name}/export` | read | BIND master file, `text/dns; charset=utf-8`, `Content-Disposition: attachment; filename="<zone>.zone"`. `?signed=true` adds DNSKEY, RRSIG, NSEC or NSEC3 and NSEC3PARAM records (`<zone>.signed.zone`); 409 when the zone is not signed |

A record `id` is a hash of its absolute lowercase owner name, type and value, so it is stable
across reloads and changes when any of those change. Record `name` may be `@`, relative to the
zone, or absolute (trailing dot).

Rules, all enforced on write:

- **Zone names** must map to a safe file name: letters, digits, `-` and `.` only, lowercase on
  disk, no root zone. Anything else (`../x`, `a/b`, backslashes, `_`, IDN in Unicode form) is 400,
  in the body and in the path. Names are case-insensitive; a second zone with the same name is 409.
- **Records** are validated as in zone files: type (A, AAAA, NS, CNAME, PTR, MX, TXT, SRV, CAA),
  rdata, owner inside the zone, and CNAME exclusivity (a CNAME cannot share a name with other
  records and cannot sit at the apex). DNSSEC types and SOA cannot be written by hand. Failures are
  422. A TTL above 2147483647 is 422.
- **Apex NS.** A zone must have at least one NS record at the apex; deleting or changing the last
  one is 422.
- **Duplicates** (same name, type, value) are 409.
- **SOA serial** goes up by one on every successful write (creation uses `soa.serial`, default 1).
- **Limits**: request bodies up to 1 MiB (413), 10000 records per zone, 1000 zones, values up to
  4096 characters. After answering 413 the listener keeps reading and discarding up to 4 MiB of the
  rest of the body (or the declared `Content-Length` if smaller) for at most 2 seconds, holding the
  connection slot meanwhile, so a client that is still uploading can read the 413; then it closes.

**Concurrency.** Zone reads return an `ETag`. Writes (`PUT`, `DELETE`, record `POST`/`PUT`/`DELETE`)
accept `If-Match`; a stale tag is 412 and nothing is written. `If-Match: *` always matches. Without
the header the write goes through. Writes are serialised, and write responses carry the new `ETag`.

Export file names come from the validated zone name, so the `Content-Disposition` header cannot be
influenced beyond `[a-z0-9.-]`.
## DNSSEC

Signing and validation control. Zone routes answer 503 without a zone signer, settings routes
without the engine. Every route that changes something needs the `admin` scope (the `admin` role);
`operator` tokens and viewers get 403. See [DNSSEC](dnssec.md) for the concepts.

| Endpoint | Scope | Purpose |
| --- | --- | --- |
| `GET /api/v1/zones/{name}/dnssec` | read | policy (`enabled`, `algorithm`, `key_layout`, `denial`, `nsec3`, validity, refresh, DNSKEY TTL), `propagation_delay`, keys that are not removed, `next_resign`, `rollover` (`state` plus `rollovers`, every role under way) and `keys_encrypted` |
| `PUT /api/v1/zones/{name}/dnssec` | admin | `{enabled, ...}`: enable, disable or change the policy; fields left out keep their value. Writes the zone file's `dnssec` block. Enabling creates the keys and signs the zone before the response, and is idempotent: repeating it never adds keys. `propagation_delay` (seconds, 0 to 604800, default 3600) is part of the policy. Algorithms other than 13 and 15, bad NSEC3 parameters and bad validity settings are 422 |
| `GET /api/v1/zones/{name}/dnssec/keys` | read | all keys of the zone, removed ones included (public metadata only) |
| `POST /api/v1/zones/{name}/dnssec/keys` | admin | `{role, algorithm?}` generates a key in state `generated`; 201. The zone needs signing enabled (409) |
| `POST /api/v1/zones/{name}/dnssec/keys/{id}/rollover` | admin | `{algorithm?}` (body optional) starts a rollover of an active key's role; 202 with the incoming key. 409 when that role already has a rollover or the key is not active |
| `POST /api/v1/zones/{name}/dnssec/keys/{id}/ds-confirmed` | admin | records that the key's DS is at the parent; 204. Lets a KSK or CSK rollover proceed |
| `POST /api/v1/zones/{name}/dnssec/rollover/abort` | admin | `{role?}` (body optional) withdraws the incoming key of that role, or of every role, and keeps the active key; 200 with the zone's DNSSEC state. 409 when no rollover is in progress (or the new key already became active) |
| `POST /api/v1/dnssec/keys/export` | admin | `{passphrase, zone?}` returns `{bundle}`, the zone keys (all zones when `zone` is omitted) as base64 of a bundle encrypted under `passphrase` (at least 12 characters; 422 otherwise). 403 on a plain-HTTP API listener, because the request carries the passphrase and the response every private key. `dnsy dnssec keys import` restores it |
| `POST /api/v1/dnssec/passphrase` | admin | `{new_passphrase}` re-encrypts every stored key under the new passphrase in one transaction (all or none) and switches the server to it; 200 `{keys_reencrypted}`. Update `DNSY_DNSSEC_PASSPHRASE` or the passphrase file before the next start. The secrets are never logged or returned |
| `GET /api/v1/zones/{name}/dnssec/ds` | read | DS records (SHA-256 then SHA-384) and DNSKEY records of the published and active KSKs and CSKs. JSON, or `Accept: text/plain` for zone-file lines |
| `GET /api/v1/settings/dnssec` | read | `validation` (`off`, `permissive`, `strict`), `negative_trust_anchors` (names) and `negative_trust_anchor_entries` (`name`, `expires_at`; expired anchors are left out), and the read-only `trust_anchors` (owner, key tag, algorithm, digest type, digest) |
| `PATCH /api/v1/settings/dnssec` | admin | `{validation?, negative_trust_anchors?}`; applied at once. A change flushes the resolver cache. The list replaces the old one; an entry is a name or `{name, expires_at}` (Unix time in the future, after which the anchor stops applying; 422 otherwise). The root cannot be an anchor (422) |
| `GET /api/v1/dnssec/status` | read | validation mode, `clock_trusted`, answer counts by DNSSEC status for the last 24 hours, `secure`, `bogus`, `signed_zones` |

Key responses carry `id`, `role`, `algorithm`, `key_tag`, `state` and the state timestamps
(`created_at`, `published_at`, `active_at`, `retired_at`, `removed_at`, `ds_confirmed_at`). No route,
response, error body, log line or OpenAPI schema carries private key material or the key
passphrase; the tests check the responses and the logs against the stored key blobs.

Run-time changes through `PATCH /settings/dnssec` are not written back to the configuration file;
a restart returns to the `[dnssec]` section.

## Query log, stats and cache

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /api/v1/querylog` | read | search the query log, newest first |
| `GET /api/v1/querylog/stream` | write (operator, admin) | live tail as server-sent events |
| `GET /api/v1/stats/summary` | read | totals, blocked ratio, cache hit ratio, answer sources, DNSSEC status counts, latency |
| `GET /api/v1/stats/timeseries` | read | counts per bucket |
| `GET /api/v1/stats/top-domains`, `top-blocked`, `top-clients` | read | ranked lists |
| `GET /api/v1/cache` | read | live cache counters |
| `DELETE /api/v1/cache` | write | flush everything; answers `{"removed": n}` |
| `DELETE /api/v1/cache/entries?name=<name>&subtree=<bool>` | write | flush one name, optionally with everything below it; answers `{"removed": n}` |

`/querylog` filters: `from` (inclusive) and `to` (exclusive) in unix milliseconds, `client`
(exact address), `domain` (case-insensitive substring), `type` (`A`, `AAAA`, or a number),
`outcome` (response code such as `NXDOMAIN`, or a number), `source` (`authoritative`, `cache`,
`cache_stale`, `upstream`, `blocked`, `refused`, `error`) and `dnssec` (`unchecked`, `secure`,
`insecure`, `bogus`, `indeterminate`). `limit` is 1 to 500 (default 100). A page with more rows
behind it carries `next_cursor`; pass it back as `cursor`. Pages stay stable while new rows arrive.
Unknown filter values answer 400.

`/stats/*` take `from` and `to` (unix milliseconds; default the last 24 hours, at most 366 days,
`from` before `to`, else 400). `timeseries` takes `bucket` in seconds (a multiple of 60, default
3600, at most 5000 buckets). The top lists take `limit` (1 to 100, default 10). Rollups are minute
or hour granular for the last two to three days and day granular before that, so buckets touching
the range count whole; `timeseries` buckets under one day have no data for older days.

The live tail sends `query` events (one log record as JSON) and `lagged` when rows were skipped
because the reader was too slow. The server polls the log at its own pace, so a slow reader never
makes it buffer. At most 16 streams run at once; more answer 429 with `Retry-After`. It takes the
same filters as the search.

Query-log responses never contain a token: anything shaped like a DNSY token is replaced with
`[redacted]` (defence in depth; tokens are already redacted before logging). With
`querylog.redact_client_ip` on, client addresses are shown as their /24 or /48 network, and the
`client` filter matches the redacted form.

## Filtering, upstreams, client certificates and settings

Changes made through these routes are stored and applied to the running server at once. Reads need
`api:read`; changes need `api:write` unless noted. See [Filtering](filtering.md) for what the rules
and lists do.

| Route | Purpose |
| --- | --- |
| `GET /acl`, `POST /acl`, `DELETE /acl/{id}` | CIDR (or client-certificate fingerprint) rules with action `allow`, `refuse` or `drop`; longest prefix wins. A single address blocks one IP |
| `PUT /acl/rate-limit` | Per-client queries per second (`0` = unlimited, at most 1,000,000), persisted |
| `GET /response-ip`, `PUT /response-ip` | Response-IP networks `{"cidrs": [...]}`; `PUT` replaces the list live and persists it (invalid network `422`) |
| `GET/POST /blocklists`, `PATCH/DELETE /blocklists/{id}` | List sources and their last fetch status (`last_fetched`, `last_status`, `entries`); `PATCH` enables or disables |
| `POST /blocklists/{id}/refresh` | Fetch now: `{"outcome": "updated" \| "not_modified"}`; a failed fetch is `422` and the previous list stays active |
| `GET/POST /rules`, `DELETE /rules/{id}` | Custom `block` or `allow` rules for a domain and its subdomains (allow wins) |
| `GET /upstream-groups`, `GET /upstream-groups/{name}`, `GET /upstream-groups/{name}/health` | Groups, members and live health (`available`, `consecutive_failures`, `latency_ms`) |
| `POST /upstream-groups`, `PUT/DELETE /upstream-groups/{name}` | Create, replace, delete a group (**admin**) |
| `POST /upstream-groups/{name}/upstreams`, `DELETE /upstream-groups/{name}/upstreams/{index}` | Add or remove one member (**admin**) |
| `GET/POST /client-certs`, `PATCH/DELETE /client-certs/{id}` | mTLS fingerprint allowlist with label and optional expiry (**admin**, reads too) |
| `GET/PATCH /settings` | The runtime-changeable settings (**admin**) |

A group change is validated as a whole (one default group, no pattern routed twice) before
anything is stored. Replacing a group set resets the health counters.

**Blocklist sources and SSRF.** A source is an `http(s)` URL or a file path. A URL whose host is an
IP literal in a private, loopback, link-local or otherwise non-public range, `localhost`, and any
file path are refused unless `allow_private` is set, and setting it (or using such a location)
needs the `admin` scope: a write-scope token gets `403`. Host names are resolved and pinned at
fetch time, where every non-public address is refused for sources without `allow_private`.

**Client certificates.** Adding, disabling, enabling or removing a fingerprint reloads the DoT
allowlist, which bumps its generation so connections that are already open are checked again and
a removed certificate is cut off, not only refused on the next handshake. If the reload fails the
request answers `500`; the change is stored and the periodic reload applies it.

**Settings.** `PATCH /settings` takes a partial document; `GET` returns the same shape:

```json
{
  "filter":   { "block_mode": "null_ip" },
  "querylog": { "retention_days": 30 },
  "limits":   { "per_client_qps": 0 },
  "cache":    { "min_ttl": 0, "max_ttl": 86400,
                "serve_stale": { "enabled": true }, "prefetch": { "enabled": true } }
}
```

The patch is applied to a copy of the running configuration and checked with the same validation
the config loader uses (for example `min_ttl` must not exceed `max_ttl`) before anything changes;
a bad value is `422` and nothing changes. Any other key, such as listeners, TLS paths or the
DNSSEC key passphrase, is not part of the model and is rejected as unknown, so no secret is ever
read or written here. Settings are in effect immediately but are not written to `dnsy.toml`; after
a restart the file applies again (the rate limit is the exception, it is persisted with the ACL).

## Errors

Errors are RFC 9457 `application/problem+json`:

```json
{ "type": "https://dnsy.dev/problems/forbidden", "title": "Forbidden", "status": 403,
  "detail": "missing or invalid CSRF token" }
```

| Status | Meaning |
| --- | --- |
| 400 | malformed request |
| 401 | missing, invalid or expired credentials (`WWW-Authenticate: Bearer`) |
| 403 | credential lacks the scope, or CSRF check failed |
| 404 | no such resource |
| 409 | conflict (duplicate name, record or zone, last admin) |
| 412 | `If-Match` does not match the current `ETag` |
| 413 | request body too large |
| 422 | well-formed request with invalid data (record rdata, CNAME conflict, missing apex NS) |
| 429 | too many failed logins or too many live-tail streams; `Retry-After` header and `retry_after_secs` field |
| 500 | internal error; details are logged, never returned |
| 503 | not ready, or the service behind the endpoint (the cache) is not running |

## Security headers and the web UI

All responses carry `Content-Security-Policy: default-src 'self'` (plus `frame-ancestors 'none'`),
`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` and, when
the API is served over TLS, `Strict-Transport-Security`. API responses are `Cache-Control: no-store`.

With the `embed-ui` cargo feature the built Angular app (`web/dist/dnsy/browser`) is embedded in the
binary and served for all non-API paths; unknown client-side routes fall back to `index.html`.
Build the UI first (`just web`), then `cargo build --features embed-ui`.

## OpenAPI

The spec is generated from the handler annotations (`utoipa`). After changing an endpoint run
`just openapi` and commit `openapi/dnsy.json`. `just check` (and so `just ci`) runs
`just openapi-check`, and a unit test fails when the checked-in file is stale.

## For route authors

Each route group is a file `crates/dnsy-api/src/routes/<group>.rs` exposing
`pub fn router() -> OpenApiRouter<ApiState>` with paths relative to `/api/v1`, registered by one
`.merge(<group>::router())` line in `routes/mod.rs`. Guard handlers by taking
`RequireScope<Read>`, `RequireScope<Write>` or `RequireScope<AdminScope>` as an argument, and return
`Result<_, ApiError>`.
