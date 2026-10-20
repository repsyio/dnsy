# REST API

The API lives under `/api/v1`. The generated reference is served by the running site at
[/api/](../api/); the machine-readable OpenAPI 3.1 document is served at `/api/openapi.json` and
checked in as `openapi/dnsy.json`.

## Probes

| Path | Auth | Purpose |
| --- | --- | --- |
| `GET /healthz` | none | the process is up |
| `GET /readyz` | none | the database answers (503 otherwise) |
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
| `GET/PATCH/DELETE /api/v1/users/{id}` | admin | PATCH takes `role` and/or `password`. 409 when it would remove or demote the last admin |
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
| `GET /api/v1/zones/{name}/export` | read | BIND master file, `text/dns; charset=utf-8`, `Content-Disposition: attachment; filename="<zone>.zone"` |

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
  4096 characters.

**Concurrency.** Zone reads return an `ETag`. Writes (`PUT`, `DELETE`, record `POST`/`PUT`/`DELETE`)
accept `If-Match`; a stale tag is 412 and nothing is written. `If-Match: *` always matches. Without
the header the write goes through. Writes are serialised, and write responses carry the new `ETag`.

Export file names come from the validated zone name, so the `Content-Disposition` header cannot be
influenced beyond `[a-z0-9.-]`.

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
| 429 | too many failed logins; `Retry-After` header and `retry_after_secs` field |
| 500 | internal error; details are logged, never returned |
| 503 | not ready |

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
