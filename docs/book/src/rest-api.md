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
| 409 | conflict (duplicate name, last admin) |
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
