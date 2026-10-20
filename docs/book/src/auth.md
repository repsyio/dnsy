# Users, tokens and sessions

## Roles and scopes

Roles are `admin`, `operator` and `viewer`. Tokens carry scopes (`dns:query`, `api:read`,
`api:write`, `admin`). A token's scopes must be a subset of what its owner's role allows
(viewer: `api:read`; operator: everything except `admin`; admin: all). The role is checked
again on every use, so demoting a user narrows their existing tokens.

## API tokens

Format: `dnsy_<base32 id>_<base64url secret>` (8-byte id, 32-byte secret). The secret is shown
once, when the token is created. Only `sha256(secret)` is stored, compared in constant time.
A token can have an expiry and can be revoked at any time. Expired, revoked, unknown and
tampered tokens all fail with the same error. `last_used_at` is refreshed at most once per
minute.

## Sessions

The web UI uses a server-side session with a 256-bit random id (stored hashed). A session ends
after 30 minutes without use or 12 hours after login, whichever comes first. Logging in again
discards the presented session and issues a new id.

## Login throttling

After 5 failed logins for the same username and client IP within 15 minutes, further attempts
are refused with HTTP 429 and a `Retry-After` header until the oldest failure leaves the
window. A successful login clears the counter.
