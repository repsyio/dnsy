# Users, tokens and sessions

## Roles and scopes

Roles are `admin`, `operator` and `viewer`. Tokens carry scopes (`dns:query`, `api:read`,
`api:write`, `admin`). A token's scopes must be a subset of what its owner's role allows
(viewer: `api:read`; operator: everything except `admin`; admin: all). The role is checked
again on every use, so demoting a user narrows their existing tokens.

Scopes are flat: `admin` is not a superset of `api:read` or `api:write`. Each route requires one
scope (viewer-level reads `api:read`, changes `api:write`, administration `admin`), so an
admin-only token that should also read must be minted with all three. `GET /api/v1/version`,
`/healthz`, `/readyz` and `/api/openapi.json` need no credential by design. The
route-by-role expectations are a committed table in `crates/dnsy-api/src/tests_matrix.rs`; a new
route without a row fails the test suite.

Limits: a token name is at most 128 characters, a username at most 64 and a user holds at most
100 tokens; the API answers 422 with a problem detail beyond that.

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

## Disabling users

`PATCH /users/{id}` with `{"disabled": true}` disables an account: login fails like a wrong
password, the user's sessions are deleted at once and their API and DoH tokens are refused (401)
until `{"disabled": false}`; old sessions stay gone. The last active admin cannot be disabled,
demoted or deleted (409), so an installation cannot lock itself out; a disabled admin does not
count as one. `dnsy user disable|enable <username>` does the same offline.

## Login throttling

The API takes the client address from the TCP peer. Behind a reverse proxy every client shares
the proxy's address, so the limits below apply to all of them together; trusted-proxy headers are
not interpreted. Addresses are grouped before counting: an IPv6 client counts as its `/64`, and an
IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) counts as the plain IPv4 address.

Login attempts are limited in one write transaction, so concurrent requests cannot exceed the
limits:

- **Per username and client**: at most 5 attempts within 15 minutes, and at most 20 per client
  across all usernames. Further attempts get HTTP 429 with `Retry-After` until the oldest one
  leaves the window. A locked-out client cannot lock the account out for anyone else.
- **Per username, across clients**: after 10 attempts on one username within the window from
  clients that have not recently logged in as that user, each further attempt from such a client
  must wait `2^n` seconds after the previous one, capped at 60 seconds. This slows distributed
  guessing without ever locking the account; the correct password is delayed in the same way (429,
  never exempt). Clients that completed a login as the user in the last 7 days (the last 8 are
  remembered in memory and forgotten on restart) are exempt, so an attacker cannot slow the
  owner's usual address. Behind a reverse proxy all users share the proxy's address, so this
  exemption makes the account-wide delay ineffective there; only the per-client limits protect.

Refused attempts are not counted, so hammering a locked client does not extend the lock. A
successful login clears the username's counters. Passwords longer than 1 KiB are refused (400)
before hashing. At most as many argon2 hashes as CPUs run at once, and at most 2 per client:
when no slot is free a login gets 503 with `Retry-After: 1`. The slot is taken before the
attempt is recorded, so a busy refusal never counts as a failed password.

## Web UI

The users page (admin), the tokens page and the profile page in the web UI wrap this API; see
[Web UI](web-ui.md#users-tokens-and-profile). The token secret is shown once in a dialog and held
only in memory until the dialog closes. Changing a password keeps the current browser signed in
(a new session is issued) and ends every other session; changing a user's role or resetting
their password as an admin ends all of that user's sessions.
