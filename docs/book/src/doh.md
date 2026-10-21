# DoH and tokens

DNS over HTTPS (RFC 8484) is served by the `dnsy-server` DoH listener on `/dns-query`. It speaks
HTTP/1.1 and HTTP/2 over TLS (ALPN `h2`, `http/1.1`) and uses the same certificate loading and hot
reload as DoT: replacing the PEM files takes effect for new connections, and a bad replacement
keeps the previous certificate.

## Requests

| Method | Request |
| --- | --- |
| `GET` | `/dns-query?dns=<base64url>`, the DNS message in base64url without padding |
| `POST` | `/dns-query`, body is the DNS message, `Content-Type: application/dns-message` |

Responses are `200` with `Content-Type: application/dns-message` and
`Cache-Control: max-age=<n>`, where `n` is the smallest TTL of any record in the response (0 when
there are none). Responses are padded (RFC 8467) when the query carries an EDNS Padding option.

| Status | Meaning |
| --- | --- |
| 400 | bad base64, missing `dns`, not a DNS message, empty body, or more than 65535 octets (body or decoded parameter) |
| 401 | no token (when required) or a rejected token; `WWW-Authenticate: Bearer` |
| 403 | valid token without the `dns:query` scope |
| 404 | any path other than the configured `[doh] path` (default `/dns-query`) and `{path}/{token}` |
| 405 | method other than `GET` and `POST` (`Allow: GET, POST`) |
| 415 | `POST` with a content type other than `application/dns-message` |
| 429 | too many rejected tokens from this client address (`Retry-After`) |

## Tokens

Tokens are created through the API (scope `dns:query`; see [Users, tokens and sessions](auth.md)). A token is
required by default. Send it either way:

- `Authorization: Bearer <token>`
- in the path, `https://dns.example/dns-query/<token>`, for clients that cannot set headers
  (browsers' DoH settings, many mobile resolvers)

A presented token is always verified, even when tokens are not required. Verification and secret
comparison are constant time and done by the token verifier in `dnsy-auth`. The authenticated
principal is attached to the request, so the query log shows which token asked.

Rejected tokens are counted per client (an IPv4 address or an IPv6 `/64`; default 10 per 60 s). Past that limit the client gets
429 before any token is looked at, so the response never reveals whether a token exists. Malformed,
unknown, revoked, expired and wrong-secret tokens all give the same 401.
The table holds at most 10 000 clients; clients that reached the limit are never evicted to make
room, so flooding it with other addresses cannot unblock them.

## Secrets are not logged

The request URI and the `Authorization` header are never logged, never copied into error bodies,
and never passed to the engine, so path tokens cannot reach the query log. Access logging records
only the client address and status. Prefer the header where the client allows it: path tokens can
still be recorded by reverse proxies or browser history in front of or around dnsy.

## Settings

The listener is configured through `DohConfig`: listen addresses, certificate and key, the token
authenticator, `require_token` (default `true`), `max_auth_failures` and `auth_window`. It shares
the idle timeout, connection cap and drain time of the TCP and DoT listeners.
