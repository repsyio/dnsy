# API reference

The management API is a JSON REST API under `/api/v1`, described by an OpenAPI 3.1 document.

| Where | What |
| --- | --- |
| `openapi/dnsy.json` in the repository | the checked-in document; `just openapi-check` (part of `just check`) fails when it drifts from the handler annotations |
| `GET /api/openapi.json` on a running server | the same document, served by the binary |
| `dnsy openapi` | prints the document to stdout |
| [`/api/`](../api/) on the docs site | rustdoc for every crate (the planned Redoc rendering of the OpenAPI document joins it with the Pages pipeline) |

```sh
dnsy openapi | jq '.paths | keys | length'    # how many paths the server exposes
curl -s http://127.0.0.1:5380/api/openapi.json | jq '.info'
```

The [REST API](rest-api.md) page is the narrative reference: authentication (bearer tokens and
session cookies with CSRF), error format (RFC 9457 problem documents), pagination and what each
endpoint group does. Endpoint groups:

| Group | Paths | Page |
| --- | --- | --- |
| Probes and version | `/healthz`, `/readyz`, `/api/v1/version` | [REST API](rest-api.md#probes) |
| Auth, users, tokens | `/api/v1/auth/*`, `/api/v1/users`, `/api/v1/tokens` | [Users, tokens and sessions](auth.md) |
| Zones and records | `/api/v1/zones`, `/api/v1/zones/{name}/records`, `.../export` | [Zones](zones.md) |
| DNSSEC | `/api/v1/zones/{name}/dnssec*`, `/api/v1/settings/dnssec`, `/api/v1/dnssec/status` | [DNSSEC](dnssec.md#managing-dnssec-through-the-api) |
| Filtering and ACL | `/api/v1/blocklists`, `/api/v1/rules`, `/api/v1/acl`, `/api/v1/client-certs` | [Filtering](filtering.md) |
| Upstreams, cache, settings | `/api/v1/upstream-groups`, `/api/v1/cache`, `/api/v1/settings` | [Resolver, upstreams and cache](resolver.md) |
| Query log and stats | `/api/v1/querylog`, `/api/v1/stats/*` | [Query log and stats](query-log.md) |

Generate a client from the document with any OpenAPI tool; the web UI does exactly that for its
TypeScript types (`just web-types`).
