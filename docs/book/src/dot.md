# DoT and mTLS

DNSY serves DNS over TLS (RFC 7858) on every address in `dot.listen` (conventionally `:853`). An
empty `listen` disables the listener.

```toml
[dot]
listen = ["0.0.0.0:853"]
cert = "/etc/dnsy/dot.pem"   # certificate chain, PEM, leaf first
key  = "/etc/dnsy/dot.key"   # private key, PEM (PKCS#8, PKCS#1 or SEC1)
```

`cert` and `key` are required when `listen` is set; the server refuses to start if they cannot be
read or do not match.

## TLS

- TLS 1.2 and 1.3 with rustls' default cipher suites (ring provider); older versions are not
  offered.
- ALPN `dot` is advertised. Clients that send no ALPN extension are still served.
- Framing, pipelining, the idle timeout (`limits.tcp_idle_ms`), the connection cap
  (`limits.max_tcp_conns`) and shutdown draining are the same as for plain TCP. The TLS handshake
  also has to finish within the idle timeout. A plain TCP client talking to the DoT port fails the
  handshake and is closed.
- Responses are padded to a multiple of 468 octets (RFC 8467) when the query carried an EDNS
  Padding option (RFC 7830).
- Queries reach the engine with transport `dot`.

## Certificate hot reload

The certificate and key are re-read when either file changes (the parent directories are
watched, so atomic renames and Kubernetes secret symlink swaps work) and on `SIGHUP`. New
handshakes use the new certificate; established connections are not dropped. If the new files are
unreadable or the key does not match the certificate, the previous certificate stays in use and a
warning is logged (without key material).

## mTLS

```toml
[dot]
mtls = "required"                  # off | optional | required
client_ca = "/etc/dnsy/clients-ca.pem"   # PEM bundle of CAs that issue client certificates
```

- `off`: no client certificate is requested.
- `optional`: clients may connect without a certificate; a presented certificate must be valid.
- `required`: a handshake without a valid certificate is refused (with TLS 1.3 the client sees
  the failure on its first read, not in `connect`).

Validation is rustls' `WebPkiClientVerifier`: the chain must lead to `client_ca`, and the
certificate must be within its validity period. `client_ca` must be set whenever `mtls` is not
`off`.

### Revocation (CRL)

The embedding code can pass a PEM file of CRLs to `MtlsVerifier::new`. Revoked certificates are
refused. `MtlsVerifier::reload` (or `spawn_reload(interval)`) re-reads the CA bundle and CRL
file; if the new files are unreadable, empty or contain no CRL, the previous state is kept and a
warning is logged. With a CRL configured, a certificate whose issuer is not covered by a CRL is
refused.

### Fingerprint allowlist

When an `Allowlist` is attached, a certificate that passes chain validation must also be on the
list, otherwise the handshake fails. Entries are stored in the `client_certs` table (migration
`0008`) and managed through `ClientCertService`: SHA-256 of the DER certificate, a label, an
enabled flag and an optional expiry. `Allowlist::refresh` / `spawn_refresh` load the enabled,
unexpired entries; a list with no entries admits no certificate. Disabling, deleting or expiring
an entry takes effect for new handshakes at the next refresh.

### Resumption and open connections

TLS session resumption is disabled whenever mTLS is on (no session cache, no tickets), because a
resumed session would skip certificate verification. Every handshake re-verifies the chain, the
CRL and the allowlist. A connection that stays open is re-checked on its next query after the CA,
CRL or allowlist changed; if the certificate is no longer permitted the connection is closed.
Enable it with `DotConfig::with_mtls`.

### Client identity

For a connection with a client certificate every request carries the principal
`ClientCert { sha256, subject }`: the fingerprint and a short `CN=... SAN=...` string, available
to ACLs and the query log. Raw certificates are never logged.
