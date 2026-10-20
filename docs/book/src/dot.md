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

Client certificate authentication (`dot.mtls`, `dot.client_ca`) is delivered by a separate story.
The listener already accepts a rustls client certificate verifier through
`DotConfig::client_verifier`; without one, no client certificate is requested.
