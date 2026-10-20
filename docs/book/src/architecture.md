# Architecture

Stub: crate layout and the request pipeline. See the design spec in the repository for the current contract.

## Handler and plain DNS listeners

`dnsy-engine::handler` defines the transport-agnostic contract: a `Handler` takes a `RequestContext` (client address, transport, optional principal, receive time) and a decoded `Message` and returns the response `Message`. DoT and DoH reuse it unchanged. Until the full pipeline is wired, `RefusedHandler` answers REFUSED.

`dnsy-server` runs the UDP and TCP listeners (`[dns] udp`/`tcp`) and only frames bytes:

- **UDP:** the response limit is `min(client EDNS payload, 1232)`, or 512 without EDNS. Larger answers are truncated by `Message::encode` and flagged TC, so clients retry over TCP. In-flight requests per socket are bounded and excess datagrams are dropped.
- **TCP:** RFC 1035 two-byte framing with RFC 7766 pipelining; responses are written as they complete, in any order. At most `max_tcp_conns` connections are served (further ones are closed at accept), and a complete frame must arrive within `tcp_idle_ms`, which also cuts off slowloris-style trickling. Each connection bounds its pipelined requests.
- **Malformed input:** a packet with a readable header gets a minimal FORMERR (id and question only, so no amplification); an unreadable header, a stray response or an oversized datagram is dropped. A malformed frame on TCP gets FORMERR and the connection is closed.
- **Shutdown:** listeners stop accepting, then wait up to 5 seconds for in-flight requests to be answered.
