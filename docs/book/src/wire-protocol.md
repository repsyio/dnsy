# Wire protocol

DNSY parses and builds DNS messages with its own codec in `dnsy-proto` (standard library only).
This page describes how it treats packets on the wire.

## Decoding

- Every section count in the header is checked against the data: a count larger than the packet,
  RDATA whose fields do not fill exactly RDLENGTH octets, or bytes left after the last section are
  all malformed.
- Compression pointers must point strictly backwards and are followed at most 128 times; labels
  are at most 63 octets and names at most 255.
- Memory use follows what actually parsed, never the counts claimed in the header.
- A malformed query whose 12-byte header is readable gets a FORMERR reply that echoes its id and,
  when it parses, its first question. Packets shorter than a header, and malformed packets that are
  themselves responses, are dropped silently.

## Encoding

- Owner names in every section are compressed. Inside RDATA only the names of NS, CNAME, PTR, MX
  and SOA are compressed (RFC 3597 section 4); SRV, RRSIG and NSEC names are always written in full.
- The OPT pseudo-record is always written last in the additional section.
- When a response is larger than the limit (512 octets without EDNS, otherwise the client's
  advertised size), whole RRsets are dropped from the end: additional first, then authority, then
  answers. The OPT record is never dropped. TC is set when an answer or authority RRset had to go;
  losing only additional data does not set TC (RFC 2181 section 9).

## Fuzzing

A `cargo-fuzz` target lives in `crates/dnsy-proto/fuzz/` (not run by `just ci`):

```sh
cd crates/dnsy-proto
cargo +nightly fuzz run fuzz_decode
```
