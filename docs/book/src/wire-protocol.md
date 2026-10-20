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

## EDNS0

- The OPT pseudo-record is lifted out of the additional section into `Message::edns` (UDP payload
  size, DO bit, version, options). More than one OPT, or an OPT not owned by the root name, makes
  the packet malformed (FORMERR).
- `Message::header.rcode` is the full 12-bit rcode: the header's four bits merged with the OPT's
  upper eight on decode, split again on encode. A query with an EDNS version other than 0 is
  answered with `Message::badvers_for` (BADVERS, version 0 OPT, no data).
- Options: Padding, client subnet, cookie, Extended DNS Error and unknown options (kept raw).
- `Message::set_ede(code, text)` attaches an Extended DNS Error (RFC 8914), creating the OPT with
  a 1232-octet payload size if needed; the codes live in the `ede` module.
- For DoT and DoH, `Message::encode_padded` pads the response to a multiple of 468 octets
  (RFC 8467) when the query carried a Padding option (`Edns::has_padding`).

## DNSSEC records

`dnsy-proto` has typed codecs and presentation text for DNSKEY, CDNSKEY, RRSIG, DS, CDS, NSEC,
NSEC3 and NSEC3PARAM (RFC 4034, RFC 5155, RFC 8078).

- Presentation: keys and signatures are base64 (may be split over several tokens), digests and
  salts are hex (an empty salt is `-`), NSEC3 next-hashed-owner names are base32hex (written
  uppercase, accepted in either case), RRSIG times are `YYYYMMDDHHmmSS` (a plain count of seconds
  is accepted too), and algorithms are numbers.
- A decoded record always has a presentation form that parses back to the same value, so wire
  decoding rejects empty keys, signatures, digests and next-hashed names, and type bitmaps with an
  empty, oversized, repeated or out-of-order window or a trailing zero octet.
- `TypeBitmap` encodes and decodes the NSEC/NSEC3 window blocks. Types print by mnemonic, or as
  `TYPEnnn` when unnamed.
- `Dnskey::key_tag` follows RFC 4034 appendix B, including the algorithm 1 special case (a key too
  short for it gives tag 0). `serial_lt` and `serial_gt` implement RFC 1982 arithmetic for RRSIG
  validity checks; `Rrsig::is_current` uses them.
- `canonical::rrset_signing_input` builds the octets an RRSIG signs (RFC 4034 3.1.8.1): the RRSIG
  fields without the signature, then the RRs ordered by canonical RDATA with duplicates removed,
  the original TTL, lowercased owner names, and wildcard owners rewritten from the RRSIG `labels`
  field. Names in the RDATA of NS, CNAME, PTR, MX, SOA and SRV are lowercased and never compressed;
  NSEC and RRSIG names keep their case (RFC 6840 section 5.1).

## Fuzzing

A `cargo-fuzz` target lives in `crates/dnsy-proto/fuzz/` (not run by `just ci`):

```sh
cd crates/dnsy-proto
cargo +nightly fuzz run fuzz_decode
```
