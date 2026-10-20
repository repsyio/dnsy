# DNSSEC

DNSY implements DNSSEC itself. The `dnsy-dnssec` crate holds the cryptography and the
`dnsy-proto` crate holds the record types and the canonical form. The only third-party
crypto is [`ring`](https://github.com/briansmith/ring) for raw signature checks and digests
(plus `zeroize` to wipe key material); the DNSSEC logic is written in this repository.

This page covers the cryptographic building blocks. Chain-of-trust validation, zone
signing and key rollover are added by later stories and extend this page.

## Algorithms

| Number | Algorithm | Verify | Sign |
| --- | --- | --- | --- |
| 8 | RSASHA256 (RFC 5702) | yes | no |
| 10 | RSASHA512 (RFC 5702) | yes | no |
| 13 | ECDSAP256SHA256 (RFC 6605) | yes | yes |
| 14 | ECDSAP384SHA384 (RFC 6605) | yes | no |
| 15 | Ed25519 (RFC 8080) | yes | yes |

Every other algorithm (RSAMD5, DSA, the RSASHA1 family, GOST, Ed448) is reported as
`Unsupported`; a validator treats a zone signed only with such algorithms as insecure
(RFC 6840 5.2).

Signing is limited to algorithms 13 and 15 because `ring` cannot generate RSA keys.
Algorithm 13 is the recommended default; 15 is available for zones whose parent accepts it.

### RSA keys

DNSKEY RSA keys follow RFC 3110: an exponent length, the exponent, the modulus, with no
leading zero octets. Moduli of 1024 to 8192 bits are accepted (`ring`'s legacy RSA variants
cover 1024 to 2047 bits). Smaller keys, including the 512-bit key in the RFC 5702 SHA-256
example, are refused with `UnsupportedKeySize`. Larger ones are refused too.

## Verifying an RRSIG

`verify_rrsig(rrset, rrsig, key, now)` checks, in this order:

1. The RRset is non-empty and every record has the RRSIG's owner, class and covered type;
   the RRSIG `labels` field does not exceed the owner's label count; the owner is at or
   below the signer name.
2. The DNSKEY has the zone-key flag and protocol 3, the algorithm matches the RRSIG and the
   key tag matches.
3. The validity window, with RFC 1982 serial arithmetic. `verify_rrsig_with_skew` widens the
   window by a clock skew of up to 86400 seconds.
4. The signature over the RRSIG RDATA (without signature) followed by the RRset in canonical
   form (RFC 4034 3.1.8.1), built by `dnsy_proto::canonical::rrset_signing_input`.

ECDSA signatures are the fixed-width `r || s` form and DNSKEY points are the raw `x || y`
coordinates (RFC 6605); Ed25519 uses the raw 32-octet key (RFC 8080). Malformed keys are
rejected before any signature is tried.

## DS records

`ds_for(owner, key, digest_type)` hashes the lowercased owner name followed by the DNSKEY
RDATA. SHA-256 (2) and SHA-384 (4) are supported; SHA-1 (1) exists so that existing DS
records can be checked, and should not be used to publish new ones.

## NSEC3 hashing

`nsec3_hash(name, salt, iterations)` is the RFC 5155 hash (SHA-1, salted, iterated) of the
lowercased name. Resolvers must bound the iteration count of records they receive, since each
iteration costs one SHA-1 per name (RFC 9276). `checked_nsec3_hash` rejects iterations above a
caller-chosen maximum (`MAX_NSEC3_ITERATIONS` is 150) and salts longer than 255 octets.

## Signing keys

`SigningKey::generate(alg, ksk)` creates a key, `from_pkcs8` loads one, `to_pkcs8` exports
it and `dnskey()` derives the public record (flags 256, or 257 for a key-signing key). The
`Debug` output never contains key material and the PKCS#8 bytes are zeroized on drop.
`from_pkcs8` is strict: truncated documents, wrong key types and an Ed25519 key whose
embedded public key disagrees with its seed are rejected. `sign_rrset` returns the RRSIG
record, counting wildcard owners correctly in the `labels` field.

## Test vectors

The tests under `crates/dnsy-dnssec/tests/vectors/` are copied from RFC 4034 (DS), RFC 5155
(NSEC3 hashes), RFC 5702 (RSA), RFC 6605 (ECDSA) and RFC 8080 (Ed25519). Two RFC quirks are
documented in the vector files: RFC 8080 prints its RRSIGs without the algorithm and with a
labels value of 3 that exceeds the owner's label count, so DNSY checks those signatures
directly rather than through the strict `verify_rrsig`; and RFC 5702's SHA-256 key is below
the 1024-bit floor, so that algorithm is exercised with a 2048-bit key generated with
openssl.
