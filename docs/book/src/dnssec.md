# DNSSEC

DNSY implements DNSSEC itself. The `dnsy-dnssec` crate holds the cryptography and the
`dnsy-proto` crate holds the record types and the canonical form. The only third-party
crypto is [`ring`](https://github.com/briansmith/ring) for raw signature checks and digests
(plus `zeroize` to wipe key material); the DNSSEC logic is written in this repository.

This page covers the cryptographic building blocks, signing keys and zone signing.
Chain-of-trust validation is added by a later story and extends this page.

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

## Signing keys

The `KeyStore` in `dnsy-zone` keeps each signing zone's keys in the `dnssec_keys` table
(migration `0006`). A key has a role (`csk`, `ksk` or `zsk`), an algorithm (13 or 15), its key
tag, a state and a timestamp for every state it has reached. Generation uses `ring` through
`SigningKey::generate`; RSA keys cannot be generated.

When a zone's policy enables DNSSEC, `bootstrap` creates the first keys as `active`: one CSK,
or a KSK and a ZSK when `key_layout` is `ksk_zsk`.

### Encryption at rest

Private keys are PKCS#8 documents sealed with AES-256-GCM (`ring`). The key comes from the
passphrase through argon2id (19 MiB, 2 iterations, 1 lane by default) with a fresh random salt
and nonce for every key; the KDF cost, the salt and the format version are authenticated and
stored with the ciphertext. A wrong passphrase or damaged data yields one generic decryption
error that never includes key material.

The passphrase is read from `DNSY_DNSSEC_PASSPHRASE` (an empty value counts as unset), else
from the first line of `dnssec.key_passphrase_file`. Keep that file at mode `0600`; DNSY logs
a warning when other users can read it.

Without a passphrase keys are stored unencrypted, DNSY logs a warning at startup and the API
reports `keys_encrypted=false`. Protect the database file accordingly (mode `0600`, owned by
the service user). Key material is zeroized after use and `Debug` output of keys and
passphrases is redacted; keys and the passphrase are never logged.

### Key states and rollover

```text
generated -> published -> active -> retired -> removed
```

| State | Meaning |
| --- | --- |
| `generated` | created, not in the DNSKEY RRset |
| `published` | in the DNSKEY RRset, not signing |
| `active` | signing |
| `retired` | no longer signing, still published for validators holding old signatures |
| `removed` | withdrawn; the private key is wiped from the database |

Rollovers are planned by a pure function of the key set, the zone's timings and the current
time, and a timer task (`KeyStore::spawn_timer`) applies them. The clock is injectable, which
is how the tests advance days without sleeping.

* **ZSK, pre-publish (RFC 6781).** `start_rollover` creates and publishes the new ZSK. After
  the DNSKEY TTL plus the propagation delay it becomes `active` and the old ZSK is `retired`.
  The old key leaves the DNSKEY RRset once its last signature has expired: the maximum
  signature validity plus the DNSKEY TTL and propagation delay after retirement.
* **KSK and CSK, double-DS.** The new key is published and its DS goes to the parent. It stays
  `published` for as long as it takes: only when the operator confirms the DS at the parent
  (`confirm_ds`, exposed through the API) and the DNSKEY TTL has elapsed does it become
  `active` and the old key `retired`. DNSY never contacts the registrar.

Only one rollover per role runs at a time, and a role needs an active key to roll. Algorithm
rollovers are not coordinated beyond this: start one by passing the new algorithm.

### Backup and restore

`export_bundle` writes the zone's (or every zone's) non-removed keys as a single blob encrypted
with AES-256-GCM under a bundle passphrase of the operator's choosing, independent of the
store passphrase. `import_bundle` decrypts it, validates every key (PKCS#8, algorithm, key
tag), re-seals the keys under the current store passphrase and skips keys that are already
present. The file variants create the bundle with mode `0600` and refuse to overwrite.

## Zone signing

`ZoneSigner::sign(zone, keys, policy, now)` in `dnsy-dnssec` turns a zone's records into a
`SignedZone`: every RRset keyed by owner (in canonical order, RFC 4034 6.1) and type, each
with its RRSIGs. `dnsy-zone` supplies the inputs: `Zone::signing_data()` for the records,
`DnssecPolicy::signing_policy()` for the policy and `KeyStore::active_keys(zone)` for the
keys. `export_bind(&zone, Some(&signed))` writes the signed zone as a master file.

### What is signed

| RRset | Signed by |
| --- | --- |
| DNSKEY at the apex | every active or published KSK/CSK |
| CDS, CDNSKEY (during a KSK/CSK rollover) | the KSK/CSKs above and the zone-signing keys |
| every other authoritative RRset, NSEC, NSEC3, NSEC3PARAM | every active ZSK/CSK |
| DS at a delegation | the zone-signing keys |
| NS at a delegation, glue and anything else at or below a zone cut | not signed |

The DNSKEY RRset holds every published, active and retired key. A ZSK being pre-published
appears in it without signing anything, and a retired ZSK stays until its signatures are gone.
During a KSK or CSK rollover the new key is published and signs the DNSKEY RRset next to the
old one, so the RRset validates whichever DS the parent holds. While that rollover waits for
the DS, the apex also carries CDS (SHA-256) and CDNSKEY records for both keys (RFC 7344).

Each RRSIG has the RRset's TTL as original TTL, a `labels` count that leaves out a wildcard
label, inception one hour before signing time (for validators with slow clocks) and
expiration `signature_validity_days` after it. Expirations are jittered per RRset by up to
half of `min(refresh_days, signature_validity_days - refresh_days)`, so re-signing spreads
out instead of happening all at once. The jitter is derived from the owner, type and signing
time, so it is reproducible. Records of one RRset with different TTLs are given the lowest
one (RFC 2181 5.2).

The signer refuses zones without an apex SOA, records outside the origin, DNSSEC records in
the input (it generates them all), DS at the apex or outside a delegation, and policies whose
validity is not longer than `refresh_days`.

### Denial of existence

The NSEC and NSEC3 records and NSEC3PARAM have the TTL `min(SOA minimum, SOA TTL)` (RFC 9077).

* **NSEC** (`denial = "nsec"`): one NSEC per authoritative name and delegation point in
  canonical order, the last pointing back to the apex. Glue names and empty non-terminals get
  none. A delegation's bitmap lists only NS, DS (when present), RRSIG and NSEC.
* **NSEC3** (`denial = "nsec3"`, the default): SHA-1 hashes of the same names plus every empty
  non-terminal, sorted by hash and linked in a ring, with NSEC3PARAM at the apex. RFC 9276
  defaults apply: 0 extra iterations and an empty salt. A non-zero iteration count needs
  `nsec3.allow_nonzero_iterations` and produces a warning. An insecure delegation's bitmap is just NS, since nothing is signed there.
* **Opt-out** (`nsec3.opt_out = true`): delegations without DS are left out of the chain,
  along with empty non-terminals that exist only because of them, and every NSEC3 record
  carries the opt-out flag. NSEC3PARAM flags stay 0.

### Re-signing

`ZoneSigner::resign(zone, keys, policy, previous, now)` builds a new snapshot and keeps a
signature from `previous` when its RRset is unchanged (same TTL and RDATA in canonical form),
its key still has that signing duty, and it expires more than `refresh_days` from now.
Anything else is signed again. `SignedZone::next_resign` is the first time some signature
falls inside the refresh window, and `needs_refresh(now)` says whether that time has come.
Time is always passed in, so tests drive it with a `ManualClock`.

### Verification

The tests sign zones with algorithms 13 and 15, for NSEC, NSEC3 and NSEC3 with opt-out, and
check every RRSIG with `verify_rrsig` against the published DNSKEYs. They also check that the
chains cover names that do not exist, and they re-read the BIND export and verify it again.
When BIND's `dnssec-verify` or `ldns-verify-zone` is installed,
`dnssec_verify_accepts_signed_export` runs it on the exported zone. Without either tool the
test is skipped.
