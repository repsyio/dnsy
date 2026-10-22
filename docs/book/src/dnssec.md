# DNSSEC

DNSY implements DNSSEC itself. The `dnsy-dnssec` crate holds the cryptography and the
`dnsy-proto` crate holds the record types and the canonical form. The only third-party
crypto is [`ring`](https://github.com/briansmith/ring) for raw signature checks and digests
(plus `zeroize` to wipe key material); the DNSSEC logic is written in this repository.

This page covers the cryptographic building blocks, signing keys, zone signing, the
chain-of-trust validator and the signed authoritative answers.

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
caller-chosen maximum (`MAX_NSEC3_ITERATIONS` is 100, the same cap the validator applies by default and zone signing enforces) and salts longer than 255 octets.

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
a warning when other users can read it (the check only warns; there is no setting that makes it fatal,
so enforce the mode with your deployment tooling).

Without a passphrase keys are stored unencrypted, DNSY logs a warning at startup and the API
reports `keys_encrypted=false`. Protect the database file accordingly (mode `0600`, owned by
the service user). Key material is zeroized after use (including the sealed key on its way into
the database, the passphrases of `POST /dnssec/keys/export` and `POST /dnssec/passphrase`, and
secrets the CLI reads from stdin) and `Debug` output of keys and passphrases is redacted; keys
and the passphrase are never logged.

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
  the DNSKEY TTL plus the propagation delay (the zone policy's `propagation_delay`, default
  3600 s) it becomes `active` and the old ZSK is `retired`.
  The old key leaves the DNSKEY RRset once its last signature has expired: the maximum
  signature validity plus the DNSKEY TTL and propagation delay after retirement.
* **KSK and CSK, double-DS.** The new key is published and its DS goes to the parent. It stays
  `published` for as long as it takes: only when the operator confirms the DS at the parent
  (`confirm_ds`, exposed through the API) and the DNSKEY TTL has elapsed does it become
  `active` and the old key `retired`. DNSY never contacts the registrar.

A `generated` key never moves by itself. `generate_key` refuses to make a second one while a
`generated` or `published` key of the role exists (`RolloverInProgress`), and `start_rollover`
publishes the waiting `generated` key rather than creating another.

Only one rollover per role runs at a time, and a role needs an active key to roll. Algorithm
rollovers are not coordinated beyond this: start one by passing the new algorithm.

### Backup and restore

`export_bundle` writes the zone's (or every zone's) non-removed keys as a single blob encrypted
with AES-256-GCM under a bundle passphrase of the operator's choosing, independent of the
store passphrase (at least 12 characters in the API and CLI; argon2id with 64 MiB and three
passes, where stored keys use the cheaper per-key cost). The API refuses the export route on a
plain-HTTP listener. `import_bundle` decrypts it, validates every key (PKCS#8, algorithm, key
tag), re-seals the keys under the current store passphrase and skips keys that are already
present. The file variants create the bundle with mode `0600` and refuse to overwrite.

## Zone signing

`ZoneSigner::sign(zone, keys, policy, now)` in `dnsy-dnssec` turns a zone's records into a
`SignedZone`: every RRset keyed by owner (in canonical order, RFC 4034 6.1) and type, each
with its RRSIGs. `dnsy-zone` supplies the inputs: `Zone::signing_data()` for the records,
`DnssecPolicy::signing_policy()` for the policy and `KeyStore::active_keys(zone)` for the
keys. `export_bind(&zone, Some(&signed))` writes the signed zone as a master file.

### Parallel signing and re-signing

RRsets (and the NSEC3 owner hashes) are independent, so `ZoneSigner` spreads them over
`std::thread::scope` workers, bounded by `available_parallelism` and started only for zones
with more than about 500 RRsets. Results are collected in canonical order, so the output equals
a single-threaded run for a fixed clock (Ed25519 signatures are deterministic, ECDSA ones are
valid but not byte-equal between runs). `ZoneSigner::resign` keeps the RRSIG of every RRset
whose data, key and validity window are unchanged; after one record changes, only that RRset
and, when a name is added or removed, its NSEC3 (or NSEC) record and the chain predecessor are
signed again.

### What is signed

| RRset | Signed by |
| --- | --- |
| DNSKEY at the apex | every active, published or retired KSK/CSK |
| CDS, CDNSKEY (during a KSK/CSK rollover) | the KSK/CSKs above and the zone-signing keys |
| every other authoritative RRset, NSEC, NSEC3, NSEC3PARAM | every active ZSK/CSK |
| DS at a delegation | the zone-signing keys |
| NS at a delegation, glue and anything else at or below a zone cut | not signed |

The DNSKEY RRset holds every published, active and retired key. A ZSK being pre-published
appears in it without signing anything, and a retired ZSK stays until its signatures are gone.
During a KSK or CSK rollover the new key is published and signs the DNSKEY RRset next to the
old one, and the retired key keeps signing until it is removed, so the RRset validates
whichever DS the parent holds, including an old DS still cached by resolvers after the
operator confirmed the new one. While that rollover waits for
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

## Chain-of-trust validation

`Validator::validate(fetcher, question, response, now)` checks one upstream response (fetched
with DO=1 and CD=1) and returns a `ValidationOutcome`: the RFC 4035 4.3 status, an optional
extended DNS error (RFC 8914) and, for secure answers, `min_ttl`, the lowest of the validated
records' TTLs, their RRSIG original TTLs and the seconds left until their RRSIGs expire. The
resolver caps cache lifetimes with it. The clock is a parameter, so callers (and tests)
control it.

| Status | Meaning |
| --- | --- |
| `Secure` | Every RRset on the answer chain, and the denial proof if any, verified up to a trust anchor. |
| `Insecure` | The data lies below a proven unsigned delegation, an NSEC3 opt-out span, a zone using only unsupported algorithms or digests, or a negative trust anchor. |
| `Bogus` | Something should have verified and did not. |
| `Indeterminate` | No trust anchor covers the name, the response code (SERVFAIL, REFUSED, ...) carries nothing to validate, or a DS or DNSKEY fetch failed. |

### Trust anchors

`TrustAnchors` holds DS anchors (`add_ds`), DNSKEY anchors (`add_dnskey`) and negative trust
anchors (`add_negative`, or `add_negative_until` with an expiry; RFC 7646). An expired anchor
stops applying (`is_negative` takes the validation time), and an answer accepted under an
expiring anchor carries a TTL cap of the time it has left, so caches drop it by then. The configuration's `dnssec.trust_anchors` are the root
KSK DS records (key tags 20326 and 38696) and `dnssec.negative_trust_anchors` are domain
names. A name at or below a negative trust anchor validates as `Insecure` without any fetch.
The validator always starts from the closest (deepest) anchor above a name.

### Building the chain

Missing DS and DNSKEY RRsets are fetched through the `DnssecFetcher` trait, so the resolver
can supply them over its upstreams and tests can use in-memory zones. For a signer zone (the
RRSIG signer name), the validator walks up with DS queries until it reaches a zone it has
already validated or the anchor, then validates back down:

1. At the anchor, the DNSKEY RRset must be signed by a key matching an anchor DS (or equal to
   an anchor DNSKEY).
2. At each level, the DS RRset is verified with the parent's keys, and the child's DNSKEY
   RRset must be signed by a key matching one of those DS records. SHA-1 DS records are
   ignored when a SHA-256 one exists (RFC 4509).
3. If there is no DS, the parent must prove it with a signed NSEC or NSEC3 record: a
   delegation without DS (or an opt-out span) makes the subtree `Insecure`; a name that is
   not a delegation stays in the parent zone. An unsigned DS answer proves nothing.
4. A DS set using only unsupported algorithms or digest types makes the zone `Insecure`.

The RRSIG signer must be the zone apex that the walk found, and must lie at or below the
anchor that covers the owner. Validated zones and fetched responses are memoised for the rest
of the validation.

Unsigned data is never accepted on its own word: it is `Insecure` only if the walk from the
anchor proves an insecure delegation above it, and `Bogus` (EDE 10) otherwise.

### Answers, CNAME and DNAME

The answer chain is followed from the question name: each CNAME and DNAME RRset is validated
on its own, so a chain that leaves a signed zone for an unsigned one is `Insecure` and a
broken link anywhere is `Bogus`. The CNAME synthesized from a DNAME is unsigned (RFC 6672)
and must equal the substitution. Any other RRset in the answer section is validated too, and
an unsigned one next to a secure chain makes the answer `Bogus` rather than downgrading it.

A positive answer whose RRSIG `labels` field is shorter than the owner name is a wildcard
expansion; the authority section must prove that the name itself does not exist (RFC 4035
5.3.4, RFC 5155 8.8), using only denial records signed by the zone that signed the wildcard.
When the NSEC3 covering the next closer name has the opt-out flag, the name may exist as an
unsigned delegation, so the expansion is `Insecure`, not `Secure`.

DNSKEYs with the REVOKE flag (0x0080, RFC 5011) are never trusted: they are dropped from the
validated key set and `verify_rrsig` rejects them with `VerifyError::Revoked`.

### Denial of existence

- **NSEC** (RFC 4035 5.4): NXDOMAIN needs an NSEC covering the name and one covering the
  wildcard at the closest encloser. NODATA needs the name's NSEC without the type or CNAME
  in its bitmap, an NSEC proving an empty non-terminal, or the wildcard's NSEC. NSEC records
  from the parent side of a delegation (NS without SOA) prove nothing about the child, and
  never deny names below themselves; the child's apex NSEC cannot prove a missing DS
  (RFC 6840 4.4).
- **NSEC3** (RFC 5155 8): closest-encloser proof (matching NSEC3 for the encloser, covering
  NSEC3 for the next closer name), wildcard cover for NXDOMAIN, matching NSEC3 for NODATA,
  wildcard NODATA, and opt-out: a DS NODATA or NXDOMAIN proven only through an opt-out span
  is `Insecure`. NSEC3 records with more than 100 iterations make the answer `Insecure`
  (RFC 9276 3.2) without being hashed.

A proof never mixes records of different zones. A negative answer is proven with the records
of the deepest zone that encloses the name; a hidden deeper zone cannot be skipped because the
parent's records show its delegation. If that proof fails, the name's own chain is walked: an
insecure delegation above it (for example after a CNAME from a signed zone into an unsigned
one) makes the answer `Insecure`, anything else leaves it `Bogus`.

### Extended DNS errors

| EDE | When |
| --- | --- |
| 1 Unsupported DNSKEY algorithm | Insecure: the zone uses only unsupported algorithms. |
| 2 Unsupported DS digest | Insecure: the DS set has only unsupported digest types. |
| 5 DNSSEC indeterminate | No trust anchor, or an error response code. |
| 6 DNSSEC bogus | Bad signature, contradicting denial, work limit exceeded, failed fetch. |
| 7 Signature expired | The only RRSIGs tried have expired. |
| 8 Signature not yet valid | The only RRSIGs tried are not yet valid. |
| 9 DNSKEY missing | No DNSKEY matches the DS, the anchor or the RRSIG key tag, or the DNSKEY fetch failed. |
| 10 RRSIGs missing | Data in a secure zone came without signatures. |
| 12 NSEC missing | A negative answer or wildcard expansion lacks its proof. |

### Work limits

NSEC3 records with an unknown hash algorithm, or with any flag bit other than Opt-Out set, are
ignored when building a denial proof (RFC 5155 8.1 and 8.2).

Each validation runs under `ValidationLimits` so that a hostile zone cannot exhaust CPU
(KeyTrap, CVE-2023-50387; NSEC3 floods, CVE-2023-50868). Exceeding any limit makes the answer
`Bogus` with EDE 6.

| Limit | Default |
| --- | --- |
| `max_zone_cuts`: names walked between the anchor and a signer | 16 |
| `max_rrsig_verifications`: signature checks per RRset | 8 |
| `max_verifications`: signature checks per validation | 64 |
| `max_fetches`: DS/DNSKEY fetches per validation | 32 |
| `max_nsec3_iterations`: above this, NSEC3 proofs are `Insecure` | 100 (`MAX_NSEC3_ITERATIONS`) |
| `max_nsec3_hashes`: distinct NSEC3 hashes per validation | 64 |
| `clock_skew`: seconds the RRSIG validity window is widened (`dnssec.clock_skew_s`) | 300 |

Only RRSIG/DNSKEY pairs whose key tag and algorithm match are tried, the validity window is
checked before any signature math, and DS digest computations count against
`max_verifications`. A failed DS or DNSKEY fetch is `Bogus`, not `Indeterminate`: an attacker
who can block those fetches must not get unvalidated answers served in strict mode.

### Tests

`crates/dnsy-dnssec/tests/validate.rs` builds zones signed with `SigningKey` (root, TLD and
child zones, NSEC and NSEC3 chains, opt-out, wildcards) and serves them from an in-memory
`DnssecFetcher`, covering secure chains, insecure delegations, every bogus case above, the
negative trust anchor short-circuit and the work limits.

## Authoritative DNSSEC responses

Zones whose `dnssec` block has `enabled = true` are served signed. `ZoneSigning` (in
`dnsy-zone`) holds the zone store and the key store; `Services::open` creates it, signs every
such zone before it returns and exposes it as `Services::signing`; `Services::spawn_background`
starts its refresh task (`ZoneSigning::spawn(interval)`). A zone without keys gets its
first key set (`KeyStore::bootstrap`) on the first signing pass.

### Signed snapshots

A signing pass signs a zone when it was never signed, when its file changed, when its keys
changed state (a rollover step) or when some signature is within `refresh_days` of expiry
(`SignedZone::needs_refresh`). Re-signing goes through `ZoneSigner::resign`, so unchanged
`RRsets` keep their signatures. The signing itself runs on a blocking thread; the finished
snapshot is installed with the same atomic swap the zone store uses for reloads, so queries
never wait for it and always see one complete version.

A reload that changes a signed zone does not expose unsigned data: the previous version keeps
serving, signed, until the refresh task (woken by the reload) has signed the new one, then
both are swapped in together. A zone that has never been signed (the window between startup
and the first pass, or a zone whose keys cannot be decrypted) is served unsigned and the error
is logged. Disabling `dnssec` drops the signed snapshot on the next reload.

### What a DO query gets

Without the EDNS DO bit nothing changes: no RRSIG, NSEC or NSEC3 is added and an `ANY` query
leaves the NSEC record out. DNSKEY, NSEC3PARAM, CDS and CDNSKEY are ordinary data at the apex
and are answered when asked for, with or without DO.

With DO (RFC 4035 3.1, RFC 5155 7.2):

| Answer | Added records |
| --- | --- |
| Data, CNAME chains, additional A/AAAA | the RRSIGs of every `RRset` (wildcard expansions carry the RRSIG under the query name, its `labels` field showing the expansion) |
| Wildcard expansion | NSEC covering the query name, or NSEC3 covering the next closer name |
| NXDOMAIN | SOA and RRSIG; NSEC covering the name and NSEC covering the wildcard at the closest encloser, or the NSEC3 closest-encloser proof (matching closest encloser, covering next closer name, covering wildcard) |
| NODATA | SOA and RRSIG; the NSEC or NSEC3 matching the name (for an NSEC empty non-terminal, the NSEC whose span holds it) |
| Wildcard NODATA | the NXDOMAIN-style proof for the name plus the NSEC/NSEC3 matching the wildcard |
| Referral to a signed child | NS, DS and its RRSIG, glue |
| Referral to an unsigned child | NS, the NSEC/NSEC3 matching the cut (bitmap without DS) and its RRSIG; under NSEC3 opt-out, the closest provable encloser proof with the opt-out NSEC3 covering the cut |

Delegation NS records and glue are never signed. DS queries are answered by the parent side of
the cut (RFC 4035 3.1.4.1), with a NODATA proof when the delegation has no DS. NSEC3 owner names
do not exist as names: a query for one gets NXDOMAIN (RFC 5155 7.2.8).

Authoritative answers set AA and never AD (AD speaks for validated data, RFC 4035 3.1.6);
referrals set neither. When a signed answer does not fit the client's UDP payload size, the
response is truncated by whole `RRsets` with TC set so the client retries over TCP; signatures
are never dropped to make an answer fit.

### Verification

The tests in `crates/dnsy-zone/src/signed_tests.rs` sign zones with NSEC, NSEC3 and NSEC3
opt-out, then check every RRSIG of the responses with `verify_rrsig` against the zone's DNSKEYs
and check that every proof record matches or covers the names it must (hash order for NSEC3,
canonical order for NSEC). `signed_responses_validate_secure` feeds the responses to the
chain-of-trust validator, anchored at the zone's DS: answers, CNAME chains, NODATA, wildcard
answers and wildcard NODATA, NXDOMAIN and DS validate `Secure` under NSEC, NSEC3 and NSEC3
opt-out (except an NXDOMAIN inside an opt-out span, which is `Insecure` by RFC 5155 9.2), and
data below the unsigned delegation validates `Insecure`. The engine test
`from_config_serves_signed_zone_with_aa_never_ad` runs a DO query through the full pipeline.

## Validation in the forwarding path

Forwarded answers are validated according to `dnssec.validation`:

| Mode | Upstream query | Bogus answer | Status |
| --- | --- | --- | --- |
| `off` | the client's DO and CD bits | served as received | `unchecked` |
| `permissive` | DO=1, CD=1 | served without AD, with the validator's EDE, logged as a warning | validated |
| `strict` (default) | DO=1, CD=1 | SERVFAIL with the validator's EDE | validated |

Validating modes always ask upstream with DO=1 and CD=1, so the upstream returns signatures
and denial records but does not validate (and SERVFAIL) for us. The raw answer is validated,
then scrubbed for the client: RRSIG, NSEC and NSEC3 records are returned only to clients that
set DO. `Secure` and `Insecure` answers are served; `Indeterminate` answers (no trust anchor
covers the name) are served without AD.

### AD and CD

- AD is set only when the status is `Secure` and the client set DO or AD (RFC 6840 5.7). It
  is cleared in every other case, including answers served from the cache.
- A client that sets CD=1 gets no validation: its query goes upstream with CD=1, the answer is
  returned as received (status `unchecked`), and it is cached under the CD=1 key. Those
  entries are never served to CD=0 clients, and a CD=0 client's Bogus entry is never served to
  anyone as validated data.

### Extended DNS errors on Bogus answers

The EDE is the validator's reason (see the table above): 6 DNSSEC bogus (bad signature, work
limit exceeded), 7 signature expired, 8 signature not yet valid,
9 DNSKEY missing, 10 RRSIGs missing, 12 NSEC missing. It is stored with the cache entry, so
cached replies carry the same code.

A DS or DNSKEY fetch that fails or times out is a transport problem, not evidence of an
attack: the status is `Indeterminate` with EDE 5, never `Bogus`, so it is not cached for
`bogus_ttl`. In `strict` mode the client gets SERVFAIL with EDE 5, cached for `servfail_ttl`,
so unvalidated data is never handed on and a blip is retried within seconds. In `permissive`
mode the answer is served without AD, with its TTLs lowered to `indeterminate_ttl` (5 s).

### Cache

- The status is stored with each cache entry. A `Bogus` entry lives at most `cache.bogus_ttl`
  seconds, is returned to CD=0 clients only as SERVFAIL (strict) or without AD (permissive),
  and never replaces a live `Secure` entry.
- The lifetime of validated data is capped by its signatures: record TTLs are lowered to the
  validator's `min_ttl` (the lowest record TTL, RRSIG original TTL and seconds until the
  RRSIGs expire), so a cached `Secure` answer never outlives its RRSIGs.
- DS and DNSKEY answers fetched for validation are memoised in the same cache under the
  DO=1/CD=1 key with status `unchecked`; the validator checks them on every use. That entry
  is also what a CD=1 client asking for the same name receives, so the fetcher first strips
  everything but the asked RRset, its RRSIGs and the denial records of a negative answer.
- Changing the validation mode (`Engine::set_dnssec_mode`) or the negative trust anchors
  (`Engine::set_negative_trust_anchors`, from `dnssec.negative_trust_anchors` at start or the
  API at run time) flushes the cache.

### Amplification bounds

One client query cannot make the validator fetch without limit:

- `ValidationLimits` caps a validation at 32 DS/DNSKEY fetches and 64 signature checks
  (see Work limits above);
- at most 64 validation fetches are in flight across all clients; a fetch waits for a slot only
  until its deadline;
- every fetch of one validation shares a deadline of `resolver.timeout_ms * resolver.attempts`,
  so a slow upstream turns the answer Bogus instead of hanging the client;
- fetched DS/DNSKEY sets are cached, so popular zones cost one fetch per TTL.

### Clock safety

A device without a real-time clock (a Raspberry Pi, for one) may boot in 1970, when every
RRSIG looks "not yet valid". Validating then would SERVFAIL every name, including the NTP
server that would fix the clock. So while the system clock is earlier than the build time
(passed by the binary through `EngineBuilder::build_time`; 2026-10-01 by default), DNSY:

- does not validate: answers are served without AD and logged as `indeterminate`;
- logs a warning once, and `/readyz` returns `"warnings": ["dnssec_clock_untrusted"]`;
- resumes validation as soon as the clock is plausible, flushing the cache of the
  `indeterminate` entries.

### Query log and statistics

Every query event carries its validation status (`secure`, `insecure`, `bogus`,
`indeterminate`, `unchecked`), whether the answer came from the upstream or the cache. The
query log stores it and the statistics count it per status (`by_dnssec`, with `secure` and
`bogus` totals).

## Managing DNSSEC through the API

The REST API (see [REST API](rest-api.md#dnssec)) drives everything above without editing files.
All changing calls need the `admin` scope.

**Enable signing.** `PUT /api/v1/zones/example.com./dnssec` with `{"enabled": true}` writes the
`dnssec` block of the zone file (defaults: algorithm 13, one CSK, NSEC3 with zero iterations, 14 day
signatures refreshed 5 days before expiry), creates the keys and signs the zone, so the next
DO query already gets signed answers. Only algorithms 13 and 15 are accepted. Other policy fields
(`key_layout`, `denial`, `nsec3`, `signature_validity_days`, `refresh_days`, `dnskey_ttl`, `propagation_delay`) can be
sent in the same or a later call; a field left out keeps its value. The algorithm of existing keys
changes only through a rollover with a new `algorithm`.

**Publish the DS.** `GET .../dnssec/ds` returns the DS records (SHA-256 and SHA-384) of the
published and active KSKs or CSKs, plus the DNSKEY records for registrars that take keys. Send
`Accept: text/plain` for lines to paste into a registrar form. The digests are computed from the
same DNSKEY the zone serves.

**Roll a key.** `POST .../dnssec/keys/{id}/rollover` takes the id of an active key, generates its
successor and publishes it (202). A ZSK rollover finishes by itself once the DNSKEY TTL and
propagation time have passed. A KSK or CSK rollover waits: publish the new key's DS at the parent
(`GET .../dnssec/ds` lists it already), then call `POST .../dnssec/keys/{new id}/ds-confirmed`.
`GET .../dnssec` reports the state as `idle`, `in_progress` or `awaiting_ds_confirmation`, with
every rollover under way in `rollover.rollovers`. One rollover per role runs at a time; a second
request is 409. `POST .../dnssec/rollover/abort` (optionally `{role}`) withdraws the incoming key
and keeps the active one (`KeyStore::abort_rollover`); 409 once the new key has become active.
`dnsy dnssec rollover abort` and `dnsy dnssec ds-confirmed` do the same from the CLI.

**Key backup and passphrase.** `POST /api/v1/dnssec/keys/export` returns the keys as a bundle
encrypted under a given passphrase, and `POST /api/v1/dnssec/passphrase` re-encrypts all keys
under a new key passphrase atomically (`KeyStore::change_passphrase`, which blocks key creation
and decryption while it runs). The CLI has `dnsy dnssec keys export|import` and
`dnsy dnssec passphrase change`. See the [operator guide](dnssec-operator-guide.md).

**Signed export.** `GET .../export?signed=true` downloads the zone as a BIND file with the DNSKEY,
RRSIG, NSEC or NSEC3 and NSEC3PARAM records of the current signed snapshot.

**Validation at run time.** `GET/PATCH /api/v1/settings/dnssec` shows and changes the validation
mode and the negative trust anchors (RFC 7646) without a restart. Names are lowercased and
de-duplicated; an entry may carry an `expires_at` after which the anchor stops applying; the root
is refused because it would disable validation (use mode `off`). Any change
flushes the cache, since cached entries carry statuses computed under the old settings. Trust
anchors are read-only: they come from the configuration, and the API lists them with their key
tags. Changes are not saved to the configuration file. `GET /api/v1/dnssec/status` adds the
answer counts by DNSSEC status for the last 24 hours and whether the clock is trusted.

**Secrets.** Private keys stay in the key store. No API response, error body or log line contains
them, and the OpenAPI schemas have no field for them. `keys_encrypted` in the zone's DNSSEC view
tells whether new keys are encrypted at rest; when it is false, set a key passphrase.

## Managing DNSSEC in the web UI

The web UI drives the same API (see [Web UI](web-ui.md#dnssec)). The zone's **DNSSEC** tab enables
or disables signing, shows keys with their timers and starts rollovers, and lists the DS records
to paste at the registrar (SHA-256 first). Enabling and rollovers ask for confirmation and explain
the registrar steps, because a missing or stale DS makes validating resolvers fail the zone. The
**DNSSEC** page under the main navigation sets the validation mode (`strict`, `permissive`, `off`;
weaker modes ask for confirmation), manages negative trust anchors and lists the configured trust
anchors read-only.
