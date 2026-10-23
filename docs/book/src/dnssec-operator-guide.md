# DNSSEC operator guide

This guide is the runbook for running DNSSEC with DNSY: turning on validation, signing a zone,
handing the DS to your registrar, and rolling keys safely. Reference material (record types,
the validator, the API) is on the [DNSSEC](dnssec.md) page. Every command below was run against
a local `dnsy` build; outputs are copied from those runs (key tags, digests and timestamps
differ on your system).

Commands that talk to the database (`dnsy dnssec ...`, `dnsy zone export --signed`) read the
same configuration file and the same passphrase as `dnsy serve`, so export
`DNSY_DNSSEC_PASSPHRASE` (or set `dnssec.key_passphrase_file`) in the shell you run them from.
API examples use `$A` for `Authorization: Bearer <token>`; a token for the calls below needs
the scopes `api:read`, `api:write` and `admin` (scopes are not hierarchical).

## Concepts in two paragraphs

DNSSEC lets a resolver prove that an answer came from the zone owner. A zone signs each record
set with a **zone signing key** (ZSK) and publishes the signatures (RRSIG) and public keys
(DNSKEY). A **key signing key** (KSK) signs the DNSKEY set, and a hash of it, the **DS**
record, is stored in the parent zone. That makes a chain from the root's **trust anchor**
down to your data. Missing names are proven absent with NSEC or NSEC3 records. A validator
ends in one of five states: `secure` (chain verified), `insecure` (provably no DNSSEC, for
example no DS at the parent), `bogus` (the chain exists but fails), `indeterminate` (no trust
anchor covers the name) or `unchecked` (not validated).

Clients steer it with three header bits: **DO** asks for DNSSEC records, **CD** (checking
disabled) asks the resolver not to validate, and **AD** in the reply says the data was
validated. DNSY sets AD only when the status is `secure` and the client set DO or AD.
Remember that a `bogus` answer is *worse* than an unsigned one, because the
resolver refuses it. Every DNSSEC change is therefore a timing problem: caches must never see
signatures, keys or DS records that do not match.

## Enabling validation

`dnssec.validation` in `dnsy.toml`:

| Mode | Behaviour |
| --- | --- |
| `strict` (default) | bogus answers become SERVFAIL with an extended DNS error |
| `permissive` | bogus answers are served without AD, with the EDE, and logged as a warning |
| `off` | no validation, the client's DO/CD bits go upstream unchanged |

```toml
[dnssec]
validation = "strict"
clock_skew_s = 300
```

Validation needs at least one trust anchor; `dnsy config check` refuses the file otherwise.
A running server's mode can be changed without a restart (not persisted; a restart returns to
the file):

```sh
curl -s -X PATCH -H "$A" -H 'Content-Type: application/json' \
  -d '{"validation":"permissive"}' http://127.0.0.1:5380/api/v1/settings/dnssec
```

### Trust anchor and its update

The defaults are the DS records of the two root KSKs (key tags 20326 and 38696):

```sh
curl -s -H "$A" http://127.0.0.1:5380/api/v1/settings/dnssec | jq -c '.trust_anchors[]'
```

```text
{"owner":".","key_tag":20326,"algorithm":8,"kind":"ds","digest_type":2,"digest":"E06D44B8...EC8D"}
{"owner":".","key_tag":38696,"algorithm":8,"kind":"ds","digest_type":2,"digest":"683D2D0A...2B16"}
```

Anchors are read-only through the API. RFC 5011 automatic updates are **not** implemented:
when the root KSK changes (the next one is announced by IANA months ahead), add the new DS
to `dnssec.trust_anchors`, or to `trust_anchor_file` (one DS per line in the form
`keytag algorithm digest-type digest-hex`; blank lines and lines starting with `#` or `;` are
skipped), then send `SIGHUP` (`kill -HUP $(pidof dnsy)`). The reload re-reads `[dnssec]` from
the file, swaps the anchors, keeps the current mode and negative trust anchors, and flushes the
cache. A malformed anchor keeps the previous set and logs a warning. Keep the old DS until
the old KSK is retired by IANA.

### Negative trust anchors

A negative trust anchor (NTA, RFC 7646) makes a name and everything below it validate as
`insecure`, as an emergency measure when a *remote* zone is broken and you cannot wait for its
owner. Set it at run time or in `dnssec.negative_trust_anchors`:

```sh
curl -s -X PATCH -H "$A" -H 'Content-Type: application/json' \
  -d '{"negative_trust_anchors":["dnssec-failed.org"]}' http://127.0.0.1:5380/api/v1/settings/dnssec
```

The list replaces the old one and the cache is flushed. An entry is a name, or an object with an
expiry (Unix time in the future); the anchor stops applying by itself at that moment:

```sh
curl -s -X PATCH -H "$A" -H 'Content-Type: application/json' \
  -d '{"negative_trust_anchors":[{"name":"dnssec-failed.org","expires_at":1893456000}]}' \
  http://127.0.0.1:5380/api/v1/settings/dnssec
```

`GET` returns `negative_trust_anchors` (names) and `negative_trust_anchor_entries` (name and
`expires_at`, `null` for none); expired anchors are left out. Answers accepted because of an
expiring anchor are cached for no longer than the time it has left, so nothing outlives it.
The web UI takes the expiry as hours from now. Give an NTA an expiry whenever you can: without
one it stays until you remove it. The root cannot be an NTA (422, "use mode off"). NTAs set
through the API are lost on restart; put long-lived ones in the file and remove them as soon
as the zone is fixed. While an NTA is active the reply still carries the EDE explaining why
the chain does not validate.

### Clock requirements

Signatures carry absolute validity times, so a wrong clock turns good data bogus. Keep NTP
running. `clock_skew_s` (default 300) is the tolerance applied to both ends of a signature's
validity. If the system clock is earlier than the binary's build time (a device that boots in
1970), DNSY does not validate at all: answers are served without AD and logged as
`indeterminate`, `/readyz` warns `dnssec_clock_untrusted`, and the web UI shows a banner.
`GET /api/v1/dnssec/status` reports `clock_trusted`. Validation resumes by itself once the
clock is plausible.

### Extended DNS errors

A SERVFAIL (strict) or AD-less answer (permissive) carries an EDE option (RFC 8914):

| EDE | Meaning | Usual cause |
| --- | --- | --- |
| 1 Unsupported DNSKEY algorithm | zone treated as insecure | zone signed only with an algorithm DNSY cannot verify |
| 2 Unsupported DS digest | zone treated as insecure | DS uses only unknown digest types |
| 5 DNSSEC indeterminate | no trust anchor, or an error code | misconfigured anchors |
| 6 DNSSEC bogus | signature does not verify, proof contradicts, or DS/DNSKEY fetch failed | tampering, broken signing, unreachable name servers |
| 7 Signature expired | only expired RRSIGs | zone owner stopped re-signing |
| 8 Signature not yet valid | only RRSIGs from the future | signer clock ahead, or yours behind |
| 9 DNSKEY missing | no DNSKEY matches the DS or RRSIG | DS at the parent does not match the zone's keys |
| 10 RRSIGs missing | unsigned data in a signed zone | zone unsigned but DS left at the parent |
| 12 NSEC missing | negative answer without proof | broken denial chain |

### Reading the query log

Each log row has a `dnssec` field: `secure`, `insecure`, `bogus`, `indeterminate` or
`unchecked`. The Query log page of the web UI has a DNSSEC filter and a lock or warning badge
per row; the API takes `dnssec=bogus`:

```sh
curl -s -H "$A" 'http://127.0.0.1:5380/api/v1/querylog?dnssec=bogus&limit=2' | jq -c '.entries[]'
```

```text
{"id":6,"qname":"sigfail.verteiltesysteme.net.","qtype":"A","rcode":"SERVFAIL","source":"upstream","source_detail":"1.1.1.1:53","dnssec":"bogus",...}
```

`GET /api/v1/dnssec/status` gives the counts for the last 24 hours:

```json
{"validation":"strict","clock_trusted":true,"window_ms":86400000,"counters":{"bogus":2,"secure":4,"unchecked":2},"secure":4,"bogus":2,"signed_zones":0}
```

The log record does not store the EDE; get it with `dig` (below).

### Troubleshooting a Bogus answer

Ask DNSY with DO and read the EDE:

```console
$ dig @127.0.0.1 -p 5353 dnssec-failed.org A +dnssec
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 35469
; EDNS: version: 0, flags: do; udp: 1232
; EDE: 9 (DNSKEY Missing): (no DNSKEY at dnssec-failed.org. matches the DS or trust anchor)
```

Then repeat with `+cd`, which skips validation, to see the data DNSY refuses:

```console
$ dig @127.0.0.1 -p 5353 dnssec-failed.org A +dnssec +cd
;; flags: qr rd ra cd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
dnssec-failed.org.	117	IN	A	96.99.227.255
dnssec-failed.org.	117	IN	RRSIG	A 13 2 300 ...
```

If `+cd` works and the plain query fails, the problem is in the zone's chain, not in the
network. If the same name also fails against a public validating resolver
(`dig @1.1.1.1 name`), it is broken at the source: wait, contact the owner, or add an NTA.
`delv` shows where the chain breaks:

```console
$ delv @127.0.0.1 -p 5353 cloudflare.com A
; fully validated
cloudflare.com.		51	IN	A	104.16.132.229
$ delv @127.0.0.1 -p 5353 dnssec-failed.org A +cd +vtrace
;; validating dnssec-failed.org/A: fetch_callback_dnskey: got failure
;; broken trust chain resolving 'dnssec-failed.org/A/IN': 127.0.0.1#5353
;; resolution failed: broken trust chain
```

`delv` uses BIND's built-in root anchor, so it checks DNSY's answers independently of DNSY's
own validator. Also check your own clock first (`timedatectl`) and the cache: a change of
mode or NTAs flushes it, `DELETE /api/v1/cache` does too.

## Signing a zone

### Policy options

Signing is configured per zone in the `dnssec` block of its JSON file (see
[Zones](zones.md#dnssec-policy)); the API writes the same block.

| Field | Default | Notes |
| --- | --- | --- |
| `enabled` | `false` | creates keys and signs on the next pass |
| `algorithm` | `13` | 13 ECDSAP256SHA256 or 15 Ed25519 only |
| `key_layout` | `csk` | `csk` (one key) or `ksk_zsk` (two keys) |
| `denial` | `nsec3` | `nsec` or `nsec3` |
| `nsec3` | iterations 0, empty salt, no opt-out | see below |
| `signature_validity_days` | 14 | |
| `refresh_days` | 5 | re-sign this long before expiry; must be below the validity |
| `dnskey_ttl` | 3600 | drives rollover timing |
| `propagation_delay` | 3600 | seconds added to `dnskey_ttl` before a published key may sign; 0 to 604800 |

Enable by editing the file (hot reload picks it up within a second or so, and the timer signs
within a minute), or through the API. Enabling is idempotent: sending `enabled: true` again, or
concurrently with a zone reload, never creates a second key set:

```sh
curl -s -X PUT -H "$A" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"key_layout":"ksk_zsk"}' \
  http://127.0.0.1:5380/api/v1/zones/example.com./dnssec
```

Check the result:

```console
$ dnsy dnssec keys list example.com
1    ksk  alg 13  tag 18887 active     ds-confirmed: false
2    zsk  alg 13  tag 44434 active     ds-confirmed: false
```

Algorithm 8 or 14 is refused (`422 algorithm 8 is unsupported (use 13 or 15)`; the CLI says
`algorithm 8 cannot sign (use 13 or 15)`). Disabling (`"enabled": false`) stops signing and
keeps the keys; enabling again reuses them. **Never disable signing while a DS is at the
parent**: the zone becomes bogus. Remove the DS and wait for its TTL first.

### Algorithm choice

Use 13 (the default): universally supported by registries and resolvers, small signatures.
Choose 15 (Ed25519) only if your parent zone and registrar accept it. RSA cannot be generated
(the crypto library lacks key generation), though DNSY validates RSA-signed zones. Changing
algorithm is a rollover with a new `--algorithm`, see below.

### NSEC or NSEC3, and opt-out

- `nsec3` (default) hashes names, so the zone cannot be walked by listing NSEC records. DNSY
  follows RFC 9276: 0 extra iterations and an empty salt. More iterations are refused (422)
  unless `allow_nonzero_iterations` is set, which only adds validator cost. Check:
  `dig @127.0.0.1 -p 5353 example.com NSEC3PARAM +noall +answer` returns
  `example.com. 300 IN NSEC3PARAM 1 0 0 -`.
- `nsec` is simpler to debug and cheaper, but lists every name. Use it for public data.
- `nsec3.opt_out: true` leaves insecure delegations out of the chain. It only helps zones with
  very many unsigned delegations (a TLD); for an ordinary zone leave it off.

### Key encryption passphrase

Private keys are sealed with AES-256-GCM under a key derived by argon2id from the passphrase.
Supply it as `DNSY_DNSSEC_PASSPHRASE` (an empty value counts as unset) or as the first line of
`dnssec.key_passphrase_file`. Keep the file at mode `0600`; with wider permissions DNSY logs
`passphrase file is accessible to other users; use mode 0600`.

Set it **before** the first key is created. Without a passphrase the keys are stored
unencrypted, `dnsy` warns `private keys are stored unencrypted` at every start and the API
shows `keys_encrypted: false`. Store the passphrase in your secret manager, apart from the
database backups. A lost or wrong passphrase makes the keys unusable:

```console
$ DNSY_DNSSEC_PASSPHRASE=wrong dnsy zone export example.com --signed
ERROR dnsy_zone::signed: zone signing failed zone=example.com. error=cannot decrypt key material (wrong passphrase or corrupted data)
dnsy: zone `example.com.` could not be signed (see the log)
```

#### Changing the passphrase

The change re-encrypts every stored key under the new passphrase in one database transaction:
all keys move or none does. It also encrypts keys that were stored unencrypted, so it is the
way to add a passphrase to an existing installation. While it runs no key is created or read.

```sh
# offline, with the current passphrase in the environment:
DNSY_DNSSEC_PASSPHRASE=old-phrase DNSY_DNSSEC_NEW_PASSPHRASE=new-phrase \
  dnsy dnssec passphrase change
# or against the running server (admin token); it switches to the new passphrase at once:
curl -s -X POST -H "$A" -H 'Content-Type: application/json' \
  -d '{"new_passphrase":"new-phrase"}' http://127.0.0.1:5380/api/v1/dnssec/passphrase
```

Passphrases need at least 12 characters. The CLI also reads the new passphrase from stdin
(`--new-passphrase-stdin`). **Afterwards update `DNSY_DNSSEC_PASSPHRASE` or the passphrase
file** before the next start. A server started with the old passphrase cannot read the keys:
it does not serve the zone unsigned (the DS would still be at the parent and validators would
fail it anyway). The zone answers SERVFAIL, the failure is logged once, and `/readyz` answers
503 with `dnssec_signing_failed` until the passphrase is right again.
After the offline command, restart a running server with the new passphrase. The passphrase
never appears in logs or responses.

### Where the keys live and backups

Keys are rows of the `dnssec_keys` table in `<server.data_dir>/dnsy.db` (default
`/var/lib/dnsy/dnsy.db`); the public part is also in the DNSKEY records. Two backups work:

- An **encrypted key bundle**: every non-removed key (or one zone's), sealed with AES-256-GCM
  under a bundle passphrase that may differ from the key passphrase:

  ```sh
  DNSY_DNSSEC_BACKUP_PASSPHRASE=bundle-phrase dnsy dnssec keys export keys.bundle
  DNSY_DNSSEC_BACKUP_PASSPHRASE=bundle-phrase dnsy dnssec keys import keys.bundle
  curl -s -X POST -H "$A" -H 'Content-Type: application/json' \
    -d '{"passphrase":"bundle-phrase","zone":"example.com."}' \
    http://127.0.0.1:5380/api/v1/dnssec/keys/export   # {"bundle":"<base64>"}
  ```

  The CLI creates the file with mode 0600 and refuses to overwrite one; `--zone` limits it and
  `--passphrase-stdin` reads the passphrase from stdin. Import re-seals the keys under the
  store's passphrase and skips keys that already exist. The API export needs the admin scope
  (the response is ciphertext only) and is **refused with 403 on a plain-HTTP API listener**:
  the request carries the bundle passphrase and the response every private key, so serve the
  API over TLS (`[api] tls`) or reach it through a TLS-terminating proxy. The bundle
  passphrase needs at least 12 characters and is stretched with argon2id at 64 MiB and three
  passes. Keep it apart from the bundle.
- The SQLite database, taken as described in [Operations](operations.md#backups), plus the
  passphrase kept separately.

Test a restore: start a copy with the passphrase and run
`dnsy dnssec keys ds <zone>`; the DS must equal the one at your registrar. The database file is
created with the process umask (0644 in the test above); restrict `data_dir` to the service
user. Removed keys have their private key wiped from the row.

## Giving the DS to the registrar

Print the DS records of the active and published KSKs (or CSK):

```console
$ dnsy dnssec keys ds example.com
example.com. IN DS 18887 13 2 44843D658634C024A33044B2DC4CC81AE9F4A9B52585C59C779D3A3520BC029A
example.com. IN DS 18887 13 4 3538DCDF647691CDFAA57BD3E934B3A456AD085CA7B3B3F40D7CBBC009253BE97E1D10734CD77979E4C131C2393254B1
```

Or through the API (`GET` with `Accept: text/plain` prints the same lines plus the DNSKEY
record; the default JSON has `ds` and `dnskey` arrays):

```console
$ curl -s -H "$A" -H 'Accept: text/plain' http://127.0.0.1:5380/api/v1/zones/example.com./dnssec/ds
example.com. IN DS 18887 13 2 44843D65...C029A
example.com. IN DS 18887 13 4 3538DCDF...54B1
example.com. IN DNSKEY 257 3 13 Y4GtDCPqSB/MTPrMTtnKV1N5...
```

The fields are key tag, algorithm (13), digest type, digest. Digest type **2** is SHA-256 and
**4** is SHA-384. Registrars normally take one DS: submit the SHA-256 one (type 2); some
accept several. Registrars that ask for the DNSKEY instead of the DS need the `257` (KSK/CSK)
record from the text output. The steps in the registrar's panel are theirs (usually
"DNSSEC" or "DS records" on the domain); the web UI's DNSSEC tab is introduced with DNSY-52 and
is not covered here, use the CLI or API.

Before submitting, make sure DNSY already serves the signed zone from every authoritative
server, and nothing else signs the same zone. After submitting, wait for the parent's DS TTL
(often 1 hour to 1 day) and verify:

```sh
dig +short DS example.com @a.gtld-servers.net     # replace with your TLD's server; DS must appear
dig +dnssec www.example.com A @<your resolver>     # flags must include ad
delv www.example.com A                              # "; fully validated"
```

Also try an independent validating resolver, such as `dig @1.1.1.1 www.example.com +dnssec`.
This chain could not be exercised against a real parent in the documentation tests.

## Safe key rollover runbook

### What DNSY does

Keys move through `generated -> published -> active -> retired -> removed`. A timer runs every
60 seconds, advances the states and the zone is re-signed on the pass after a change, so
changes show up within about a minute of their due time. Timings used (for `dnskey_ttl` T and
a signature validity V of 14 days):

- **Propagation** (P) is the zone policy's `propagation_delay`, default 3600 s, on top of T.
  Raise it when secondaries or resolvers are slow to see a new DNSKEY.
- A published key may become active after `T + P` s (3600 + 3600 with the defaults).
- A retired key is removed (and its private key wiped) `T + P + V` after retirement, so
  that the last signature it made has expired.
- A ZSK rolls by itself (pre-publish). A KSK or CSK also waits for you to confirm that its DS
  is at the parent (double-DS); DNSY never contacts the registrar.
- A retired KSK or CSK keeps signing the DNSKEY RRset until it is removed, so the RRset
  stays valid for resolvers that still hold the old DS (a parent's DS TTL is often 24 to 48
  hours). Confirming the DS never takes the old signature away.
- One rollover per role at a time. A second start answers
  `dnsy: a zsk rollover is already in progress for this zone` (API: 409). A role needs an
  active key to roll.
- A key made with `POST /zones/{name}/dnssec/keys` is only `generated`: it stays inert, and
  the same 409 stops a second one while it exists. Starting a rollover of that role publishes
  it (it keeps its algorithm) instead of making a new key; abort withdraws it.

### ZSK rollover (about 2 hours plus the retire wait, no registrar)

```console
$ dnsy dnssec keys rollover example.com --role zsk
rollover started: new key 3 (tag 31218, published)
$ dnsy dnssec keys list example.com
1    ksk  alg 13  tag 18887 active     ds-confirmed: false
2    zsk  alg 13  tag 44434 active     ds-confirmed: false
3    zsk  alg 13  tag 31218 published  ds-confirmed: false
```

With T = 3600: after about 2 hours the new ZSK is active and the old one retired; the zone is
re-signed with the new key. Fourteen days and two hours later the old key is removed.
`--algorithm 15` starts an algorithm change at the same time (the default is 13, so pass it
explicitly if the zone uses 15). Verified by moving the key timestamps in the database
forward: both transitions happened on the next timer pass and the signatures of `www` changed
from key tag 44434 to 31218 on the pass after.

### Algorithm rollover: double signing

When the new key has a different algorithm than the active key of its role (for example 13
to 15), every algorithm in the DNSKEY RRset must have a complete set of signatures (RFC 4035
2.2, RFC 6781 4.1.4). DNSY therefore double-signs the whole zone for the length of the
rollover, instead of letting the new key wait unused as in a same-algorithm pre-publish:

- From the moment the new key is `published`, it signs every RRset beside the old key, so
  validators holding either DNSKEY see a complete chain.
- A `retired` key of the old algorithm keeps signing zone data until it is `removed`, for
  the same reason it keeps signing the DNSKEY RRset.
- A published or retired key whose algorithm an active key of the same kind already covers
  (a same-algorithm rollover) does not sign zone data, so nothing changes there.
- Costs: while double-signing, the zone carries two RRSIGs per RRset, so responses with
  DNSSEC OK and zone transfers grow, and signing takes about twice the CPU.

For a KSK or CSK algorithm change the DS record for the new algorithm still waits for your
confirmation as above; the double signatures keep the zone valid for resolvers on either DS.

### KSK or CSK rollover (needs the registrar)

1. Start it: `dnsy dnssec keys rollover example.com --role ksk`
   (API: `POST /api/v1/zones/example.com./dnssec/keys/{id}/rollover` with the active key's id,
   answers 202 with the new key). For `key_layout: csk` use `--role csk`.
2. Print the DS: `dnsy dnssec keys ds example.com` now lists the old **and** the new DS:

   ```text
   example.com. IN DS 18887 13 2 4484...
   example.com. IN DS 24686 13 2 4AD6ECC42C422994954E9B2A248781E53AC16A978FA7D1C983CCE704524B0844
   ```

   Add the new DS at the registrar and **keep the old one**.
3. Wait for the parent to publish it, and then for the DS TTL of the *old* DS records to
   pass, so every cache holds both. Check with `dig +short DS example.com @<parent server>`.
4. Confirm to DNSY, with the CLI (it picks the one published KSK or CSK waiting for a DS;
   `--key <id>` names it when there are several), the API or the zone's DNSSEC tab:

   ```console
   $ dnsy dnssec ds-confirmed example.com
   DS of key 4 confirmed
   $ curl -s -X POST -H "$A" -w '%{http_code}\n' \
       http://127.0.0.1:5380/api/v1/zones/example.com./dnssec/keys/4/ds-confirmed
   204
   ```

5. DNSY activates the new key once `T + P` s have passed since publication, retires the old
   one and re-signs the DNSKEY set with the new KSK. Watch
   `GET /api/v1/zones/example.com./dnssec` (`rollover.state` is `in_progress` and key 4 shows
   `ds_confirmed_at`; it returns to `idle` when done) or `dnsy dnssec keys list`.
6. When the new KSK is active and `T` plus the propagation time have elapsed, remove the
   **old** DS at the registrar. DNSY does not track this step, and it removes the old
   DNSKEY after `T + P + V`; remove the old DS well before that, never after.

### Timeline example (T = 3600, parent DS TTL 24 h)

| When | Action |
| --- | --- |
| day 0 | start rollover, add the new DS at the registrar |
| day 0 + parent publication + 24 h | confirm the DS (earlier is allowed; this is on you) |
| confirm + about 2 h | new KSK active, old retired, DNSKEY re-signed |
| +2 h and the DS TTL 24 h | remove the old DS at the registrar |
| +14 d 2 h after retirement | old DNSKEY removed, private key wiped |

The rule behind it: never remove something that a cache may still need. A resolver may hold
the old DNSKEY set for T, the old DS for the parent's DS TTL, and signatures for V.

### Monitoring

- `dnsy dnssec keys list <zone>` and `GET .../dnssec` (`keys`, `next_resign`, `rollover`).
- `dig @127.0.0.1 -p 5353 example.com DNSKEY +short` during a rollover shows the extra keys.
- An external validator (`delv`, `dig @1.1.1.1 ... +dnssec`, `ad` flag) at each step.
- `GET /api/v1/dnssec/status` and the query log for a rise in `bogus`.
- The server logs `dnssec key states advanced transitions=N` for every change.

The `rollover` view lists every rollover under way in `rollover.rollovers` (role, state, new
key id), so a KSK and a ZSK rollover running together both show, in the API and in the UI.
(`rollover.state`, `role` and `new_key_id` summarise: `awaiting_ds_confirmation` wins, and the
last two name the first entry.) Doing ZSK and KSK rollovers one after the other is still the
easier path.

### Abort and rollback

A rollover that has not yet switched keys can be aborted: the incoming key is withdrawn (its
private key destroyed), the current key stays active, and the DNSKEY set is re-signed without
the new key. A new rollover can start right after.

```console
$ dnsy dnssec rollover abort example.com            # every rollover of the zone
$ dnsy dnssec rollover abort example.com --role ksk # only the KSK one
aborted ksk rollover: key 4 (tag 51234) withdrawn; its DS was confirmed, remove it at the registrar
$ curl -s -X POST -H "$A" -H 'Content-Type: application/json' -d '{"role":"ksk"}' \
    http://127.0.0.1:5380/api/v1/zones/example.com./dnssec/rollover/abort
```

The API answers with the zone's DNSSEC state; the zone's DNSSEC tab has an **Abort rollover**
button that asks for confirmation. It answers 409 when no rollover is in progress. Admin
scope is required.

- **Remove the new DS** from the registrar if you already added it; leaving a DS for a key the
  zone no longer serves makes validators fail once the old DS is gone. If you confirmed the
  DS, the CLI reminds you.
- **After activation** the old key is `retired` (the new one is already `active`) and the
  rollover cannot be aborted. Do not remove the old DS yet; fix the problem and roll again.
- If the new DS was wrong (typo), the old KSK is still active: replace the DS at the registrar
  with the correct value. Because the old DS stayed, nothing breaks meanwhile.

### Emergency procedures

- **Key compromised.** Start a rollover of that role now. For a KSK the compromised key still
  signs until you confirm the DS, so confirm as soon as the new DS is visible, then remove the
  old DS promptly. Note that waiting out `T + P + V` for removal cannot be shortened with
  a command.
- **Zone is bogus and you can't fix it quickly.** Remove the DS at the registrar. After the
  parent's DS TTL the zone becomes insecure (resolvers accept it unsigned). Then repair and
  re-add the DS. Disabling signing in DNSY without removing the DS makes things worse.
- **Remote zone bogus, your users affected.** Add an NTA for it (above) and remove it when
  fixed.

## Common failure modes

| Symptom | Cause | Fix |
| --- | --- | --- |
| everything bogus or `indeterminate` after boot | clock wrong | fix NTP; DNSY stops validating while the clock is before the build time, but a clock off by hours gives EDE 7/8 |
| EDE 7, signatures expired | signer stopped (service down, passphrase missing, zone not reloading) | check logs for `zone signing failed`; restore the passphrase; the next 60 s pass re-signs |
| EDE 9 right after enabling at the registrar | DS does not match the keys served (wrong key tag/digest, wrong zone, old key removed) | compare `dnsy dnssec keys ds` with the registrar; fix the DS |
| EDE 10 | DS at the parent for an unsigned zone | re-enable signing or remove the DS |
| forgot to update the DS during a KSK rollover | new key never confirmed, or the old DS removed before the new KSK became active | do not remove the old DS; confirm the new one |
| signing fails after a restart | passphrase env or file not set (`keys are encrypted but no passphrase is configured`) or changed (`cannot decrypt key material`) | restore the original passphrase |
| lost keys (database lost, no backup) | cannot re-create the same key | remove the DS at the registrar, wait for its TTL, enable signing again to get new keys, then publish the new DS |

## Security notes

- Private keys, the passphrase and tokens never appear in API responses, error bodies or logs.
  Do not put the passphrase in `dnsy.toml`; use the environment or a `0600` file.
- The database holds the keys: keep `data_dir` private to the service user and encrypt the
  backups; store the passphrase elsewhere.
- Use `strict` validation; `permissive` and NTAs are for incidents. A failed DS or DNSKEY fetch is
  treated as bogus, deliberately, so an attacker who blocks the fetch cannot downgrade you.
- Validation limits (32 fetches, 64 signature checks per query) protect against crafted zones.
- Admin scope is needed for every changing DNSSEC call; give it only to operators who handle
  keys, and use short-lived tokens.
