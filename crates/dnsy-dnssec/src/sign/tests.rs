use super::*;
use crate::{Algorithm, Clock, ManualClock, nsec3_hash, verify_rrsig};
use dnsy_proto::{Ds, Nsec3, Rrsig, Soa, base32hex_encode};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

const NOW: u32 = 1_800_000_000;

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn rec(owner: &str, ttl: u32, data: RData) -> Record {
    Record {
        name: n(owner),
        rtype: data.rtype(),
        class: Class::In,
        ttl,
        data,
    }
}

fn a(owner: &str, ip: [u8; 4]) -> Record {
    rec(owner, 300, RData::A(Ipv4Addr::from(ip)))
}

fn ns(owner: &str, target: &str) -> Record {
    rec(owner, 3600, RData::Ns(n(target)))
}

fn soa() -> Record {
    rec(
        "example.",
        7200,
        RData::Soa(Soa {
            mname: n("ns1.example."),
            rname: n("hostmaster.example."),
            serial: 1,
            refresh: 3600,
            retry: 600,
            expire: 86_400,
            minimum: 900,
        }),
    )
}

fn ds(owner: &str) -> Record {
    rec(
        owner,
        3600,
        RData::Ds(Ds {
            key_tag: 1234,
            algorithm: 13,
            digest_type: 2,
            digest: vec![0xab; 32],
        }),
    )
}

/// Apex data, an empty non-terminal pair (`c`, `b.c`), a wildcard, a secure delegation
/// with glue, an insecure delegation with glue, and an insecure delegation whose only
/// ancestor below the apex is an empty non-terminal (`ent2`).
fn zone() -> ZoneData {
    ZoneData {
        origin: n("example."),
        records: vec![
            soa(),
            ns("example.", "ns1.example."),
            a("ns1.example.", [192, 0, 2, 1]),
            a("WWW.example.", [192, 0, 2, 2]),
            rec(
                "example.",
                300,
                RData::Mx {
                    preference: 10,
                    exchange: n("mail.example."),
                },
            ),
            a("a.b.c.example.", [192, 0, 2, 3]),
            rec("*.wild.example.", 300, RData::Txt(vec![b"hi".to_vec()])),
            ns("secure.example.", "ns.secure.example."),
            ds("secure.example."),
            a("ns.secure.example.", [192, 0, 2, 4]),
            ns("insecure.example.", "ns.insecure.example."),
            a("ns.insecure.example.", [192, 0, 2, 5]),
            a("insecure.example.", [192, 0, 2, 9]),
            ns("x.ent2.example.", "ns.other."),
        ],
    }
}

fn csk(alg: Algorithm) -> ActiveKeys {
    ActiveKeys {
        keys: vec![ZoneKey::new(
            KeyRole::Csk,
            KeyState::Active,
            SigningKey::generate(alg, true).unwrap(),
        )],
    }
}

fn key(role: KeyRole, state: KeyState) -> ZoneKey {
    let k = SigningKey::generate(Algorithm::EcdsaP256Sha256, role.is_sep()).unwrap();
    ZoneKey::new(role, state, k)
}

fn policy(denial: Denial) -> SigningPolicy {
    SigningPolicy {
        denial,
        signature_validity_days: 14,
        refresh_days: 5,
        dnskey_ttl: 3600,
    }
}

fn nsec3(opt_out: bool) -> Denial {
    Denial::Nsec3 {
        iterations: 0,
        salt: Vec::new(),
        opt_out,
    }
}

fn rrsig(r: &Record) -> &Rrsig {
    match &r.data {
        RData::Rrsig(s) => s,
        other => panic!("not an RRSIG: {other:?}"),
    }
}

fn dnskeys(z: &SignedZone) -> Vec<Dnskey> {
    z.rrset(&z.origin, RecordType::Dnskey)
        .unwrap()
        .records
        .iter()
        .map(|r| match &r.data {
            RData::Dnskey(k) => k.clone(),
            _ => unreachable!(),
        })
        .collect()
}

/// Checks every RRSIG against the published DNSKEYs, that the DNSKEY `RRset` is signed by a
/// SEP key, and that every authoritative `RRset` carries a signature.
fn verify_zone(z: &SignedZone, now: u32) {
    let keys = dnskeys(z);
    for ((name, code), set) in &z.rrsets {
        for sig in &set.rrsigs {
            let s = rrsig(sig);
            let k = keys
                .iter()
                .find(|k| k.key_tag() == s.key_tag && k.algorithm == s.algorithm)
                .expect("signing key published");
            assert_eq!(
                verify_rrsig(&set.records, s, k, now),
                Ok(()),
                "{name} type {code}"
            );
            assert_eq!(s.type_covered, RecordType::from(*code));
            assert_eq!(sig.ttl, set.records[0].ttl);
        }
    }
    let dnskey_sigs = &z.rrset(&z.origin, RecordType::Dnskey).unwrap().rrsigs;
    assert!(dnskey_sigs.iter().any(|s| {
        keys.iter()
            .any(|k| k.key_tag() == rrsig(s).key_tag && k.flags & 1 == 1)
    }));
}

fn owners_of(z: &SignedZone, t: RecordType) -> Vec<Name> {
    z.rrsets
        .iter()
        .filter(|((_, c), _)| *c == u16::from(t))
        .map(|((name, _), _)| name.clone())
        .collect()
}

fn covers_nsec(z: &SignedZone, qname: &Name) -> bool {
    z.records().any(|r| match &r.data {
        RData::Nsec { next, .. } => r.name < *qname && (qname < next || next == &z.origin),
        _ => false,
    })
}

fn nsec3_records(z: &SignedZone) -> Vec<(&Record, &Nsec3)> {
    z.records()
        .filter_map(|r| match &r.data {
            RData::Nsec3(x) => Some((r, x)),
            _ => None,
        })
        .collect()
}

fn hash_label(name: &str) -> String {
    base32hex_encode(&nsec3_hash(&n(name), &[], 0)).to_ascii_lowercase()
}

fn covers_nsec3(z: &SignedZone, qname: &str) -> bool {
    let h = nsec3_hash(&n(qname), &[], 0).to_vec();
    nsec3_records(z).iter().any(|(r, x)| {
        let own = dnsy_proto::base32hex_decode(
            std::str::from_utf8(r.name.labels().next().unwrap()).unwrap(),
        )
        .unwrap();
        if own < x.next_hashed {
            own < h && h < x.next_hashed
        } else {
            h > own || h < x.next_hashed
        }
    })
}

#[test]
fn signed_zone_verifies_with_own_validator() {
    for alg in [Algorithm::EcdsaP256Sha256, Algorithm::Ed25519] {
        for denial in [Denial::Nsec, nsec3(false), nsec3(true)] {
            let nsec = denial == Denial::Nsec;
            let z = ZoneSigner::sign(&zone(), &csk(alg), &policy(denial), NOW).unwrap();
            verify_zone(&z, NOW);
            // Still valid an hour before signing (inception offset) and just before expiry.
            verify_zone(&z, NOW - 3600);
            verify_zone(&z, NOW + 9 * DAY);
            if nsec {
                assert!(covers_nsec(&z, &n("nope.example.")));
                assert!(covers_nsec(&z, &n("zzz.example.")));
            } else {
                assert!(covers_nsec3(&z, "nope.example."));
                assert!(covers_nsec3(&z, "zzz.example."));
            }
            for name in [
                "example.",
                "www.example.",
                "a.b.c.example.",
                "*.wild.example.",
            ] {
                for ((owner, code), set) in &z.rrsets {
                    if owner == &n(name) {
                        assert!(!set.rrsigs.is_empty(), "{owner} {code} unsigned");
                    }
                }
            }
        }
    }
}

#[test]
fn rrsig_fields_follow_rfc4034() {
    let z = ZoneSigner::sign(
        &zone(),
        &csk(Algorithm::Ed25519),
        &policy(Denial::Nsec),
        NOW,
    )
    .unwrap();
    let wild = z.rrset(&n("*.wild.example."), RecordType::Txt).unwrap();
    let s = rrsig(&wild.rrsigs[0]);
    assert_eq!(s.labels, 2, "wildcard label not counted");
    assert_eq!(s.original_ttl, 300);
    assert_eq!(s.signer, n("example."));
    assert_eq!(s.inception, NOW - 3600);
    let validity = 14 * DAY;
    let window = (5 * DAY).min(validity - 5 * DAY) / 2;
    let mut expirations = BTreeSet::new();
    for set in z.rrsets.values() {
        for sig in &set.rrsigs {
            let e = rrsig(sig).expiration;
            assert!(e <= NOW + validity && e > NOW + validity - window, "{e}");
            expirations.insert(e);
        }
    }
    assert!(expirations.len() > 3, "expirations are not jittered");
    let www = z.rrset(&n("www.example."), RecordType::A).unwrap();
    assert_eq!(rrsig(&www.rrsigs[0]).labels, 2);
    assert!(z.next_resign > NOW + validity - window - 5 * DAY);
    assert!(!z.needs_refresh(NOW));
    assert!(z.needs_refresh(z.next_resign));
}

#[test]
fn nsec_chain_complete_and_ordered() {
    use RecordType as T;
    let z = ZoneSigner::sign(
        &zone(),
        &csk(Algorithm::Ed25519),
        &policy(Denial::Nsec),
        NOW,
    )
    .unwrap();
    let owners = owners_of(&z, RecordType::Nsec);
    let expected: Vec<Name> = [
        "example.",
        "a.b.c.example.",
        "x.ent2.example.",
        "insecure.example.",
        "ns1.example.",
        "secure.example.",
        "*.wild.example.",
        "www.example.",
    ]
    .iter()
    .map(|s| n(s))
    .collect();
    assert_eq!(owners, expected);
    for (i, owner) in owners.iter().enumerate() {
        let set = z.rrset(owner, RecordType::Nsec).unwrap();
        assert_eq!(set.records.len(), 1);
        assert_eq!(set.records[0].ttl, 900, "min(SOA minimum, SOA TTL)");
        let RData::Nsec { next, types } = &set.records[0].data else {
            unreachable!()
        };
        assert_eq!(next, &owners[(i + 1) % owners.len()]);
        assert!(types.contains(RecordType::Nsec) && types.contains(RecordType::Rrsig));
        assert_eq!(set.rrsigs.len(), 1);
    }
    let bitmap = |name: &str| match &z.rrset(&n(name), RecordType::Nsec).unwrap().records[0].data {
        RData::Nsec { types, .. } => types.types().collect::<Vec<_>>(),
        _ => unreachable!(),
    };
    assert_eq!(
        bitmap("example."),
        [T::Ns, T::Soa, T::Mx, T::Rrsig, T::Nsec, T::Dnskey]
    );
    assert_eq!(bitmap("secure.example."), [T::Ns, T::Ds, T::Rrsig, T::Nsec]);
    assert_eq!(
        bitmap("insecure.example."),
        [T::Ns, T::Rrsig, T::Nsec],
        "occluded A at the cut is not listed"
    );
    assert!(z.rrset(&n("example."), RecordType::Nsec3param).is_none());
}

#[test]
fn nsec3_chain_complete_with_ents() {
    use RecordType as T;
    let z = ZoneSigner::sign(
        &zone(),
        &csk(Algorithm::Ed25519),
        &policy(nsec3(false)),
        NOW,
    )
    .unwrap();
    let chain = nsec3_records(&z);
    let names = [
        "example.",
        "a.b.c.example.",
        "insecure.example.",
        "ns1.example.",
        "secure.example.",
        "*.wild.example.",
        "www.example.",
        "x.ent2.example.",
    ];
    let ents = [
        "b.c.example.",
        "c.example.",
        "wild.example.",
        "ent2.example.",
    ];
    assert_eq!(chain.len(), names.len() + ents.len());
    let owners: Vec<String> = chain
        .iter()
        .map(|(r, _)| String::from_utf8(r.name.labels().next().unwrap().to_vec()).unwrap())
        .collect();
    for name in names.iter().chain(&ents) {
        assert!(owners.contains(&hash_label(name)), "{name} missing");
    }
    for glue in ["ns.secure.example.", "ns.insecure.example."] {
        assert!(!owners.contains(&hash_label(glue)), "{glue} in chain");
    }
    let mut sorted = owners.clone();
    sorted.sort();
    assert_eq!(owners, sorted, "chain not in hash order");
    for (i, (r, x)) in chain.iter().enumerate() {
        let next = base32hex_encode(&x.next_hashed).to_ascii_lowercase();
        assert_eq!(next, owners[(i + 1) % owners.len()]);
        assert_eq!((x.flags, x.iterations, x.hash_alg), (0, 0, 1));
        assert_eq!(r.ttl, 900);
        assert!(r.name.is_subdomain_of(&n("example.")));
        assert_eq!(r.name.label_count(), 2);
    }
    let bitmap = |name: &str| {
        let label = hash_label(name);
        let (_, x) = chain
            .iter()
            .find(|(r, _)| r.name.labels().next().unwrap() == label.as_bytes())
            .unwrap();
        x.types.types().collect::<Vec<_>>()
    };
    assert_eq!(bitmap("c.example."), []);
    assert_eq!(
        bitmap("insecure.example."),
        [T::Ns],
        "no RRSIG at an insecure cut"
    );
    assert_eq!(bitmap("secure.example."), [T::Ns, T::Ds, T::Rrsig]);
    assert_eq!(
        bitmap("example."),
        [T::Ns, T::Soa, T::Mx, T::Rrsig, T::Dnskey, T::Nsec3param]
    );
    let param = z.rrset(&n("example."), RecordType::Nsec3param).unwrap();
    assert_eq!(
        param.records[0].data,
        RData::Nsec3param(Nsec3Param {
            hash_alg: 1,
            flags: 0,
            iterations: 0,
            salt: Vec::new()
        })
    );
    assert_eq!(param.rrsigs.len(), 1);
    assert_eq!(owners_of(&z, RecordType::Nsec), []);
}

#[test]
fn nsec3_salt_and_iterations_are_used() {
    let denial = Denial::Nsec3 {
        iterations: 2,
        salt: vec![0xaa, 0xbb],
        opt_out: false,
    };
    let z = ZoneSigner::sign(&zone(), &csk(Algorithm::Ed25519), &policy(denial), NOW).unwrap();
    let label =
        base32hex_encode(&nsec3_hash(&n("www.example."), &[0xaa, 0xbb], 2)).to_ascii_lowercase();
    assert!(
        nsec3_records(&z)
            .iter()
            .any(|(r, x)| r.name.labels().next().unwrap() == label.as_bytes()
                && x.salt == [0xaa, 0xbb]
                && x.iterations == 2)
    );
    verify_zone(&z, NOW);
}

#[test]
fn nsec3_opt_out_skips_insecure_delegations() {
    let z = ZoneSigner::sign(&zone(), &csk(Algorithm::Ed25519), &policy(nsec3(true)), NOW).unwrap();
    let chain = nsec3_records(&z);
    let owners: Vec<String> = chain
        .iter()
        .map(|(r, _)| String::from_utf8(r.name.labels().next().unwrap().to_vec()).unwrap())
        .collect();
    for gone in ["insecure.example.", "x.ent2.example.", "ent2.example."] {
        assert!(!owners.contains(&hash_label(gone)), "{gone} not opted out");
    }
    for kept in ["secure.example.", "c.example.", "example."] {
        assert!(owners.contains(&hash_label(kept)), "{kept} missing");
    }
    assert!(chain.iter().all(|(_, x)| x.flags == 1));
    assert_eq!(chain.len(), 9);
    // NSEC3PARAM never carries the opt-out flag (RFC 5155 4.1.2).
    let param = &z
        .rrset(&n("example."), RecordType::Nsec3param)
        .unwrap()
        .records[0];
    assert!(matches!(&param.data, RData::Nsec3param(p) if p.flags == 0));
    // The insecure delegation itself is still unsigned.
    let cut = z.rrset(&n("insecure.example."), RecordType::Ns).unwrap();
    assert_eq!(cut.rrsigs, []);
}

#[test]
fn glue_not_signed() {
    let z = ZoneSigner::sign(
        &zone(),
        &csk(Algorithm::Ed25519),
        &policy(Denial::Nsec),
        NOW,
    )
    .unwrap();
    let unsigned = [
        ("ns.secure.example.", RecordType::A),
        ("ns.insecure.example.", RecordType::A),
        ("insecure.example.", RecordType::A),
        ("secure.example.", RecordType::Ns),
        ("insecure.example.", RecordType::Ns),
        ("x.ent2.example.", RecordType::Ns),
    ];
    for (name, t) in unsigned {
        let set = z.rrset(&n(name), t).expect("glue kept in the snapshot");
        assert!(set.rrsigs.is_empty(), "{name} {t:?} signed");
    }
    assert_eq!(
        z.rrset(&n("secure.example."), RecordType::Ds)
            .unwrap()
            .rrsigs
            .len(),
        1,
        "DS at a delegation is signed"
    );
    assert_eq!(
        z.rrset(&n("example."), RecordType::Ns)
            .unwrap()
            .rrsigs
            .len(),
        1
    );
    assert_eq!(
        z.rrset(&n("ns1.example."), RecordType::A)
            .unwrap()
            .rrsigs
            .len(),
        1,
        "in-zone name server address is authoritative"
    );
    assert!(
        z.rrset(&n("ns.secure.example."), RecordType::Nsec)
            .is_none()
    );
}

#[test]
fn resign_only_near_expiry() {
    let clock = ManualClock::new(i64::from(NOW));
    let now = |c: &ManualClock| u32::try_from(c.now()).unwrap();
    let keys = csk(Algorithm::EcdsaP256Sha256);
    let p = policy(nsec3(false));
    let mut data = zone();
    let first = ZoneSigner::sign(&data, &keys, &p, now(&clock)).unwrap();

    // A day later nothing is near expiry: identical signatures, except for changed data.
    clock.advance(i64::from(DAY));
    data.records.push(a("www.example.", [192, 0, 2, 99]));
    let second = ZoneSigner::resign(&data, &keys, &p, &first, now(&clock)).unwrap();
    verify_zone(&second, now(&clock));
    let www = (n("www.example."), u16::from(RecordType::A));
    for (k, set) in &second.rrsets {
        let old = first.rrsets.get(k);
        if *k == www {
            assert_ne!(old.unwrap().rrsigs, set.rrsigs, "changed RRset re-signed");
        } else if let Some(old) = old {
            assert_eq!(old.rrsigs, set.rrsigs, "{} {} re-signed early", k.0, k.1);
        }
    }
    assert_eq!(second.next_resign, first.next_resign);
    assert!(!second.needs_refresh(now(&clock)));

    // Past the refresh point the due signatures are replaced, later ones kept.
    clock.set(i64::from(first.next_resign));
    assert!(second.needs_refresh(now(&clock)));
    let third = ZoneSigner::resign(&data, &keys, &p, &second, now(&clock)).unwrap();
    verify_zone(&third, now(&clock));
    let mut replaced = 0;
    for (k, set) in &third.rrsets {
        for (old, new) in second.rrsets[k].rrsigs.iter().zip(&set.rrsigs) {
            if old == new {
                assert!(rrsig(old).expiration > now(&clock) + 5 * DAY);
            } else {
                replaced += 1;
                assert!(rrsig(old).expiration <= now(&clock) + 5 * DAY);
                assert_eq!(rrsig(new).inception, now(&clock) - 3600);
            }
        }
    }
    assert!(replaced >= 1);
    assert!(!third.needs_refresh(now(&clock)));

    // A new signing key replaces every signature.
    let other = csk(Algorithm::EcdsaP256Sha256);
    let fourth = ZoneSigner::resign(&data, &other, &p, &third, now(&clock)).unwrap();
    for (k, set) in &fourth.rrsets {
        for sig in &set.rrsigs {
            assert!(!third.rrsets[k].rrsigs.contains(sig));
        }
    }
}

#[test]
fn rollover_dnskey_set_double_signed() {
    let keys = ActiveKeys {
        keys: vec![
            key(KeyRole::Ksk, KeyState::Active),
            key(KeyRole::Ksk, KeyState::Published),
            key(KeyRole::Zsk, KeyState::Active),
            key(KeyRole::Zsk, KeyState::Published),
            ZoneKey::public(
                KeyRole::Zsk,
                KeyState::Retired,
                SigningKey::generate(Algorithm::EcdsaP256Sha256, false)
                    .unwrap()
                    .dnskey(),
            ),
            key(KeyRole::Zsk, KeyState::Generated),
        ],
    };
    let tag = |i: usize| keys.keys[i].dnskey.key_tag();
    let z = ZoneSigner::sign(&zone(), &keys, &policy(Denial::Nsec), NOW).unwrap();
    verify_zone(&z, NOW);
    let published: Vec<Dnskey> = dnskeys(&z);
    assert_eq!(published.len(), 5, "generated key not published");
    assert!(!published.contains(&keys.keys[5].dnskey));
    let tags = |set: &SignedRrset| {
        let mut t: Vec<u16> = set.rrsigs.iter().map(|s| rrsig(s).key_tag).collect();
        t.sort_unstable();
        t
    };
    let mut both_ksks = vec![tag(0), tag(1)];
    both_ksks.sort_unstable();
    assert_eq!(
        tags(z.rrset(&n("example."), RecordType::Dnskey).unwrap()),
        both_ksks
    );
    assert_eq!(
        tags(z.rrset(&n("www.example."), RecordType::A).unwrap()),
        [tag(2)]
    );
    assert_eq!(
        tags(z.rrset(&n("example."), RecordType::Soa).unwrap()),
        [tag(2)]
    );

    let cds = z.rrset(&n("example."), RecordType::Cds).unwrap();
    let cdnskey = z.rrset(&n("example."), RecordType::Cdnskey).unwrap();
    assert_eq!(cds.records.len(), 2);
    assert_eq!(cdnskey.records.len(), 2);
    assert_eq!(cds.records[0].ttl, 3600);
    let expected = ds_for(&n("example."), &keys.keys[1].dnskey, DigestType::Sha256).unwrap();
    assert!(
        cds.records
            .iter()
            .any(|r| r.data == RData::Cds(expected.clone()))
    );
    assert_eq!(cds.rrsigs.len(), 3, "CDS signed by both KSKs and the ZSK");

    // Outside a rollover there is no CDS.
    let calm = ActiveKeys {
        keys: vec![
            key(KeyRole::Ksk, KeyState::Active),
            key(KeyRole::Zsk, KeyState::Active),
        ],
    };
    let z = ZoneSigner::sign(&zone(), &calm, &policy(Denial::Nsec), NOW).unwrap();
    assert!(z.rrset(&n("example."), RecordType::Cds).is_none());
    assert_eq!(
        z.rrset(&n("example."), RecordType::Dnskey)
            .unwrap()
            .rrsigs
            .len(),
        1
    );
}

#[test]
fn retired_ksk_still_signs_dnskey_rrset() {
    let keys = ActiveKeys {
        keys: vec![
            key(KeyRole::Ksk, KeyState::Retired),
            key(KeyRole::Ksk, KeyState::Active),
            key(KeyRole::Zsk, KeyState::Active),
        ],
    };
    let z = ZoneSigner::sign(&zone(), &keys, &policy(Denial::Nsec), NOW).unwrap();
    verify_zone(&z, NOW);
    let mut tags: Vec<u16> = z
        .rrset(&n("example."), RecordType::Dnskey)
        .unwrap()
        .rrsigs
        .iter()
        .map(|s| rrsig(s).key_tag)
        .collect();
    tags.sort_unstable();
    let mut want = vec![keys.keys[0].dnskey.key_tag(), keys.keys[1].dnskey.key_tag()];
    want.sort_unstable();
    assert_eq!(tags, want, "retired and active KSK both sign DNSKEY");
    // The retired key does not sign zone data.
    let www = z.rrset(&n("www.example."), RecordType::A).unwrap();
    assert_eq!(www.rrsigs.len(), 1);
    assert_eq!(rrsig(&www.rrsigs[0]).key_tag, keys.keys[2].dnskey.key_tag());
}

#[test]
fn snapshot_accessors_and_ttl_normalisation() {
    let mut data = zone();
    data.records.push(rec(
        "www.example.",
        60,
        RData::A(Ipv4Addr::new(192, 0, 2, 7)),
    ));
    let z = ZoneSigner::sign(&data, &csk(Algorithm::Ed25519), &policy(Denial::Nsec), NOW).unwrap();
    let www = z.rrset(&n("www.example."), RecordType::A).unwrap();
    assert!(www.records.iter().all(|r| r.ttl == 60));
    assert_eq!(rrsig(&www.rrsigs[0]).original_ttl, 60);
    assert!(z.dnssec_records().all(|r| is_dnssec_type(r.rtype)));
    assert!(z.dnssec_records().any(|r| r.rtype == RecordType::Dnskey));
    let all: Vec<&Record> = z.records().collect();
    assert_eq!(all[0].name, n("example."));
    assert!(all.iter().any(|r| r.rtype == RecordType::Soa));
    let dnskey = z.rrset(&n("example."), RecordType::Dnskey).unwrap();
    assert_eq!(dnskey.records[0].ttl, 3600);
}

#[test]
fn key_duties() {
    use KeyRole::{Csk, Ksk, Zsk};
    use KeyState::{Active, Generated, Published, Removed, Retired};
    assert!(ZoneKey::signs(Csk, Active) && ZoneKey::signs(Zsk, Active));
    assert!(ZoneKey::signs(Ksk, Active) && ZoneKey::signs(Ksk, Published));
    assert!(ZoneKey::signs(Csk, Published));
    assert!(!ZoneKey::signs(Zsk, Published) && !ZoneKey::signs(Zsk, Retired));
    assert!(ZoneKey::signs(Ksk, Retired) && ZoneKey::signs(Csk, Retired));
    assert!(!ZoneKey::signs(Csk, Generated));
    assert!(!ZoneKey::signs(Csk, Removed));
}

#[test]
fn invalid_input_rejected() {
    let keys = csk(Algorithm::Ed25519);
    let p = policy(Denial::Nsec);
    let with = |extra: Record| {
        let mut z = zone();
        z.records.push(extra);
        ZoneSigner::sign(&z, &keys, &p, NOW)
    };
    let invalid =
        |r: Result<SignedZone, DnssecError>| matches!(r, Err(DnssecError::InvalidZone(_)));
    assert!(invalid(with(a("www.other.", [1, 2, 3, 4]))));
    assert!(invalid(with(ds("example."))));
    assert!(invalid(with(ds("www.example."))));
    assert!(invalid(with(rec(
        "www.example.",
        300,
        RData::Dnskey(keys.keys[0].dnskey.clone())
    ))));
    let mut below = soa();
    below.name = n("www.example.");
    assert!(invalid(with(below)));
    let mut no_soa = zone();
    no_soa.records.remove(0);
    assert!(invalid(ZoneSigner::sign(&no_soa, &keys, &p, NOW)));
    assert_eq!(
        ZoneSigner::sign(&zone(), &ActiveKeys::default(), &p, NOW).unwrap_err(),
        DnssecError::NoSigningKey("zone data")
    );
    let zsk_only = ActiveKeys {
        keys: vec![key(KeyRole::Zsk, KeyState::Active)],
    };
    assert_eq!(
        ZoneSigner::sign(&zone(), &zsk_only, &p, NOW).unwrap_err(),
        DnssecError::NoSigningKey("the DNSKEY RRset")
    );
    let public_only = ActiveKeys {
        keys: vec![ZoneKey::public(
            KeyRole::Csk,
            KeyState::Active,
            keys.keys[0].dnskey.clone(),
        )],
    };
    assert_eq!(
        ZoneSigner::sign(&zone(), &public_only, &p, NOW).unwrap_err(),
        DnssecError::InvalidKey
    );
    for (validity, refresh) in [(14, 14), (14, 0), (0, 0), (u32::MAX, 5), (30_000, 5)] {
        let bad = SigningPolicy {
            signature_validity_days: validity,
            refresh_days: refresh,
            ..policy(Denial::Nsec)
        };
        assert_eq!(
            ZoneSigner::sign(&zone(), &keys, &bad, NOW).unwrap_err(),
            DnssecError::InvalidValidity
        );
    }
    let salty = policy(Denial::Nsec3 {
        iterations: 0,
        salt: vec![0; 256],
        opt_out: false,
    });
    assert_eq!(
        ZoneSigner::sign(&zone(), &keys, &salty, NOW).unwrap_err(),
        DnssecError::Nsec3SaltTooLong
    );
    let e = DnssecError::InvalidZone("why");
    assert!(e.to_string().contains("why"));
    assert!(
        DnssecError::NoSigningKey("zone data")
            .to_string()
            .contains("zone data")
    );
}

#[test]
fn nsec3_owner_too_long_rejected() {
    // An origin of 250 octets leaves no room for the 32-character hash label.
    let long = format!(
        "{}.{}.{}.{}.",
        "a".repeat(62),
        "b".repeat(62),
        "c".repeat(62),
        "d".repeat(60)
    );
    let origin = n(&long);
    let mut s = soa();
    s.name = origin.clone();
    let data = ZoneData {
        origin,
        records: vec![s],
    };
    assert_eq!(
        ZoneSigner::sign(&data, &csk(Algorithm::Ed25519), &policy(nsec3(false)), NOW).unwrap_err(),
        DnssecError::InvalidZone("NSEC3 owner name too long")
    );
}
