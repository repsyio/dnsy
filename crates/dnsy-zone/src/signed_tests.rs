use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use dnsy_dnssec::{
    ActiveKeys, Algorithm, KeyRole, KeyState, ManualClock, SignedZone, SigningKey, ZoneKey,
    ZoneSigner, nsec3_hash, verify_rrsig,
};
use dnsy_proto::{
    Class, Dnskey, Message, Name, Question, RData, Record, RecordType, base32hex_encode,
};
use dnsy_store::Store;

use super::*;
use crate::lookup::LookupResult;
use crate::model::Zone;
use crate::store::ZoneSet;

/// Signing time of the fixtures.
const T: u32 = 1_800_000_000;

const ZONE: &str = r#"{"schema":1,"origin":"example.com.","default_ttl":3600,
  "soa":{"mname":"ns1.example.com.","rname":"h.example.com.","serial":1,"refresh":1,"retry":1,
         "expire":1,"minimum":300},
  "records":[
    {"name":"@","type":"NS","value":"ns1.example.com."},
    {"name":"@","type":"MX","value":"10 mail.example.com."},
    {"name":"ns1","type":"A","value":"192.0.2.53"},
    {"name":"mail","type":"A","value":"192.0.2.25"},
    {"name":"www","type":"A","ttl":300,"value":"192.0.2.1"},
    {"name":"www","type":"A","ttl":300,"value":"192.0.2.2"},
    {"name":"www","type":"AAAA","ttl":300,"value":"2001:db8::1"},
    {"name":"alias","type":"CNAME","value":"www.example.com."},
    {"name":"*.wild","type":"TXT","value":"\"wild\""},
    {"name":"*.cw","type":"CNAME","value":"www.example.com."},
    {"name":"a.b.deep","type":"A","value":"192.0.2.77"},
    {"name":"secure","type":"NS","value":"ns.secure.example.com."},
    {"name":"secure","type":"DS","value":"12345 13 2 2BB183AF5F22588179A53B0A98631FAD1A292118A6D2A5EA3E8D9C33D7E5F1D3"},
    {"name":"ns.secure","type":"A","value":"192.0.2.99"},
    {"name":"insecure","type":"NS","value":"ns.elsewhere.org."}
  ],
  "dnssec":{"enabled":true,"algorithm":13,"denial":"DENIAL","nsec3":{"opt_out":OPTOUT}}}"#;

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn zone(denial: &str, opt_out: bool) -> Zone {
    let json = ZONE
        .replace("DENIAL", denial)
        .replace("OPTOUT", &opt_out.to_string());
    Zone::from_json(&json).unwrap().0
}

fn csk() -> ActiveKeys {
    let key = SigningKey::generate(Algorithm::EcdsaP256Sha256, true).unwrap();
    ActiveKeys {
        keys: vec![ZoneKey::new(KeyRole::Csk, KeyState::Active, key)],
    }
}

fn sign(zone: &Zone, keys: &ActiveKeys) -> SignedZone {
    let policy = zone.dnssec.as_ref().unwrap().signing_policy().unwrap();
    ZoneSigner::sign(&zone.signing_data(), keys, &policy, T).unwrap()
}

/// A snapshot serving `zone` signed, and its DNSKEYs.
fn signed_set(zone: Zone) -> (ZoneSet, Vec<Dnskey>) {
    let keys = csk();
    let signed = sign(&zone, &keys);
    let dnskeys = keys.keys.iter().map(|k| k.dnskey.clone()).collect();
    let origin = zone.origin.clone();
    let set = ZoneSet::with_signed(
        BTreeMap::from([(origin.clone(), Arc::new(zone))]),
        BTreeMap::from([(origin, Arc::new(signed))]),
    );
    (set, dnskeys)
}

fn lookup(set: &ZoneSet, qname: &str, qtype: RecordType, dnssec_ok: bool) -> LookupResult {
    let q = Question {
        name: name(qname),
        qtype,
        qclass: Class::In,
    };
    set.lookup(&q, dnssec_ok).unwrap()
}

fn sections(result: &LookupResult) -> Vec<&Record> {
    match result {
        LookupResult::Answer {
            answers,
            authority,
            additional,
        } => answers.iter().chain(authority).chain(additional).collect(),
        LookupResult::Referral {
            ns,
            ds_or_proof,
            glue,
        } => ns.iter().chain(ds_or_proof).chain(glue).collect(),
        LookupResult::NoData { authority } | LookupResult::NxDomain { authority } => {
            authority.iter().collect()
        }
    }
}

fn authority(result: &LookupResult) -> &[Record] {
    match result {
        LookupResult::Answer { authority, .. }
        | LookupResult::NoData { authority }
        | LookupResult::NxDomain { authority } => authority,
        LookupResult::Referral { ds_or_proof, .. } => ds_or_proof,
    }
}

fn is_dnssec(t: RecordType) -> bool {
    matches!(
        t,
        RecordType::Rrsig | RecordType::Nsec | RecordType::Nsec3 | RecordType::Ds
    )
}

/// Checks every RRSIG in `records` against `dnskeys`, and that every `RRset` of a type in
/// `signed_types` carries a valid one. Returns the number of `RRsets` verified.
fn verify_signed(records: &[Record], dnskeys: &[Dnskey], signed_types: &[RecordType]) -> usize {
    let mut sets: BTreeMap<(Name, RecordType), Vec<Record>> = BTreeMap::new();
    for r in records.iter().filter(|r| r.rtype != RecordType::Rrsig) {
        sets.entry((r.name.clone(), r.rtype))
            .or_default()
            .push(r.clone());
    }
    let mut verified = 0;
    for ((owner, rtype), set) in &sets {
        let sigs: Vec<_> = records
            .iter()
            .filter_map(|r| match &r.data {
                RData::Rrsig(s) if r.name == *owner && s.type_covered == *rtype => Some(s),
                _ => None,
            })
            .collect();
        if signed_types.contains(rtype) {
            assert!(!sigs.is_empty(), "{owner} {rtype:?} has no RRSIG");
        }
        for sig in sigs {
            let key = dnskeys
                .iter()
                .find(|k| k.key_tag() == sig.key_tag)
                .expect("signed by a zone key");
            verify_rrsig(set, sig, key, T).unwrap_or_else(|e| panic!("{owner} {rtype:?}: {e}"));
            verified += 1;
        }
    }
    verified
}

fn of_type(records: &[Record], t: RecordType) -> Vec<&Record> {
    records.iter().filter(|r| r.rtype == t).collect()
}

/// True when the NSEC `r` proves that `n` does not exist (owner < n < next, canonically,
/// the last NSEC wrapping to the apex).
fn nsec_covers(r: &Record, n: &Name) -> bool {
    let RData::Nsec { next, .. } = &r.data else {
        return false;
    };
    r.name < *n && (*n < *next || *next <= r.name)
}

fn nsec_matches(r: &Record, n: &Name) -> Option<Vec<RecordType>> {
    match &r.data {
        RData::Nsec { types, .. } if r.name == *n => Some(types.types().collect()),
        _ => None,
    }
}

fn hash_label(n: &Name) -> String {
    base32hex_encode(&nsec3_hash(n, &[], 0)).to_ascii_lowercase()
}

fn owner_label(r: &Record) -> String {
    String::from_utf8_lossy(r.name.labels().next().unwrap()).to_ascii_lowercase()
}

fn nsec3_matches(r: &Record, n: &Name) -> Option<Vec<RecordType>> {
    match &r.data {
        RData::Nsec3(n3) if owner_label(r) == hash_label(n) => Some(n3.types.types().collect()),
        _ => None,
    }
}

fn nsec3_covers(r: &Record, n: &Name) -> bool {
    let RData::Nsec3(n3) = &r.data else {
        return false;
    };
    let (owner, h) = (owner_label(r), hash_label(n));
    let next = base32hex_encode(&n3.next_hashed).to_ascii_lowercase();
    if owner < next {
        owner < h && h < next
    } else {
        h > owner || h < next
    }
}

#[test]
fn do_query_gets_rrsigs() {
    let (set, keys) = signed_set(zone("nsec3", false));
    let result = lookup(&set, "www.example.com.", RecordType::A, true);
    let LookupResult::Answer {
        answers,
        additional,
        ..
    } = &result
    else {
        panic!("{result:?}")
    };
    assert_eq!(of_type(answers, RecordType::A).len(), 2);
    assert_eq!(of_type(answers, RecordType::Rrsig).len(), 1);
    assert_eq!(verify_signed(answers, &keys, &[RecordType::A]), 1);
    assert_eq!(additional.len(), 0);

    // A CNAME chain: each link is signed.
    let result = lookup(&set, "alias.example.com.", RecordType::A, true);
    let LookupResult::Answer { answers, .. } = &result else {
        panic!()
    };
    assert_eq!(
        verify_signed(answers, &keys, &[RecordType::Cname, RecordType::A]),
        2
    );

    // MX targets in the additional section are signed too.
    let result = lookup(&set, "example.com.", RecordType::Mx, true);
    let records: Vec<Record> = sections(&result).into_iter().cloned().collect();
    assert_eq!(
        verify_signed(&records, &keys, &[RecordType::Mx, RecordType::A]),
        2
    );
}

#[test]
fn no_do_no_dnssec_records() {
    let (set, _) = signed_set(zone("nsec", false));
    for (qname, qtype) in [
        ("www.example.com.", RecordType::A),
        ("nope.example.com.", RecordType::A),
        ("www.example.com.", RecordType::Txt),
        ("x.wild.example.com.", RecordType::Txt),
        ("host.secure.example.com.", RecordType::A),
        ("host.insecure.example.com.", RecordType::A),
        ("example.com.", RecordType::Any),
    ] {
        let result = lookup(&set, qname, qtype, false);
        let dnssec: Vec<_> = sections(&result)
            .into_iter()
            .filter(|r| is_dnssec(r.rtype))
            .collect();
        assert!(dnssec.is_empty(), "{qname} {qtype:?}: {dnssec:?}");
    }
    // Types asked for explicitly are still answered.
    let result = lookup(&set, "example.com.", RecordType::Dnskey, false);
    let LookupResult::Answer { answers, .. } = result else {
        panic!()
    };
    assert_eq!(of_type(&answers, RecordType::Dnskey).len(), 1);
    assert_eq!(of_type(&answers, RecordType::Rrsig).len(), 0);
}

#[test]
fn unsigned_zone_ignores_do() {
    let (zone, _) = Zone::from_json(&ZONE.replace(",\n  \"dnssec\":{\"enabled\":true,\"algorithm\":13,\"denial\":\"DENIAL\",\"nsec3\":{\"opt_out\":OPTOUT}}", "")).unwrap();
    let set = ZoneSet::new(BTreeMap::from([(zone.origin.clone(), Arc::new(zone))]));
    let result = lookup(&set, "nope.example.com.", RecordType::A, true);
    assert_eq!(authority(&result).len(), 1);
    assert!(set.signed(&name("example.com.")).is_none());
}

#[test]
fn nxdomain_has_nsec3_proof() {
    let (set, keys) = signed_set(zone("nsec3", false));
    let qname = name("nope.www.example.com.");
    let result = lookup(&set, "nope.www.example.com.", RecordType::A, true);
    assert!(matches!(result, LookupResult::NxDomain { .. }));
    let auth = authority(&result);
    let nsec3 = of_type(auth, RecordType::Nsec3);
    // Closest encloser www (matching), next closer nope.www (covered), *.www (covered).
    assert_eq!(nsec3.len(), 3, "{auth:?}");
    let ce = name("www.example.com.");
    assert!(nsec3.iter().any(|r| nsec3_matches(r, &ce).is_some()));
    assert!(nsec3.iter().any(|r| nsec3_covers(r, &qname)));
    assert!(
        nsec3
            .iter()
            .any(|r| nsec3_covers(r, &name("*.www.example.com.")))
    );
    assert_eq!(
        verify_signed(auth, &keys, &[RecordType::Soa, RecordType::Nsec3]),
        4
    );
}

#[test]
fn nxdomain_has_nsec_proof() {
    let (set, keys) = signed_set(zone("nsec", false));
    let qname = name("nope.example.com.");
    let result = lookup(&set, "nope.example.com.", RecordType::A, true);
    let auth = authority(&result);
    let nsec = of_type(auth, RecordType::Nsec);
    assert!(nsec.iter().any(|r| nsec_covers(r, &qname)));
    assert!(nsec.iter().any(|r| nsec_covers(r, &name("*.example.com."))));
    verify_signed(auth, &keys, &[RecordType::Soa, RecordType::Nsec]);
}

#[test]
fn nodata_has_nsec_proof() {
    let (set, keys) = signed_set(zone("nsec", false));
    let result = lookup(&set, "www.example.com.", RecordType::Txt, true);
    assert!(matches!(result, LookupResult::NoData { .. }));
    let auth = authority(&result);
    let nsec = of_type(auth, RecordType::Nsec);
    assert_eq!(nsec.len(), 1);
    let types = nsec_matches(nsec[0], &name("www.example.com.")).unwrap();
    assert!(types.contains(&RecordType::A) && !types.contains(&RecordType::Txt));
    verify_signed(auth, &keys, &[RecordType::Soa, RecordType::Nsec]);

    // An empty non-terminal: the NSEC whose span holds it.
    let result = lookup(&set, "b.deep.example.com.", RecordType::A, true);
    assert!(matches!(result, LookupResult::NoData { .. }));
    let nsec = of_type(authority(&result), RecordType::Nsec);
    assert!(nsec_covers(nsec[0], &name("b.deep.example.com.")));
}

#[test]
fn nodata_has_nsec3_proof() {
    let (set, keys) = signed_set(zone("nsec3", false));
    for qname in ["www.example.com.", "b.deep.example.com."] {
        let result = lookup(&set, qname, RecordType::Txt, true);
        let auth = authority(&result);
        let nsec3 = of_type(auth, RecordType::Nsec3);
        assert_eq!(nsec3.len(), 1, "{qname}");
        let types = nsec3_matches(nsec3[0], &name(qname)).unwrap();
        assert!(!types.contains(&RecordType::Txt));
        verify_signed(auth, &keys, &[RecordType::Soa, RecordType::Nsec3]);
    }
}

#[test]
fn wildcard_answer_has_proof() {
    for denial in ["nsec", "nsec3"] {
        let (set, keys) = signed_set(zone(denial, false));
        let qname = name("x.y.wild.example.com.");
        let result = lookup(&set, "x.y.wild.example.com.", RecordType::Txt, true);
        let LookupResult::Answer {
            answers,
            authority: proof,
            ..
        } = &result
        else {
            panic!("{result:?}")
        };
        // The RRSIG is owned by the query name with the wildcard's label count.
        let sig = of_type(answers, RecordType::Rrsig)[0];
        assert_eq!(sig.name, qname);
        let RData::Rrsig(s) = &sig.data else { panic!() };
        assert_eq!(s.labels, 3);
        assert_eq!(verify_signed(answers, &keys, &[RecordType::Txt]), 1);
        // Proof that the query name (next closer y.wild for NSEC3) does not exist.
        if denial == "nsec" {
            let nsec = of_type(proof, RecordType::Nsec);
            assert_eq!(nsec.len(), 1);
            assert!(nsec_covers(nsec[0], &qname));
        } else {
            let nsec3 = of_type(proof, RecordType::Nsec3);
            assert_eq!(nsec3.len(), 1);
            assert!(nsec3_covers(nsec3[0], &name("y.wild.example.com.")));
        }
        verify_signed(proof, &keys, &[RecordType::Nsec, RecordType::Nsec3]);

        // A wildcard CNAME: the expanded CNAME is signed and proven.
        let result = lookup(&set, "a.cw.example.com.", RecordType::A, true);
        let LookupResult::Answer {
            answers,
            authority: proof,
            ..
        } = &result
        else {
            panic!()
        };
        verify_signed(answers, &keys, &[RecordType::Cname, RecordType::A]);
        assert_ne!(proof.len(), 0);

        // Wildcard NODATA: the query name is covered and the wildcard matched without TXT.
        let result = lookup(&set, "z.cw.example.com.", RecordType::Cname, true);
        assert!(matches!(result, LookupResult::Answer { .. }));
        let result = lookup(&set, "x.wild.example.com.", RecordType::A, true);
        let auth = authority(&result);
        let star = name("*.wild.example.com.");
        if denial == "nsec" {
            let nsec = of_type(auth, RecordType::Nsec);
            assert!(
                nsec.iter()
                    .any(|r| nsec_covers(r, &name("x.wild.example.com.")))
            );
            assert!(nsec.iter().any(|r| nsec_matches(r, &star).is_some()));
        } else {
            let nsec3 = of_type(auth, RecordType::Nsec3);
            assert_eq!(nsec3.len(), 3);
            assert!(nsec3.iter().any(|r| nsec3_matches(r, &star).is_some()));
            assert!(
                nsec3
                    .iter()
                    .any(|r| nsec3_matches(r, &name("wild.example.com.")).is_some())
            );
        }
        verify_signed(auth, &keys, &[RecordType::Nsec, RecordType::Nsec3]);
    }
}

#[test]
fn referral_includes_signed_ds() {
    let (set, keys) = signed_set(zone("nsec3", false));
    let result = lookup(&set, "host.secure.example.com.", RecordType::A, true);
    let LookupResult::Referral {
        ns,
        ds_or_proof,
        glue,
    } = &result
    else {
        panic!("{result:?}")
    };
    assert!(
        of_type(ns, RecordType::Rrsig).is_empty(),
        "NS at a cut is unsigned"
    );
    assert!(
        of_type(glue, RecordType::Rrsig).is_empty(),
        "glue is unsigned"
    );
    assert_eq!(of_type(ds_or_proof, RecordType::Ds).len(), 1);
    assert_eq!(verify_signed(ds_or_proof, &keys, &[RecordType::Ds]), 1);

    // Without DO: NS and glue only.
    let result = lookup(&set, "host.secure.example.com.", RecordType::A, false);
    let LookupResult::Referral { ds_or_proof, .. } = result else {
        panic!()
    };
    assert_eq!(ds_or_proof.len(), 0);

    // An insecure delegation: proof that there is no DS.
    for denial in ["nsec", "nsec3"] {
        let (set, keys) = signed_set(zone(denial, false));
        let cut = name("insecure.example.com.");
        let result = lookup(&set, "host.insecure.example.com.", RecordType::A, true);
        let proof = authority(&result);
        assert_eq!(of_type(proof, RecordType::Ds).len(), 0);
        let types = proof
            .iter()
            .find_map(|r| nsec_matches(r, &cut).or_else(|| nsec3_matches(r, &cut)))
            .expect("matching NSEC/NSEC3 at the cut");
        assert!(types.contains(&RecordType::Ns) && !types.contains(&RecordType::Ds));
        verify_signed(proof, &keys, &[RecordType::Nsec, RecordType::Nsec3]);
    }
}

#[test]
fn ds_query_at_the_cut_is_answered_by_the_parent() {
    let (set, keys) = signed_set(zone("nsec", false));
    let result = lookup(&set, "secure.example.com.", RecordType::Ds, true);
    let LookupResult::Answer { answers, .. } = &result else {
        panic!("{result:?}")
    };
    assert_eq!(verify_signed(answers, &keys, &[RecordType::Ds]), 1);
    let result = lookup(&set, "insecure.example.com.", RecordType::Ds, true);
    assert!(matches!(result, LookupResult::NoData { .. }));
    let nsec = of_type(authority(&result), RecordType::Nsec);
    assert!(nsec_matches(nsec[0], &name("insecure.example.com.")).is_some());
}

#[test]
fn opt_out_delegation_proof() {
    let (set, keys) = signed_set(zone("nsec3", true));
    let cut = name("insecure.example.com.");
    let result = lookup(&set, "host.insecure.example.com.", RecordType::A, true);
    assert!(matches!(result, LookupResult::Referral { .. }));
    let proof = authority(&result);
    let nsec3 = of_type(proof, RecordType::Nsec3);
    // No NSEC3 for the cut: closest provable encloser (the apex) plus an opt-out NSEC3
    // covering the delegation name.
    assert!(nsec3.iter().all(|r| nsec3_matches(r, &cut).is_none()));
    assert!(
        nsec3
            .iter()
            .any(|r| nsec3_matches(r, &name("example.com.")).is_some())
    );
    let cover = nsec3
        .iter()
        .find(|r| nsec3_covers(r, &cut))
        .expect("covering NSEC3");
    let RData::Nsec3(n3) = &cover.data else {
        panic!()
    };
    assert_eq!(n3.flags & 1, 1, "opt-out flag");
    verify_signed(proof, &keys, &[RecordType::Nsec3]);
    // A DS query for the opt-out delegation gets the same proof (RFC 5155 7.2.4).
    let result = lookup(&set, "insecure.example.com.", RecordType::Ds, true);
    assert!(matches!(result, LookupResult::NoData { .. }));
    assert!(
        of_type(authority(&result), RecordType::Nsec3)
            .iter()
            .any(|r| nsec3_covers(r, &cut))
    );
}

#[test]
fn apex_dnssec_records_are_answered() {
    let (set, keys) = signed_set(zone("nsec3", false));
    for qtype in [RecordType::Dnskey, RecordType::Nsec3param] {
        let result = lookup(&set, "example.com.", qtype, true);
        let LookupResult::Answer { answers, .. } = &result else {
            panic!("{qtype:?}: {result:?}")
        };
        assert_eq!(of_type(answers, qtype).len(), 1);
        assert_eq!(verify_signed(answers, &keys, &[qtype]), 1);
    }
    // No rollover in progress: CDS is NODATA, proven by the apex NSEC3.
    let result = lookup(&set, "example.com.", RecordType::Cds, true);
    assert!(matches!(result, LookupResult::NoData { .. }));
    // NSEC3 owner names do not exist (RFC 5155 7.2.8).
    let owner = format!("{}.example.com.", hash_label(&name("www.example.com.")));
    let result = lookup(&set, &owner, RecordType::Nsec3, true);
    assert!(matches!(result, LookupResult::NxDomain { .. }));
}

#[test]
fn cds_and_cdnskey_during_rollover() {
    let zone = zone("nsec", false);
    let old = SigningKey::generate(Algorithm::EcdsaP256Sha256, true).unwrap();
    let new = SigningKey::generate(Algorithm::EcdsaP256Sha256, true).unwrap();
    let keys = ActiveKeys {
        keys: vec![
            ZoneKey::new(KeyRole::Csk, KeyState::Active, old),
            ZoneKey::new(KeyRole::Csk, KeyState::Published, new),
        ],
    };
    let dnskeys: Vec<Dnskey> = keys.keys.iter().map(|k| k.dnskey.clone()).collect();
    let signed = sign(&zone, &keys);
    let origin = zone.origin.clone();
    let set = ZoneSet::with_signed(
        BTreeMap::from([(origin.clone(), Arc::new(zone))]),
        BTreeMap::from([(origin, Arc::new(signed))]),
    );
    for qtype in [RecordType::Cds, RecordType::Cdnskey, RecordType::Dnskey] {
        let result = lookup(&set, "example.com.", qtype, true);
        let LookupResult::Answer { answers, .. } = &result else {
            panic!("{qtype:?}")
        };
        assert_eq!(of_type(answers, qtype).len(), 2);
        assert!(verify_signed(answers, &dnskeys, &[qtype]) >= 2);
    }
}

#[test]
fn large_signed_answer_truncates_not_strips() {
    let mut json = ZONE.replace("DENIAL", "nsec").replace("OPTOUT", "false");
    let txt: String = (0..40).fold(String::new(), |mut acc, i| {
        let _ = write!(
            acc,
            r#"{{"name":"big","type":"TXT","value":"\"record {i:02} padding padding padding\""}},"#
        );
        acc
    });
    json = json.replace(r#""records":["#, &format!(r#""records":[{txt}"#));
    let (zone, _) = Zone::from_json(&json).unwrap();
    let (set, keys) = signed_set(zone);
    let result = lookup(&set, "big.example.com.", RecordType::Txt, true);
    let LookupResult::Answer { answers, .. } = result else {
        panic!()
    };
    assert_eq!(verify_signed(&answers, &keys, &[RecordType::Txt]), 1);

    let mut query = Message::decode(&[0; 12]).unwrap();
    query.questions.push(Question {
        name: name("big.example.com."),
        qtype: RecordType::Txt,
        qclass: Class::In,
    });
    let mut msg = Message::response_to(&query);
    msg.header.aa = true;
    msg.answers = answers;
    // Over UDP at 512 octets the answer does not fit: TC is set, nothing is served as a
    // complete but unsigned answer.
    let wire = msg.encode(512).unwrap();
    let truncated = Message::decode(&wire).unwrap();
    assert!(truncated.header.tc);
    let kept_txt = truncated.answers.iter().any(|r| r.rtype == RecordType::Txt);
    let kept_sig = truncated
        .answers
        .iter()
        .any(|r| r.rtype == RecordType::Rrsig);
    assert!(!kept_txt || kept_sig, "TXT served without its RRSIG");
    // Over TCP the whole signed answer is sent.
    let full = Message::decode(&msg.encode(65_535).unwrap()).unwrap();
    assert!(!full.header.tc);
    assert_eq!(full.answers.len(), 41);
    assert_eq!(of_type(&full.answers, RecordType::Rrsig).len(), 1);
}

// The signing service.

struct Fixture {
    dir: tempfile::TempDir,
    zones: tempfile::TempDir,
    store: Arc<ZoneStore>,
    signing: ZoneSigning,
    keys: KeyStore,
    clock: ManualClock,
}

fn write_zone(dir: &std::path::Path, json: &str) {
    std::fs::write(dir.join("example.com.json"), json).unwrap();
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let zones = tempfile::tempdir().unwrap();
    write_zone(
        zones.path(),
        &ZONE.replace("DENIAL", "nsec3").replace("OPTOUT", "false"),
    );
    let store = ZoneStore::open(zones.path()).unwrap();
    let clock = ManualClock::new(i64::from(T));
    let db = Store::open(&dir.path().join("dnsy.db")).unwrap();
    let keys = KeyStore::open(db, None, Arc::new(clock.clone()));
    let signing = ZoneSigning::new(Arc::clone(&store), keys.clone());
    Fixture {
        dir,
        zones,
        store,
        signing,
        keys,
        clock,
    }
}

fn origin() -> Name {
    name("example.com.")
}

fn rrsig_count(set: &ZoneSet, qname: &str, qtype: RecordType) -> usize {
    let result = lookup(set, qname, qtype, true);
    of_type(
        &sections(&result).into_iter().cloned().collect::<Vec<_>>(),
        RecordType::Rrsig,
    )
    .len()
}

#[tokio::test]
async fn sign_due_bootstraps_keys_and_serves_signed() {
    let f = fixture();
    // Before the first signing pass the zone serves unsigned.
    assert!(f.store.snapshot().signed(&origin()).is_none());
    assert_eq!(f.signing.sign_due().await, 1);
    let snap = f.store.snapshot();
    assert!(snap.signed(&origin()).is_some());
    let dnskeys: Vec<Dnskey> = f
        .keys
        .dnskeys(&origin())
        .await
        .unwrap()
        .into_iter()
        .map(|(_, k)| k)
        .collect();
    assert_eq!(dnskeys.len(), 1);
    let result = lookup(&snap, "www.example.com.", RecordType::A, true);
    let LookupResult::Answer { answers, .. } = result else {
        panic!()
    };
    verify_signed(&answers, &dnskeys, &[RecordType::A]);
    // Nothing is due straight after signing.
    assert_eq!(f.signing.sign_due().await, 0);
    assert!(format!("{:?}", f.signing).contains("ZoneSigning"));
    assert!(!f.signing.keys().keys_encrypted());
}

#[tokio::test]
async fn resign_on_reload() {
    let f = fixture();
    f.signing.sign_due().await;
    // A changed zone keeps serving its previous signed version until it is re-signed.
    let json = ZONE
        .replace("DENIAL", "nsec3")
        .replace("OPTOUT", "false")
        .replace(r#""serial":1"#, r#""serial":2"#)
        .replace(
            r#"{"name":"mail""#,
            r#"{"name":"new","type":"A","value":"192.0.2.200"},{"name":"mail""#,
        );
    write_zone(f.zones.path(), &json);
    f.store.reload().unwrap();
    let snap = f.store.snapshot();
    assert_eq!(snap.get(&origin()).unwrap().soa.serial, 1);
    assert!(matches!(
        lookup(&snap, "new.example.com.", RecordType::A, true),
        LookupResult::NxDomain { .. }
    ));
    // The refresh task wakes on the reload and installs the new snapshot.
    let task = f
        .signing
        .clone()
        .spawn(std::time::Duration::from_secs(3600));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while f.store.snapshot().get(&origin()).unwrap().soa.serial != 2 {
        assert!(std::time::Instant::now() < deadline, "not re-signed");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    task.abort();
    let snap = f.store.snapshot();
    assert_eq!(rrsig_count(&snap, "new.example.com.", RecordType::A), 1);
    assert_eq!(rrsig_count(&snap, "www.example.com.", RecordType::A), 1);
}

#[tokio::test]
async fn resign_when_signatures_near_expiry_or_keys_change() {
    let f = fixture();
    f.signing.sign_due().await;
    let first = Arc::clone(f.store.snapshot().signed(&origin()).unwrap());
    // Ten days later (validity 14, refresh 5) some signatures fall due.
    f.clock.set(i64::from(T) + 10 * 86_400);
    assert_eq!(f.signing.sign_due().await, 1);
    let second = Arc::clone(f.store.snapshot().signed(&origin()).unwrap());
    assert_ne!(first.next_resign, second.next_resign);

    // A ZSK-less CSK rollover publishes a new key: the DNSKEY RRset changes.
    f.keys
        .start_rollover(&origin(), KeyRole::Csk, Algorithm::EcdsaP256Sha256)
        .await
        .unwrap();
    assert_eq!(f.signing.sign_due().await, 1);
    let snap = f.store.snapshot();
    let LookupResult::Answer { answers, .. } =
        lookup(&snap, "example.com.", RecordType::Dnskey, true)
    else {
        panic!()
    };
    assert_eq!(of_type(&answers, RecordType::Dnskey).len(), 2);
}

#[tokio::test]
async fn disabled_or_removed_zone_drops_signed_snapshot() {
    let f = fixture();
    f.signing.sign_due().await;
    write_zone(
        f.zones.path(),
        &ZONE
            .replace("DENIAL", "nsec3")
            .replace("OPTOUT", "false")
            .replace(r#""enabled":true"#, r#""enabled":false"#),
    );
    f.store.reload().unwrap();
    let snap = f.store.snapshot();
    assert!(snap.signed(&origin()).is_none());
    assert_eq!(rrsig_count(&snap, "www.example.com.", RecordType::A), 0);
    assert_eq!(f.signing.sign_due().await, 0);
}

#[tokio::test]
async fn signing_failure_keeps_zone_serving() {
    let f = fixture();
    // Keys sealed under a passphrase the signer does not have.
    let db = Store::open(&f.dir.path().join("other.db")).unwrap();
    let sealed = KeyStore::open(
        db.clone(),
        Some(crate::Passphrase::new("secret")),
        Arc::new(f.clock.clone()),
    )
    .with_kdf_cost(crate::KdfCost {
        memory_kib: 8,
        iterations: 1,
    });
    let policy = f.store.snapshot().get(&origin()).unwrap().dnssec.clone();
    sealed.bootstrap(&origin(), &policy.unwrap()).await.unwrap();
    let locked = KeyStore::open(db, None, Arc::new(f.clock.clone()));
    let signing = ZoneSigning::new(Arc::clone(&f.store), locked);
    assert_eq!(signing.sign_due().await, 0);
    let snap = f.store.snapshot();
    assert!(snap.signed(&origin()).is_none());
    assert!(matches!(
        lookup(&snap, "www.example.com.", RecordType::A, true),
        LookupResult::Answer { .. }
    ));
}
