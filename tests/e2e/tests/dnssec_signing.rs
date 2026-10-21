//! Zone signing through the REST API and the signed answers it produces, checked over every
//! transport and validated with the `dnsy-dnssec` validator, the way a resolver would.

use dnsy_dnssec::{DigestType, ValidationOutcome, ds_for};
use dnsy_e2e::dnssec::{anchors_for, dnssec_query, ds_from_export, first_a, validate_answer};
use dnsy_e2e::zones::{example_zone, zone_json};
use dnsy_e2e::{Framed, Harness, MtlsPolicy, Opts, Token, udp_exchange};
use dnsy_proto::{Message, Name, RData, Rcode, RecordType};
use reqwest::Method;
use serde_json::{Value, json};

use dnsy_core::DnssecStatus;

const ZONE: &str = "example.test.";

fn opts() -> Opts {
    Opts {
        dot: Some(MtlsPolicy::Off),
        doh: true,
        ..Opts::default().zone(ZONE, signing_zone())
    }
}

/// `example_zone` plus an unsigned delegation, a signed delegation (with a DS) and a wildcard.
fn signing_zone() -> String {
    zone_json(
        ZONE,
        &[
            ("www", "A", "192.0.2.7"),
            ("*.wild", "A", "192.0.2.99"),
            ("txt", "TXT", "hello"),
            ("plain", "NS", "ns.other.invalid."),
            ("secure", "NS", "ns.other.invalid."),
            (
                "secure",
                "DS",
                "12345 13 2 0102030405060708091011121314151617181920212223242526272829303132",
            ),
        ],
        false,
    )
}

async fn put_policy(h: &Harness, policy: Value) -> Value {
    let (status, body) = h
        .api_send(Method::PUT, &format!("/zones/{ZONE}/dnssec"), Some(policy))
        .await;
    assert_eq!(status, 200, "{body}");
    body
}

async fn sign(h: &Harness, policy: Value) -> Value {
    put_policy(h, policy).await
}

/// The DS (SHA-256) of the zone's first KSK or CSK, as the API exports it.
async fn exported_ds(h: &Harness) -> Value {
    let (status, body) = h
        .api_send(Method::GET, &format!("/zones/{ZONE}/dnssec/ds"), None)
        .await;
    assert_eq!(status, 200, "{body}");
    body["ds"]
        .as_array()
        .and_then(|a| a.iter().find(|d| d["digest_type"] == 2))
        .cloned()
        .expect("a SHA-256 DS")
}

/// UDP first; over TCP when the answer is truncated.
async fn ask(h: &Harness, q: &Message) -> Message {
    let r = udp_exchange(h.udp, q).await;
    if !r.header.tc {
        return r;
    }
    h.tcp_client().await.ask(q).await.expect("tcp exchange")
}

async fn validate(h: &Harness, q: &Message, r: &Message) -> ValidationOutcome {
    let ds = ds_from_export(&exported_ds(h).await);
    validate_answer(h.udp, anchors_for(ZONE, ds), q, r).await
}

fn types(m: &Message) -> Vec<RecordType> {
    m.answers
        .iter()
        .chain(&m.authority)
        .map(|r| r.rtype)
        .collect()
}

#[tokio::test]
async fn signed_local_zone_do_query() {
    let h = Harness::start(opts()).await;
    let view = sign(&h, json!({"enabled": true, "denial": "nsec"})).await;
    assert_eq!(view["keys"].as_array().expect("keys").len(), 1, "one CSK");

    let q = dnssec_query("www.example.test.", RecordType::A);
    let r = ask(&h, &q).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert!(r.header.aa);
    assert!(!r.header.ad, "AD is never set on authoritative data");
    assert_eq!(first_a(&r), "192.0.2.7");
    assert!(types(&r).contains(&RecordType::Rrsig));
    assert_eq!(validate(&h, &q, &r).await.status, DnssecStatus::Secure);

    // Without DO the same zone answers without any DNSSEC record.
    let plain = ask(&h, &dnsy_e2e::query("www.example.test.", RecordType::A)).await;
    assert_eq!(types(&plain), [RecordType::A]);

    // A tampered answer does not validate.
    let mut forged = r.clone();
    forged.answers[0].data = RData::A("203.0.113.66".parse().expect("ip"));
    assert_eq!(validate(&h, &q, &forged).await.status, DnssecStatus::Bogus);
}

#[tokio::test]
async fn signed_answers_validate_over_every_transport() {
    let h = Harness::start(opts()).await;
    sign(&h, json!({"enabled": true})).await;
    let ds = ds_from_export(&exported_ds(&h).await);

    let q = dnssec_query("www.example.test.", RecordType::A);
    let mut replies = vec![("udp", udp_exchange(h.udp, &q).await)];
    replies.push(("tcp", h.tcp_client().await.ask(&q).await.expect("tcp")));
    let mut dot = Framed::connect_dot(h.dot.expect("dot"), &h.pki, None)
        .await
        .expect("dot connect");
    replies.push(("dot", dot.ask(&q).await.expect("dot")));
    let doh = h
        .doh_client(true)
        .post(&q, &Token::Bearer(h.doh_token.clone()))
        .await;
    assert_eq!(doh.status, 200);
    replies.push(("doh", doh.message()));

    for (transport, r) in replies {
        assert_eq!(r.header.rcode, Rcode::NoError, "{transport}");
        assert!(types(&r).contains(&RecordType::Rrsig), "{transport}");
        let outcome = validate_answer(h.udp, anchors_for(ZONE, ds.clone()), &q, &r).await;
        assert_eq!(outcome.status, DnssecStatus::Secure, "{transport}");
    }
}

#[tokio::test]
async fn apex_dnskey_is_served_and_ds_export_matches_it() {
    let h = Harness::start(opts()).await;
    sign(&h, json!({"enabled": true, "key_layout": "ksk_zsk"})).await;

    let q = dnssec_query(ZONE, RecordType::Dnskey);
    let r = ask(&h, &q).await;
    let keys: Vec<_> = r
        .answers
        .iter()
        .filter_map(|rec| match &rec.data {
            RData::Dnskey(k) => Some(k.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(keys.len(), 2, "KSK and ZSK");
    let ksk = keys.iter().find(|k| k.is_sep()).expect("a SEP key");
    assert!(keys.iter().any(|k| !k.is_sep() && k.is_zone_key()));
    assert_eq!(
        validate(&h, &q, &r).await.status,
        DnssecStatus::Secure,
        "the KSK signs the DNSKEY RRset"
    );

    let (_, export) = h
        .api_send(Method::GET, &format!("/zones/{ZONE}/dnssec/ds"), None)
        .await;
    let origin = Name::from_ascii(ZONE).expect("zone");
    let exported = export["ds"].as_array().expect("ds list");
    assert_eq!(exported.len(), 2, "SHA-256 and SHA-384 for the one KSK");
    for entry in exported {
        let digest = if entry["digest_type"] == 2 {
            DigestType::Sha256
        } else {
            DigestType::Sha384
        };
        let want = ds_for(&origin, ksk, digest).expect("ds");
        let got = ds_from_export(entry);
        assert_eq!(
            got, want,
            "export equals the DS computed from the served KSK"
        );
        assert_eq!(got.key_tag, ksk.key_tag());
    }
    let dnskeys = export["dnskey"].as_array().expect("dnskey list");
    assert_eq!(dnskeys.len(), 1, "only the KSK is handed to the registrar");
    assert_eq!(dnskeys[0]["key_tag"], ksk.key_tag());

    // The text form is zone-file lines.
    let text = reqwest::Client::new()
        .get(format!("http://{}/api/v1/zones/{ZONE}/dnssec/ds", h.api))
        .bearer_auth(&h.api_token)
        .header("accept", "text/plain")
        .send()
        .await
        .expect("request")
        .text()
        .await
        .expect("body");
    assert!(text.lines().any(|l| l.starts_with("example.test. IN DS ")));
    assert!(
        text.lines()
            .any(|l| l.starts_with("example.test. IN DNSKEY 257 "))
    );
}

#[tokio::test]
async fn nsec_denial_validates() {
    let h = Harness::start(opts()).await;
    sign(&h, json!({"enabled": true, "denial": "nsec"})).await;
    let q = dnssec_query("nope.example.test.", RecordType::A);
    let r = ask(&h, &q).await;
    assert_eq!(r.header.rcode, Rcode::NxDomain);
    assert!(types(&r).contains(&RecordType::Nsec));
    assert_eq!(validate(&h, &q, &r).await.status, DnssecStatus::Secure);

    let q = dnssec_query("www.example.test.", RecordType::Aaaa);
    let r = ask(&h, &q).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(r.answers.len(), 0);
    assert!(types(&r).contains(&RecordType::Nsec));
    assert_eq!(validate(&h, &q, &r).await.status, DnssecStatus::Secure);
}

#[tokio::test]
async fn nsec3_nxdomain_validates() {
    let h = Harness::start(opts()).await;
    let view = sign(&h, json!({"enabled": true, "denial": "nsec3"})).await;
    assert_eq!(view["nsec3"]["iterations"], 0);
    assert_eq!(view["nsec3"]["salt"], "");
    let q = dnssec_query("nope.example.test.", RecordType::A);
    let r = ask(&h, &q).await;
    assert_eq!(r.header.rcode, Rcode::NxDomain);
    assert!(types(&r).contains(&RecordType::Nsec3));
    assert!(!types(&r).contains(&RecordType::Nsec));
    assert_eq!(validate(&h, &q, &r).await.status, DnssecStatus::Secure);

    let q = dnssec_query("www.example.test.", RecordType::Aaaa);
    let r = ask(&h, &q).await;
    assert!(types(&r).contains(&RecordType::Nsec3));
    assert_eq!(validate(&h, &q, &r).await.status, DnssecStatus::Secure);

    // The apex carries the parameters.
    let q = dnssec_query(ZONE, RecordType::Nsec3param);
    let r = ask(&h, &q).await;
    assert_eq!(r.answers[0].rtype, RecordType::Nsec3param);
}

#[tokio::test]
async fn wildcard_signed_answer_validates() {
    for denial in ["nsec", "nsec3"] {
        let h = Harness::start(opts()).await;
        sign(&h, json!({"enabled": true, "denial": denial})).await;
        let q = dnssec_query("anything.wild.example.test.", RecordType::A);
        let r = ask(&h, &q).await;
        assert_eq!(r.header.rcode, Rcode::NoError, "{denial}");
        assert_eq!(first_a(&r), "192.0.2.99");
        assert_eq!(r.answers[0].name.to_string(), "anything.wild.example.test.");
        let rrsig = r
            .answers
            .iter()
            .find_map(|rec| match &rec.data {
                RData::Rrsig(s) => Some(s.clone()),
                _ => None,
            })
            .expect("RRSIG");
        assert_eq!(
            rrsig.labels, 3,
            "the RRSIG records the wildcard's label count"
        );
        assert!(
            types(&r).contains(&RecordType::Nsec) || types(&r).contains(&RecordType::Nsec3),
            "the expansion carries the proof that the name does not exist"
        );
        assert_eq!(
            validate(&h, &q, &r).await.status,
            DnssecStatus::Secure,
            "{denial}"
        );
    }
}

#[tokio::test]
async fn ds_at_delegation_is_signed_and_absence_is_proven() {
    let h = Harness::start(opts()).await;
    sign(&h, json!({"enabled": true, "denial": "nsec"})).await;

    // The parent signs the DS of a delegation.
    let q = dnssec_query("secure.example.test.", RecordType::Ds);
    let r = ask(&h, &q).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(r.answers[0].rtype, RecordType::Ds);
    assert!(types(&r).contains(&RecordType::Rrsig));
    assert_eq!(validate(&h, &q, &r).await.status, DnssecStatus::Secure);

    // The delegation NS set itself is not signed (it is the child's data).
    let ns = ask(&h, &dnssec_query("secure.example.test.", RecordType::Ns)).await;
    assert!(!types(&ns).contains(&RecordType::Rrsig) || ns.answers.is_empty());

    // No DS at the unsigned delegation: a signed NODATA with an NSEC that lacks DS.
    let q = dnssec_query("plain.example.test.", RecordType::Ds);
    let r = ask(&h, &q).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(r.answers.len(), 0);
    let nsec = r
        .authority
        .iter()
        .find(|rec| rec.rtype == RecordType::Nsec && rec.name.to_string() == "plain.example.test.")
        .expect("NSEC at the delegation");
    let RData::Nsec { types, .. } = &nsec.data else {
        unreachable!()
    };
    assert!(types.to_string().contains("NS"));
    assert!(!types.to_string().contains("DS"));
    assert_eq!(validate(&h, &q, &r).await.status, DnssecStatus::Secure);
}

#[tokio::test]
async fn enabling_signing_twice_keeps_one_key_set() {
    let h = Harness::start(opts()).await;
    sign(&h, json!({"enabled": true})).await;
    let again = sign(&h, json!({"enabled": true})).await;
    assert_eq!(again["keys"].as_array().expect("keys").len(), 1);
    let (_, keys) = h
        .api_send(Method::GET, &format!("/zones/{ZONE}/dnssec/keys"), None)
        .await;
    assert_eq!(keys.as_array().expect("keys").len(), 1);
}

#[tokio::test]
async fn signed_bind_export_has_the_dnssec_records() {
    let h = Harness::start(opts()).await;
    sign(&h, json!({"enabled": true, "denial": "nsec3"})).await;
    let get = |signed: bool| {
        let url = format!(
            "http://{}/api/v1/zones/{ZONE}/export?signed={signed}",
            h.api
        );
        let token = h.api_token.clone();
        async move {
            reqwest::Client::new()
                .get(url)
                .bearer_auth(token)
                .send()
                .await
                .expect("request")
                .text()
                .await
                .expect("body")
        }
    };
    let plain = get(false).await;
    assert!(!plain.contains("RRSIG") && !plain.contains("DNSKEY"));
    let signed = get(true).await;
    for needle in ["DNSKEY", "RRSIG", "NSEC3PARAM", "NSEC3 "] {
        assert!(signed.contains(needle), "signed export lacks {needle}");
    }
    assert!(signed.contains("192.0.2.7"));
    assert!(!signed.contains("PRIVATE"), "never a private key");
}

#[tokio::test]
async fn disabling_signing_goes_back_to_plain_answers() {
    let h = Harness::start(opts()).await;
    sign(&h, json!({"enabled": true})).await;
    put_policy(&h, json!({"enabled": false})).await;
    let r = ask(&h, &dnssec_query("www.example.test.", RecordType::A)).await;
    assert_eq!(types(&r), [RecordType::A]);
}

#[tokio::test]
async fn full_example_zone_signs() {
    let h = Harness::start(Opts::default().zone(ZONE, example_zone())).await;
    sign(&h, json!({"enabled": true, "algorithm": 15})).await;
    let q = dnssec_query("alias.example.test.", RecordType::A);
    let r = ask(&h, &q).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert!(r.answers.iter().any(|x| x.rtype == RecordType::Rrsig));
}
