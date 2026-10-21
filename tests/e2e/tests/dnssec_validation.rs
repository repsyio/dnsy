//! DNSSEC validation through the forwarding path: a fake upstream serves a signed tree
//! (`. -> test. -> example.test.`) and the server validates against the root anchor.

use std::sync::Arc;

use dnsy_e2e::dnssec::{
    checking_disabled, dnssec_query, ede_codes, first_a, start_validating, upstream,
};
use dnsy_e2e::{DsMode, Harness, Reply, Tree, ZoneSpec, query, udp_exchange};
use dnsy_proto::{Message, RData, Rcode, RecordType};
use reqwest::Method;
use serde_json::json;

const WWW: &str = "www.example.test.";

fn test_zone() -> ZoneSpec {
    ZoneSpec::new("test.").a("host", "203.0.113.10")
}

fn example() -> ZoneSpec {
    ZoneSpec::new("example.test.")
        .a("www", "192.0.2.1")
        .a("fake", "192.0.2.2")
        .a("*.wild", "192.0.2.99")
}

fn tree() -> Arc<Tree> {
    Arc::new(Tree::build(vec![test_zone(), example()]))
}

async fn ask(h: &Harness, q: &Message) -> Message {
    udp_exchange(h.udp, q).await
}

/// The signed A answer for `name` with its address replaced (the RRSIG no longer matches).
fn forge_a(tree: &Tree, name: &str, ip: &str) -> Reply {
    let mut records = tree.rrset(name, RecordType::A);
    for r in &mut records {
        if let RData::A(a) = &mut r.data {
            *a = ip.parse().expect("ip");
        }
    }
    Reply::Answer(records)
}

#[tokio::test]
async fn validated_answer_has_ad_only_for_clients_that_ask() {
    let h = start_validating(&tree(), "strict").await;

    let with_do = ask(&h, &dnssec_query(WWW, RecordType::A)).await;
    assert_eq!(with_do.header.rcode, Rcode::NoError);
    assert!(with_do.header.ad, "DO=1 and validated: AD");
    assert_eq!(first_a(&with_do), "192.0.2.1");
    assert!(
        with_do.answers.iter().any(|r| r.rtype == RecordType::Rrsig),
        "DO=1 keeps the RRSIGs"
    );

    // No DO and no AD: validated, but the client did not ask, so no AD and no DNSSEC records.
    let plain = ask(&h, &query(WWW, RecordType::A)).await;
    assert_eq!(plain.header.rcode, Rcode::NoError);
    assert!(!plain.header.ad);
    assert!(plain.answers.iter().all(|r| r.rtype == RecordType::A));

    // RFC 6840 5.7: AD in the query is a request for AD without DO.
    let mut ad_query = query(WWW, RecordType::A);
    ad_query.header.ad = true;
    assert!(ask(&h, &ad_query).await.header.ad);

    // CD=1 turns validation off for this client: never AD.
    let cd = ask(&h, &checking_disabled(dnssec_query(WWW, RecordType::A))).await;
    assert_eq!(cd.header.rcode, Rcode::NoError);
    assert!(!cd.header.ad);
}

#[tokio::test]
async fn wildcard_answer_from_the_upstream_validates() {
    let h = start_validating(&tree(), "strict").await;
    let r = ask(&h, &dnssec_query("any.wild.example.test.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert!(r.header.ad);
    assert_eq!(first_a(&r), "192.0.2.99");
}

#[tokio::test]
async fn nsec_nxdomain_and_nodata_validate() {
    let h = start_validating(&tree(), "strict").await;
    let nx = ask(&h, &dnssec_query("nope.example.test.", RecordType::A)).await;
    assert_eq!(nx.header.rcode, Rcode::NxDomain);
    assert!(nx.header.ad, "a proven NXDOMAIN is secure");
    let nodata = ask(&h, &dnssec_query(WWW, RecordType::Aaaa)).await;
    assert_eq!(nodata.header.rcode, Rcode::NoError);
    assert!(nodata.answers.is_empty());
    assert!(nodata.header.ad, "a proven NODATA is secure");
}

#[tokio::test]
async fn nsec3_nxdomain_and_nodata_validate() {
    let tree = Arc::new(Tree::build(vec![test_zone(), example().nsec3(false)]));
    let h = start_validating(&tree, "strict").await;
    let nx = ask(&h, &dnssec_query("nope.example.test.", RecordType::A)).await;
    assert_eq!(nx.header.rcode, Rcode::NxDomain);
    assert!(nx.header.ad);
    let nodata = ask(&h, &dnssec_query(WWW, RecordType::Aaaa)).await;
    assert_eq!(nodata.header.rcode, Rcode::NoError);
    assert!(nodata.header.ad);
    let wild = ask(&h, &dnssec_query("x.wild.example.test.", RecordType::A)).await;
    assert!(wild.header.ad, "wildcard expansion proven with NSEC3");
}

// ---------------------------------------------------------------------------------------
// insecure

#[tokio::test]
async fn unsigned_delegation_is_insecure_not_bogus() {
    let tree = Arc::new(Tree::build(vec![
        test_zone(),
        ZoneSpec::new("plain.test.")
            .unsigned()
            .a("www", "198.51.100.5"),
    ]));
    let h = start_validating(&tree, "strict").await;
    let r = ask(&h, &dnssec_query("www.plain.test.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(first_a(&r), "198.51.100.5");
    assert!(!r.header.ad, "insecure data never carries AD");
}

#[tokio::test]
async fn missing_ds_parent_insecure_not_bogus() {
    let tree = Arc::new(Tree::build(vec![
        test_zone(),
        example().ds(DsMode::Missing),
    ]));
    let h = start_validating(&tree, "strict").await;
    let r = ask(&h, &dnssec_query(WWW, RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::NoError, "the island is not an error");
    assert_eq!(first_a(&r), "192.0.2.1");
    assert!(!r.header.ad);
}

#[tokio::test]
async fn nsec3_opt_out_unsigned_delegation_insecure() {
    let tree = Arc::new(Tree::build(vec![
        ZoneSpec::new("test.").a("host", "203.0.113.10").nsec3(true),
        ZoneSpec::new("plain.test.")
            .unsigned()
            .a("www", "198.51.100.5"),
        example(),
    ]));
    let h = start_validating(&tree, "strict").await;
    let r = ask(&h, &dnssec_query("www.plain.test.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert!(!r.header.ad);
    // The signed sibling below the same opt-out zone still validates.
    let secure = ask(&h, &dnssec_query(WWW, RecordType::A)).await;
    assert!(secure.header.ad);
}

#[tokio::test]
async fn unsupported_algorithm_insecure() {
    let tree = Arc::new(Tree::build(vec![
        test_zone(),
        example().ds(DsMode::UnsupportedAlgorithm(200)),
    ]));
    let h = start_validating(&tree, "strict").await;
    let r = ask(&h, &dnssec_query(WWW, RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(first_a(&r), "192.0.2.1");
    assert!(!r.header.ad);
}

// ---------------------------------------------------------------------------------------
// bogus, by mode

#[tokio::test]
async fn bogus_signature_servfail_strict() {
    let tree = tree();
    let h = start_validating(&tree, "strict").await;
    upstream(&h).on(
        "fake.example.test.",
        RecordType::A,
        forge_a(&tree, "fake.example.test.", "203.0.113.66"),
    );
    let r = ask(&h, &dnssec_query("fake.example.test.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert!(r.answers.is_empty());
    assert!(!r.header.ad);
    assert_eq!(ede_codes(&r), [6], "DNSSEC Bogus");
    // The same without DO: still SERVFAIL, the server validates for every client.
    let plain = ask(&h, &query("fake.example.test.", RecordType::A)).await;
    assert_eq!(plain.header.rcode, Rcode::ServFail);
    // The good sibling is unaffected.
    assert!(ask(&h, &dnssec_query(WWW, RecordType::A)).await.header.ad);
}

#[tokio::test]
async fn bogus_signature_answered_permissive_no_ad() {
    let tree = tree();
    let h = start_validating(&tree, "permissive").await;
    upstream(&h).on(
        "fake.example.test.",
        RecordType::A,
        forge_a(&tree, "fake.example.test.", "203.0.113.66"),
    );
    let r = ask(&h, &dnssec_query("fake.example.test.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(first_a(&r), "203.0.113.66", "permissive passes the data on");
    assert!(!r.header.ad);
    assert_eq!(ede_codes(&r), [6], "and says why it is not secure");
    h.wait_for_log("DNSSEC bogus answer served without AD")
        .await;
}

#[tokio::test]
async fn bogus_signature_passes_with_validation_off() {
    let tree = tree();
    let h = start_validating(&tree, "off").await;
    upstream(&h).on(
        "fake.example.test.",
        RecordType::A,
        forge_a(&tree, "fake.example.test.", "203.0.113.66"),
    );
    let r = ask(&h, &dnssec_query("fake.example.test.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(first_a(&r), "203.0.113.66");
    assert!(!r.header.ad);
    assert!(ede_codes(&r).is_empty());
    // Even the good data gets no AD: the server did not check it.
    assert!(!ask(&h, &dnssec_query(WWW, RecordType::A)).await.header.ad);
}

#[tokio::test]
async fn expired_rrsig_ede7() {
    let tree = Arc::new(Tree::build(vec![
        test_zone(),
        example().signed_offset(-40 * 86_400),
    ]));
    let h = start_validating(&tree, "strict").await;
    let r = ask(&h, &dnssec_query(WWW, RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), [7], "Signature Expired");
}

#[tokio::test]
async fn not_yet_valid_rrsig_ede8() {
    let tree = Arc::new(Tree::build(vec![
        test_zone(),
        example().signed_offset(30 * 86_400),
    ]));
    let h = start_validating(&tree, "strict").await;
    let r = ask(&h, &dnssec_query(WWW, RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), [8], "Signature Not Yet Valid");
}

#[tokio::test]
async fn ds_without_dnskey_bogus_ede9() {
    for mode in [DsMode::WrongDigest, DsMode::UnknownKeyTag] {
        let tree = Arc::new(Tree::build(vec![test_zone(), example().ds(mode)]));
        let h = start_validating(&tree, "strict").await;
        let r = ask(&h, &dnssec_query(WWW, RecordType::A)).await;
        assert_eq!(r.header.rcode, Rcode::ServFail, "{mode:?}");
        assert_eq!(ede_codes(&r), [9], "DNSKEY Missing for {mode:?}");
    }
}

#[tokio::test]
async fn upstream_strips_rrsigs_strict_servfail_ede10() {
    let tree = tree();
    let h = start_validating(&tree, "strict").await;
    let stripped = tree
        .rrset("fake.example.test.", RecordType::A)
        .into_iter()
        .filter(|r| r.rtype != RecordType::Rrsig)
        .collect();
    upstream(&h).on("fake.example.test.", RecordType::A, Reply::Answer(stripped));
    let r = ask(&h, &dnssec_query("fake.example.test.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), [10], "RRSIGs Missing");
}

#[tokio::test]
async fn rrsig_with_a_different_algorithm_is_bogus() {
    let tree = tree();
    let h = start_validating(&tree, "strict").await;
    let mut a = tree.answer("fake.example.test.", RecordType::A);
    a = a.map_rrsigs(|s| s.algorithm = 15);
    upstream(&h).on("fake.example.test.", RecordType::A, a.reply());
    let r = ask(&h, &dnssec_query("fake.example.test.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), [9]);
}

#[tokio::test]
async fn forged_denial_is_bogus() {
    for nsec3 in [false, true] {
        let spec = if nsec3 {
            example().nsec3(false)
        } else {
            example()
        };
        let tree = Arc::new(Tree::build(vec![test_zone(), spec]));
        let h = start_validating(&tree, "strict").await;

        // NXDOMAIN with the proof removed.
        let name = "ghost.example.test.";
        let mut nx = tree.answer(name, RecordType::A);
        assert_eq!(nx.rcode, Rcode::NxDomain);
        nx.authority
            .retain(|r| !matches!(r.rtype, RecordType::Nsec | RecordType::Nsec3));
        upstream(&h).on(name, RecordType::A, nx.reply());
        let r = ask(&h, &dnssec_query(name, RecordType::A)).await;
        assert_eq!(
            r.header.rcode,
            Rcode::ServFail,
            "stripped proof, nsec3={nsec3}"
        );

        // An existing name denied with a proof that does not cover it.
        let victim = "www.example.test.";
        let mut denied = tree.answer("ghost.example.test.", RecordType::A);
        denied.rcode = Rcode::NxDomain;
        upstream(&h).on(victim, RecordType::A, denied.reply());
        let r = ask(&h, &dnssec_query(victim, RecordType::A)).await;
        assert_eq!(
            r.header.rcode,
            Rcode::ServFail,
            "false NXDOMAIN, nsec3={nsec3}"
        );

        // A genuine proof with a corrupted signature.
        let name = "ghost2.example.test.";
        let forged = tree
            .answer(name, RecordType::A)
            .map_rrsigs(|s| s.signature[0] ^= 0xff);
        upstream(&h).on(name, RecordType::A, forged.reply());
        let r = ask(&h, &dnssec_query(name, RecordType::A)).await;
        assert_eq!(
            r.header.rcode,
            Rcode::ServFail,
            "bad proof signature, nsec3={nsec3}"
        );
    }
}

#[tokio::test]
async fn keytrap_many_colliding_keys_exhaust_the_budget() {
    let tree = Arc::new(Tree::build(vec![test_zone(), example().colliding_keys(12)]));
    let h = start_validating(&tree, "strict").await;
    let r = ask(&h, &dnssec_query(WWW, RecordType::A)).await;
    assert_eq!(
        r.header.rcode,
        Rcode::ServFail,
        "the budget ends the validation"
    );
    assert_eq!(ede_codes(&r), [6]);
    h.wait_for_log("validation work limit exceeded").await;
}

// ---------------------------------------------------------------------------------------
// CD, cache and runtime control

#[tokio::test]
async fn cd_bit_returns_bogus_data() {
    let tree = tree();
    let h = start_validating(&tree, "strict").await;
    upstream(&h).on(
        "fake.example.test.",
        RecordType::A,
        forge_a(&tree, "fake.example.test.", "203.0.113.66"),
    );
    let q = dnssec_query("fake.example.test.", RecordType::A);
    let cd = ask(&h, &checking_disabled(q.clone())).await;
    assert_eq!(cd.header.rcode, Rcode::NoError);
    assert_eq!(
        first_a(&cd),
        "203.0.113.66",
        "CD=1 gets the data as received"
    );
    assert!(!cd.header.ad);
    // The CD=1 answer is cached apart; a validating client still gets SERVFAIL.
    let after = ask(&h, &q).await;
    assert_eq!(after.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&after), [6]);
    let again_cd = ask(&h, &checking_disabled(q)).await;
    assert_eq!(first_a(&again_cd), "203.0.113.66");
}

#[tokio::test]
async fn cache_never_serves_bogus_to_a_validating_client() {
    let tree = tree();
    let h = start_validating(&tree, "strict").await;
    upstream(&h).on(
        "fake.example.test.",
        RecordType::A,
        forge_a(&tree, "fake.example.test.", "203.0.113.66"),
    );
    let q = dnssec_query("fake.example.test.", RecordType::A);
    for _ in 0..3 {
        let r = ask(&h, &q).await;
        assert_eq!(r.header.rcode, Rcode::ServFail);
        assert!(r.answers.is_empty());
        assert_eq!(ede_codes(&r), [6], "a cached bogus verdict keeps its EDE");
    }
    // Whatever the cache holds, the upstream saw the name once.
    assert_eq!(upstream(&h).count("fake.example.test.", RecordType::A), 1);
}

#[tokio::test]
async fn changing_the_mode_through_the_api_flushes_the_cache() {
    let tree = tree();
    let h = start_validating(&tree, "permissive").await;
    upstream(&h).on(
        "fake.example.test.",
        RecordType::A,
        forge_a(&tree, "fake.example.test.", "203.0.113.66"),
    );
    let q = dnssec_query("fake.example.test.", RecordType::A);
    let r = ask(&h, &q).await;
    assert_eq!(first_a(&r), "203.0.113.66");
    assert!(!r.header.ad);

    let (status, body) = h
        .api_send(
            Method::PATCH,
            "/settings/dnssec",
            Some(json!({"validation": "strict"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["validation"], "strict");
    // The permissive cache entry is gone: strict asks again and refuses.
    let r = ask(&h, &q).await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_eq!(ede_codes(&r), [6]);
    assert_eq!(upstream(&h).count("fake.example.test.", RecordType::A), 2);

    let (status, _) = h
        .api_send(
            Method::PATCH,
            "/settings/dnssec",
            Some(json!({"validation": "off"})),
        )
        .await;
    assert_eq!(status, 200);
    let r = ask(&h, &q).await;
    assert_eq!(first_a(&r), "203.0.113.66");
    assert!(ede_codes(&r).is_empty());
}

#[tokio::test]
async fn negative_trust_anchor_through_the_api() {
    let tree = tree();
    let h = start_validating(&tree, "strict").await;
    upstream(&h).on(
        "fake.example.test.",
        RecordType::A,
        forge_a(&tree, "fake.example.test.", "203.0.113.66"),
    );
    let q = dnssec_query("fake.example.test.", RecordType::A);
    assert_eq!(ask(&h, &q).await.header.rcode, Rcode::ServFail);

    let (status, body) = h
        .api_send(
            Method::PATCH,
            "/settings/dnssec",
            Some(json!({"negative_trust_anchors": ["example.test"]})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["negative_trust_anchors"], json!(["example.test."]));
    let r = ask(&h, &q).await;
    assert_eq!(
        r.header.rcode,
        Rcode::NoError,
        "below an NTA nothing is checked"
    );
    assert_eq!(first_a(&r), "203.0.113.66");
    assert!(!r.header.ad);
    // Siblings outside the NTA are still validated.
    assert!(
        ask(&h, &dnssec_query("host.test.", RecordType::A))
            .await
            .header
            .ad
    );

    let (status, _) = h
        .api_send(
            Method::PATCH,
            "/settings/dnssec",
            Some(json!({"negative_trust_anchors": []})),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(ask(&h, &q).await.header.rcode, Rcode::ServFail);
}
