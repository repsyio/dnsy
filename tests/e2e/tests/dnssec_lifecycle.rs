//! DNSSEC across instances and over time: a second `dnsy` validating the first, key rollovers
//! through the API, the clock-sanity guard and interop with `dig` and `delv`.

use dnsy_core::DnssecStatus;
use dnsy_dnssec::{DigestType, ds_for};
use dnsy_e2e::dnssec::{
    anchors_for, binary_from_the_future, dnssec_query, ds_from_export, ede_codes, first_a,
    logged_build_time, start_validating, upstream, validate_answer,
};
use dnsy_e2e::{Harness, Opts, Tree, ZoneSpec, udp_exchange};
use dnsy_proto::{Message, Name, RData, Rcode, RecordType};
use reqwest::Method;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::process::Command;

const ZONE: &str = "example.test.";

fn zone() -> String {
    dnsy_e2e::zones::zone_json(
        ZONE,
        &[("www", "A", "192.0.2.7"), ("*.wild", "A", "192.0.2.99")],
        false,
    )
}

fn opts() -> Opts {
    Opts::default().zone(ZONE, zone())
}

async fn api(h: &Harness, method: Method, path: &str, body: Option<Value>) -> (u16, Value) {
    h.api_send(method, path, body).await
}

async fn ask(h: &Harness, q: &Message) -> Message {
    udp_exchange(h.udp, q).await
}

/// A signed root zone with one host, as JSON for a zone file.
fn root_zone() -> String {
    r#"{"schema": 1, "origin": ".", "default_ttl": 300,
  "soa": {"mname": "ns1.root.test.", "rname": "hostmaster.root.test.", "serial": 1,
          "refresh": 7200, "retry": 3600, "expire": 1209600, "minimum": 300},
  "records": [{"name": "host.", "type": "A", "value": "203.0.113.30"}],
  "dnssec": {"enabled": true, "denial": "nsec3"}}"#
        .to_owned()
}

/// The root DS of a `dnsy` serving a signed root, as a trust anchor entry.
async fn root_anchor(h: &Harness) -> String {
    let r = ask(h, &dnssec_query(".", RecordType::Dnskey)).await;
    let ksk = r
        .answers
        .iter()
        .find_map(|rec| match &rec.data {
            RData::Dnskey(k) if k.is_sep() => Some(k.clone()),
            _ => None,
        })
        .expect("a SEP key at the root");
    let ds = ds_for(&Name::root(), &ksk, DigestType::Sha256).expect("ds");
    format!(
        "{} {} {} {}",
        ds.key_tag,
        ds.algorithm,
        ds.digest_type,
        dnsy_e2e::hex(&ds.digest).to_uppercase()
    )
}

async fn first_instance() -> (Harness, String) {
    let h1 = Harness::start(Opts {
        same_udp_tcp_port: true,
        ..Opts::default().zone(".", root_zone())
    })
    .await;
    dnsy_e2e::eventually(dnsy_e2e::DEADLINE, "the signed root", || async {
        let r = ask(&h1, &dnssec_query("host.", RecordType::A)).await;
        r.answers
            .iter()
            .any(|x| x.rtype == RecordType::Rrsig)
            .then_some(())
    })
    .await;
    let ta = root_anchor(&h1).await;
    (h1, ta)
}

#[tokio::test]
async fn second_instance_validates_first() {
    let (h1, anchor) = first_instance().await;
    let h2 = Harness::start(Opts {
        validation: "strict",
        trust_anchors: vec![anchor],
        upstream_addr: Some(h1.udp),
        ..Opts::default()
    })
    .await;

    let q = dnssec_query("host.", RecordType::A);
    let r = ask(&h2, &q).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(first_a(&r), "203.0.113.30");
    assert!(
        r.header.ad,
        "the second instance validated the first one's signatures"
    );

    let nx = ask(&h2, &dnssec_query("nothing.", RecordType::A)).await;
    assert_eq!(nx.header.rcode, Rcode::NxDomain);
    assert!(
        nx.header.ad,
        "NSEC3 denial from the first instance validates"
    );

    // A second instance with the wrong anchor refuses the same data.
    let h3 = Harness::start(Opts {
        validation: "strict",
        trust_anchors: vec![format!("1 13 2 {}", "AB".repeat(32))],
        upstream_addr: Some(h1.udp),
        ..Opts::default()
    })
    .await;
    let r = ask(&h3, &q).await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert_ne!(ede_codes(&r), Vec::<u16>::new());
}

// ---------------------------------------------------------------------------------------
// rollover

fn dnskey_count(m: &Message) -> usize {
    m.answers
        .iter()
        .filter(|r| r.rtype == RecordType::Dnskey)
        .count()
}

async fn keys(h: &Harness) -> Vec<Value> {
    let (s, b) = api(h, Method::GET, &format!("/zones/{ZONE}/dnssec/keys"), None).await;
    assert_eq!(s, 200);
    b.as_array()
        .expect("keys")
        .iter()
        .filter(|k| k["state"] != "removed")
        .cloned()
        .collect()
}

async fn export(h: &Harness) -> Value {
    api(h, Method::GET, &format!("/zones/{ZONE}/dnssec/ds"), None)
        .await
        .1
}

/// Every anchor that was ever handed to the registrar must keep validating, and the data too.
async fn assert_valid(h: &Harness, anchors: &[dnsy_proto::Ds], step: &str) {
    for name in [
        "www.example.test.",
        "x.wild.example.test.",
        "gone.example.test.",
    ] {
        let q = dnssec_query(name, RecordType::A);
        let r = ask(h, &q).await;
        let status = validate_answer(h.udp, anchors_for(ZONE, anchors[0].clone()), &q, &r)
            .await
            .status;
        assert_eq!(status, DnssecStatus::Secure, "{name} at {step}");
    }
    let q = dnssec_query(ZONE, RecordType::Dnskey);
    let r = ask(h, &q).await;
    for ds in anchors {
        let s = validate_answer(h.udp, anchors_for(ZONE, ds.clone()), &q, &r)
            .await
            .status;
        assert_eq!(
            s,
            DnssecStatus::Secure,
            "DNSKEY under DS {} at {step}",
            ds.key_tag
        );
    }
}

#[tokio::test]
async fn zsk_rollover_end_to_end_no_bogus_window() {
    let h = Harness::start(opts()).await;
    let (s, _) = api(
        &h,
        Method::PUT,
        &format!("/zones/{ZONE}/dnssec"),
        Some(json!({"enabled": true, "key_layout": "ksk_zsk", "denial": "nsec"})),
    )
    .await;
    assert_eq!(s, 200);
    let ds = ds_from_export(&export(&h).await["ds"][0]);
    assert_valid(&h, std::slice::from_ref(&ds), "before").await;
    let zsk = keys(&h)
        .await
        .into_iter()
        .find(|k| k["role"] == "zsk")
        .expect("a ZSK");

    let (s, incoming) = api(
        &h,
        Method::POST,
        &format!("/zones/{ZONE}/dnssec/keys/{}/rollover", zsk["id"]),
        None,
    )
    .await;
    assert_eq!(s, 202, "{incoming}");
    assert_ne!(incoming["id"], zsk["id"]);

    // The new ZSK is published next to the old one; the DS (KSK) did not change.
    let q = dnssec_query(ZONE, RecordType::Dnskey);
    assert_eq!(dnskey_count(&ask(&h, &q).await), 3, "KSK, old ZSK, new ZSK");
    assert_valid(&h, std::slice::from_ref(&ds), "new ZSK published").await;
    assert_eq!(export(&h).await["ds"][0]["key_tag"], ds.key_tag);

    // A second rollover of the same role while one is under way is a conflict.
    let (s, _) = api(
        &h,
        Method::POST,
        &format!("/zones/{ZONE}/dnssec/keys/{}/rollover", zsk["id"]),
        None,
    )
    .await;
    assert_eq!(s, 409);
}

#[tokio::test]
async fn ksk_rollover_keeps_both_ds_valid() {
    let h = Harness::start(opts()).await;
    api(
        &h,
        Method::PUT,
        &format!("/zones/{ZONE}/dnssec"),
        Some(json!({"enabled": true, "key_layout": "ksk_zsk"})),
    )
    .await;
    let old = ds_from_export(&export(&h).await["ds"][0]);
    let ksk = keys(&h)
        .await
        .into_iter()
        .find(|k| k["role"] == "ksk")
        .expect("a KSK");
    let (s, incoming) = api(
        &h,
        Method::POST,
        &format!("/zones/{ZONE}/dnssec/keys/{}/rollover", ksk["id"]),
        None,
    )
    .await;
    assert_eq!(s, 202, "{incoming}");

    // Waiting for the operator to publish the new DS at the parent.
    let (_, view) = api(&h, Method::GET, &format!("/zones/{ZONE}/dnssec"), None).await;
    assert_eq!(view["rollover"]["state"], "awaiting_ds_confirmation");
    let exported = export(&h).await;
    let all: Vec<_> = exported["ds"]
        .as_array()
        .expect("ds")
        .iter()
        .filter(|d| d["digest_type"] == 2)
        .map(ds_from_export)
        .collect();
    assert_eq!(all.len(), 2, "old and new KSK are both exported");
    // Both DS records validate the DNSKEY RRset (it is signed by both KSKs).
    assert_valid(&h, &all, "KSK published, DS not confirmed").await;
    assert!(all.contains(&old));

    let (s, _) = api(
        &h,
        Method::POST,
        &format!("/zones/{ZONE}/dnssec/keys/{}/ds-confirmed", incoming["id"]),
        None,
    )
    .await;
    assert_eq!(s, 204);
    assert_valid(&h, &all, "DS confirmed").await;
}

// ---------------------------------------------------------------------------------------
// clock sanity

#[tokio::test]
async fn clock_skew_indeterminate() {
    let tree = Arc::new(Tree::build(vec![
        ZoneSpec::new("test.").a("host", "203.0.113.10"),
    ]));
    let normal = start_validating(&tree, "strict").await;
    let q = dnssec_query("host.test.", RecordType::A);
    assert!(ask(&normal, &q).await.header.ad);
    let (_, st) = api(&normal, Method::GET, "/dnssec/status", None).await;
    assert_eq!(st["clock_trusted"], true);

    let dir = tempfile::tempdir().expect("temp dir");
    let patched = binary_from_the_future(dir.path(), &logged_build_time(&normal));
    let upstream_ = dnsy_e2e::FakeUpstream::start().await;
    tree.serve(&upstream_);
    let h = Harness::start_with(
        Opts {
            validation: "strict",
            trust_anchors: vec![tree.trust_anchor.clone()],
            binary: Some(patched),
            ..Opts::default()
        },
        Some(upstream_),
    )
    .await;
    let r = ask(&h, &q).await;
    // The clock cannot be trusted: nothing is validated, so nothing is Bogus either and the
    // answer is served without AD.
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(first_a(&r), "203.0.113.10");
    assert!(!r.header.ad);
    h.wait_for_log("system clock is earlier than the build time")
        .await;
    let (_, st) = api(&h, Method::GET, "/dnssec/status", None).await;
    assert_eq!(st["clock_trusted"], false);
    dnsy_e2e::eventually(dnsy_e2e::DEADLINE, "the indeterminate counter", || async {
        let (_, st) = api(&h, Method::GET, "/dnssec/status", None).await;
        (st["counters"]["indeterminate"].as_u64().unwrap_or(0) >= 1).then_some(())
    })
    .await;
}

#[tokio::test]
async fn status_counts_secure_and_bogus_answers() {
    let tree = Arc::new(Tree::build(vec![
        ZoneSpec::new("test.").a("host", "203.0.113.10"),
    ]));
    let h = start_validating(&tree, "strict").await;
    let mut forged = tree.rrset("host.test.", RecordType::A);
    if let RData::A(a) = &mut forged[0].data {
        *a = "203.0.113.66".parse().expect("ip");
    }
    upstream(&h).on("bad.test.", RecordType::A, dnsy_e2e::Reply::Answer(forged));
    assert!(
        ask(&h, &dnssec_query("host.test.", RecordType::A))
            .await
            .header
            .ad
    );
    assert_eq!(
        ask(&h, &dnssec_query("bad.test.", RecordType::A))
            .await
            .header
            .rcode,
        Rcode::ServFail
    );
    let counters = dnsy_e2e::eventually(dnsy_e2e::DEADLINE, "status counters", || async {
        let (_, st) = api(&h, Method::GET, "/dnssec/status", None).await;
        (st["secure"].as_u64() >= Some(1) && st["bogus"].as_u64() >= Some(1)).then_some(st)
    })
    .await;
    assert_eq!(counters["validation"], "strict");
    assert_eq!(counters["clock_trusted"], true);
}

// ---------------------------------------------------------------------------------------
// interop

async fn have(tool: &str, flag: &str) -> bool {
    Command::new(tool)
        .arg(flag)
        .output()
        .await
        .is_ok_and(|o| o.status.success())
}

#[tokio::test]
async fn delv_and_dig_dnssec_agree() {
    if !have("delv", "-v").await || !have("dig", "-v").await {
        eprintln!("skipped: delv or dig is not installed");
        return;
    }
    let (h1, anchor) = first_instance().await;
    let h2 = Harness::start(Opts {
        validation: "strict",
        trust_anchors: vec![anchor.clone()],
        upstream_addr: Some(h1.udp),
        same_udp_tcp_port: true,
        ..Opts::default()
    })
    .await;
    let parts: Vec<&str> = anchor.split(' ').collect();
    let dir = tempfile::tempdir().expect("temp dir");
    let anchors = dir.path().join("anchors.conf");
    std::fs::write(
        &anchors,
        format!(
            "trust-anchors {{ . static-ds {} {} {} \"{}\"; }};\n",
            parts[0], parts[1], parts[2], parts[3]
        ),
    )
    .expect("anchor file");

    for (name, h) in [("first", &h1), ("second", &h2)] {
        let port = h.udp.port().to_string();
        let delv = Command::new("delv")
            .args(["@127.0.0.1", "-p", &port, "-a"])
            .arg(&anchors)
            .args(["host.", "A", "+tcp"])
            .output()
            .await
            .expect("run delv");
        let out = String::from_utf8_lossy(&delv.stdout).into_owned()
            + &String::from_utf8_lossy(&delv.stderr);
        assert!(
            out.contains("; fully validated"),
            "delv against the {name} instance: {out}"
        );
        assert!(out.contains("203.0.113.30"));

        let dig = Command::new("dig")
            .args([
                "@127.0.0.1",
                "-p",
                &port,
                "host.",
                "A",
                "+dnssec",
                "+time=5",
                "+tries=1",
            ])
            .output()
            .await
            .expect("run dig");
        let out = String::from_utf8_lossy(&dig.stdout).into_owned();
        assert!(out.contains("RRSIG"), "dig +dnssec shows signatures: {out}");
        let ad = out.contains("flags: qr")
            && out
                .lines()
                .any(|l| l.contains("flags:") && l.contains(" ad"));
        assert_eq!(
            ad,
            name == "second",
            "AD only from the validating instance: {out}"
        );
    }
}

/// Needs the internet: validates a signed name against the built-in root anchors through a public
/// resolver. Run with `cargo nextest run -p dnsy-e2e --run-ignored only live_root`.
#[tokio::test]
#[ignore = "needs network access to a public resolver"]
async fn live_root_validates_a_signed_name() {
    let h = Harness::start(Opts {
        validation: "strict",
        resolver_timeout_ms: 5000,
        upstream_addr: Some("1.1.1.1:53".parse().expect("addr")),
        ..Opts::default()
    })
    .await;
    let q = dnssec_query("cloudflare.com.", RecordType::A);
    let r = ask(&h, &q).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert!(
        r.header.ad,
        "cloudflare.com is signed and chains to the root KSK"
    );
}
