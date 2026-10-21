//! Key custody: bundle export is refused on a plain-HTTP API listener, a bundle passphrase
//! needs 12 characters, and after a restart without the key passphrase a signed zone is
//! withheld (SERVFAIL, `/readyz` 503) instead of being served unsigned.

use dnsy_e2e::dnssec::dnssec_query;
use dnsy_e2e::harness::binary;
use dnsy_e2e::{DEADLINE, Harness, Opts, eventually, udp_exchange};
use dnsy_proto::{Rcode, RecordType};
use reqwest::Method;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::process::Stdio;
use tokio::process::Command;

const ZONE: &str = "example.test.";

fn opts() -> Opts {
    Opts::default().zone(
        ZONE,
        dnsy_e2e::zones::zone_json(ZONE, &[("www", "A", "192.0.2.7")], true),
    )
}

#[tokio::test]
async fn key_export_is_refused_on_the_plaintext_listener() {
    let h = Harness::start(opts()).await;
    let (status, body) = h
        .api_send(
            Method::POST,
            "/dnssec/keys/export",
            Some(json!({"passphrase": "a-long-enough-passphrase"})),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert!(body["detail"].as_str().unwrap().contains("plain-HTTP"));
    assert!(body.get("bundle").is_none());
}

#[tokio::test]
async fn unopenable_keys_fail_readiness_instead_of_serving_unsigned() {
    let mut h = Harness::start(opts()).await;
    let q = dnssec_query("www.example.test.", RecordType::A);
    let signed = udp_exchange(h.udp, &q).await;
    assert!(signed.answers.iter().any(|r| r.rtype == RecordType::Rrsig));

    // Encrypt the keys under a new passphrase, then restart without telling the server.
    let (status, body) = h
        .api_send(
            Method::POST,
            "/dnssec/passphrase",
            Some(json!({"new_passphrase": "rotated-passphrase-1"})),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let token = h.api_token.clone();
    let config = h.dir.path().join("dnsy.toml");
    h.terminate().await;

    let ready = h.dir.path().join("ready2.json");
    let log = std::fs::File::create(h.dir.path().join("dnsy2.log")).unwrap();
    let mut child = Command::new(binary())
        .arg("--config")
        .arg(&config)
        .args(["serve", "--ready-file"])
        .arg(&ready)
        .env_remove("DNSY_DNSSEC_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .kill_on_drop(true)
        .spawn()
        .expect("spawn dnsy serve");
    let addrs: Value = eventually(DEADLINE * 2, "the restarted server", || {
        let text = std::fs::read_to_string(&ready).ok();
        async move { text.and_then(|t| serde_json::from_str(&t).ok()) }
    })
    .await;
    let addr = |k: &str| -> SocketAddr { addrs[k][0].as_str().unwrap().parse().unwrap() };

    // The zone is not served unsigned: SERVFAIL, never the data without signatures.
    let answer = udp_exchange(addr("udp"), &q).await;
    assert_eq!(answer.header.rcode, Rcode::ServFail);
    assert!(answer.answers.is_empty());

    let http = reqwest::Client::new();
    let res = http
        .get(format!("http://{}/readyz", addr("api")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 503);
    let problem: Value = res.json().await.unwrap();
    assert!(
        problem["detail"]
            .as_str()
            .unwrap()
            .contains("dnssec_signing_failed")
    );
    let log = std::fs::read_to_string(h.dir.path().join("dnsy2.log")).unwrap();
    assert_eq!(log.matches("zone signing failed").count(), 1, "{log}");
    assert!(!log.contains("rotated-passphrase-1"));
    child.kill().await.unwrap();
}
