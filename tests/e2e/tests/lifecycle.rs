//! Signals and process lifecycle: SIGHUP reload, graceful SIGTERM, no leaked processes.

use std::path::Path;
use std::time::Duration;

use dnsy_e2e::clients::Framed;
use dnsy_e2e::upstream::a;
use dnsy_e2e::zones::{example_zone, zone_json};
use dnsy_e2e::{Harness, MtlsPolicy, Opts, Reply, eventually, query, udp_exchange, udp_raw};
use dnsy_proto::{Message, Rcode, RecordType};
use reqwest::Method;
use serde_json::json;

fn opts() -> Opts {
    Opts::default().zone("example.test.", example_zone())
}

fn www() -> Message {
    query("www.example.test.", RecordType::A)
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[tokio::test]
async fn sighup_reloads_zones_and_keeps_serving_on_bad_files() {
    let h = Harness::start(opts()).await;
    let seen = h.logs().matches("zones reloaded").count();
    h.write_zone(
        "example.test.",
        &zone_json("example.test.", &[("www", "A", "192.0.2.77")], false),
    );
    h.signal("HUP");
    h.wait_for_log_count("zones reloaded", seen).await;
    eventually(Duration::from_secs(20), "new zone data", || async {
        let r = udp_exchange(h.udp, &www()).await;
        (r.answers
            .first()
            .map(|a| format!("{:?}", a.data))
            .is_some_and(|d| d.contains("192.0.2.77")))
        .then_some(())
    })
    .await;

    // A broken file: the previous zone keeps answering and the process stays up.
    h.write_zone("example.test.", "[]");
    h.signal("HUP");
    h.wait_for_log("zone file rejected").await;
    let r = udp_exchange(h.udp, &www()).await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert!(format!("{:?}", r.answers[0].data).contains("192.0.2.77"));
}

#[tokio::test]
async fn sighup_reloads_the_client_ca_bundle() {
    let h = Harness::start(Opts {
        dot: Some(MtlsPolicy::Required),
        ..opts()
    })
    .await;
    let dot = h.dot.unwrap();
    let mallory = &h.pki.untrusted_client;
    // Allowlisted but signed by a CA the server does not trust yet.
    let (status, _) = h
        .api_send(
            Method::POST,
            "/client-certs",
            Some(json!({"sha256": mallory.fingerprint(), "label": "mallory"})),
        )
        .await;
    assert_eq!(status, 201);
    let try_dot = |id: &dnsy_e2e::ClientIdentity| {
        let id = id.clone();
        let pki = &h.pki;
        async move {
            let mut c = Framed::connect_dot(dot, pki, Some(&id)).await.ok()?;
            c.ask(&www()).await.ok()
        }
    };
    assert!(try_dot(mallory).await.is_none());

    let bundle = format!("{}\n{}", h.pki.client_ca_pem, h.pki.untrusted_ca_pem);
    std::fs::write(h.dir.path().join("client-ca.pem"), bundle).unwrap();
    h.signal("HUP");
    h.wait_for_log("client CA bundle reloaded").await;
    let r = eventually(
        Duration::from_secs(20),
        "the reloaded CA to be trusted",
        || try_dot(mallory),
    )
    .await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    // The original client still works.
    assert!(try_dot(&h.pki.valid_client).await.is_some());
}

#[tokio::test]
async fn sigterm_shuts_down_gracefully() {
    let mut h = Harness::start(opts()).await;
    let pid = h.pid();
    let (udp, tcp) = (h.udp, h.tcp);
    let mut open = h.tcp_client().await;
    assert_eq!(open.ask(&www()).await.unwrap().header.rcode, Rcode::NoError);

    let started = std::time::Instant::now();
    let status = h.terminate().await;
    assert!(status.success(), "exit status after SIGTERM: {status:?}");
    // The query log's final flush used to wait out its 10 s timeout because the API router
    // still held the engine; an idle server must stop promptly.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "shutdown took {:?}",
        started.elapsed()
    );
    assert!(!h.logs().contains("flush timed out"));
    let logs = h.logs();
    assert!(
        logs.contains("shutting down") && logs.contains("stopped"),
        "{logs}"
    );
    assert!(!alive(pid), "the process is gone");
    // Nothing listens any more.
    assert!(tokio::net::TcpStream::connect(tcp).await.is_err());
    assert!(
        udp_raw(
            udp,
            &dnsy_e2e::clients::wire(&www()),
            Duration::from_millis(300)
        )
        .await
        .is_none()
    );
    assert!(
        open.ask(&www()).await.is_err(),
        "the idle connection was closed"
    );
}

#[tokio::test]
async fn sigterm_lets_an_in_flight_query_finish() {
    let mut h = Harness::start(Opts {
        upstream: true,
        resolver_timeout_ms: 5000,
        ..Opts::default()
    })
    .await;
    h.upstream.as_ref().unwrap().on(
        "slow.test.",
        RecordType::A,
        Reply::Delay(
            Duration::from_millis(800),
            Box::new(Reply::Answer(vec![a("slow.test.", 60, "203.0.113.3")])),
        ),
    );
    let mut c = h.tcp_client().await;
    c.send(&query("slow.test.", RecordType::A)).await.unwrap();
    // Wait until the upstream has the query, so it is in flight when the signal arrives.
    eventually(
        Duration::from_secs(10),
        "query to reach the upstream",
        || {
            let n = h
                .upstream
                .as_ref()
                .unwrap()
                .count("slow.test.", RecordType::A);
            async move { (n > 0).then_some(()) }
        },
    )
    .await;
    let waiter = tokio::spawn(async move { c.recv().await });
    let status = h.terminate().await;
    assert!(status.success(), "{status:?}");
    let reply = waiter
        .await
        .unwrap()
        .expect("the in-flight query is answered before exit");
    assert_eq!(reply.header.rcode, Rcode::NoError);
}

#[tokio::test]
async fn sigint_also_stops_cleanly() {
    let mut h = Harness::start(opts()).await;
    h.signal("INT");
    eventually(Duration::from_secs(30), "the process to exit", || {
        let running = h.is_running();
        async move { (!running).then_some(()) }
    })
    .await;
    assert!(h.logs().contains("stopped"));
}
