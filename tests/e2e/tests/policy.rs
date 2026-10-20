//! Client ACL, rate limiting and blocklists, seen from DNS clients.

use std::time::Duration;

use dnsy_e2e::clients::{Framed, query_edns, wire};
use dnsy_e2e::zones::example_zone;
use dnsy_e2e::{Harness, MtlsPolicy, Opts, eventually, query, udp_exchange, udp_silent};
use dnsy_proto::{EdnsOption, Message, RData, Rcode, RecordType, ede};
use reqwest::Method;
use serde_json::json;
use tokio::net::UdpSocket;

fn opts() -> Opts {
    Opts::default().zone("example.test.", example_zone())
}

fn www() -> Message {
    query("www.example.test.", RecordType::A)
}

fn ede_codes(m: &Message) -> Vec<u16> {
    m.edns
        .iter()
        .flat_map(|e| &e.options)
        .filter_map(|o| match o {
            EdnsOption::ExtendedError { code, .. } => Some(*code),
            _ => None,
        })
        .collect()
}

async fn add_acl(h: &Harness, cidr: &str, action: &str) -> i64 {
    let (status, body) = h
        .api_send(
            Method::POST,
            "/acl",
            Some(json!({"cidr": cidr, "action": action})),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    body["id"].as_i64().unwrap()
}

// ---- ACL ----

#[tokio::test]
async fn acl_refused() {
    let h = Harness::start(opts()).await;
    let id = add_acl(&h, "127.0.0.0/8", "refuse").await;
    assert_eq!(
        udp_exchange(h.udp, &www()).await.header.rcode,
        Rcode::Refused
    );
    let mut tcp = h.tcp_client().await;
    assert_eq!(tcp.ask(&www()).await.unwrap().header.rcode, Rcode::Refused);

    let (status, _) = h
        .api_send(Method::DELETE, &format!("/acl/{id}"), None)
        .await;
    assert_eq!(status, 204);
    assert_eq!(
        udp_exchange(h.udp, &www()).await.header.rcode,
        Rcode::NoError
    );
}

#[tokio::test]
async fn acl_drop_sends_nothing() {
    let h = Harness::start(opts()).await;
    add_acl(&h, "127.0.0.1/32", "drop").await;
    assert!(
        udp_silent(h.udp, &www()).await,
        "a dropped client gets no UDP reply"
    );
    // TCP: the connection must not yield an answer.
    let mut tcp = h.tcp_client().await;
    let _ = tcp.send(&www()).await;
    let answered = tokio::time::timeout(Duration::from_millis(700), tcp.recv()).await;
    assert!(
        !matches!(answered, Ok(Ok(_))),
        "no TCP answer for a dropped client"
    );
}

#[tokio::test]
async fn acl_longest_prefix_wins() {
    let h = Harness::start(opts()).await;
    add_acl(&h, "127.0.0.0/8", "refuse").await;
    add_acl(&h, "127.0.0.1/32", "allow").await;
    assert_eq!(
        udp_exchange(h.udp, &www()).await.header.rcode,
        Rcode::NoError
    );
    // The same network twice is a conflict (so there are no ties to break).
    let (status, _) = h
        .api_send(
            Method::POST,
            "/acl",
            Some(json!({"cidr": "127.0.0.1", "action": "refuse"})),
        )
        .await;
    assert_eq!(status, 409);
}

#[tokio::test]
async fn acl_rule_by_client_certificate() {
    let h = Harness::start(Opts {
        dot: Some(MtlsPolicy::Optional),
        ..opts()
    })
    .await;
    let (status, body) = h
        .api_send(
            Method::POST,
            "/acl",
            Some(
                json!({"client_cert_sha256": h.pki.valid_client.fingerprint(), "action": "refuse"}),
            ),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let mut with_cert = Framed::connect_dot(h.dot.unwrap(), &h.pki, Some(&h.pki.valid_client))
        .await
        .unwrap();
    assert_eq!(
        with_cert.ask(&www()).await.unwrap().header.rcode,
        Rcode::Refused
    );
    let mut anonymous = Framed::connect_dot(h.dot.unwrap(), &h.pki, None)
        .await
        .unwrap();
    assert_eq!(
        anonymous.ask(&www()).await.unwrap().header.rcode,
        Rcode::NoError
    );
}

// ---- rate limiting ----

#[tokio::test]
async fn rate_limited_udp_dropped() {
    let h = Harness::start(Opts {
        per_client_qps: 1,
        ..opts()
    })
    .await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..30 {
        socket.send_to(&wire(&www()), h.udp).await.unwrap();
    }
    let mut answered = 0;
    let mut buf = vec![0u8; 4096];
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_millis(600), socket.recv_from(&mut buf)).await
    {
        answered += 1;
    }
    assert!(
        answered >= 1,
        "the burst allowance answers the first queries"
    );
    assert!(
        answered < 10,
        "most of 30 instant queries are dropped, got {answered} replies"
    );

    // TCP over the limit is REFUSED rather than dropped.
    let mut tcp = h.tcp_client().await;
    let mut refused = false;
    for _ in 0..20 {
        if tcp.ask(&www()).await.unwrap().header.rcode == Rcode::Refused {
            refused = true;
            break;
        }
    }
    assert!(refused, "TCP queries over the limit get REFUSED");
}

#[tokio::test]
async fn rate_limit_can_be_lifted_at_runtime() {
    let h = Harness::start(Opts {
        per_client_qps: 1,
        ..opts()
    })
    .await;
    let (status, _) = h
        .api_send(Method::PUT, "/acl/rate-limit", Some(json!({"qps": 0})))
        .await;
    assert_eq!(status, 200);
    for _ in 0..30 {
        assert_eq!(
            udp_exchange(h.udp, &www()).await.header.rcode,
            Rcode::NoError
        );
    }
}

// ---- blocklists ----

fn blocking(mode: &'static str) -> Opts {
    Opts {
        blocked: vec![
            "ads.example.net".into(),
            "0.0.0.0 tracker.example.net".into(),
        ],
        block_mode: mode,
        ..opts()
    }
}

#[tokio::test]
async fn blocked_domain_nxdomain_ede() {
    let h = Harness::start(blocking("nxdomain")).await;
    let r = udp_exchange(h.udp, &query_edns("ads.example.net.", RecordType::A, 1232)).await;
    assert_eq!(r.header.rcode, Rcode::NxDomain);
    assert_eq!(ede_codes(&r), [ede::BLOCKED]);
    // Subdomains and the hosts-file entry are blocked too, and without EDNS there is no EDE.
    let sub = udp_exchange(h.udp, &query("deep.sub.ads.example.net.", RecordType::A)).await;
    assert_eq!(sub.header.rcode, Rcode::NxDomain);
    assert_eq!(ede_codes(&sub).len(), 0);
    let tracker = udp_exchange(h.udp, &query("tracker.example.net.", RecordType::Aaaa)).await;
    assert_eq!(tracker.header.rcode, Rcode::NxDomain);
    // Suffix matching is on labels, not strings.
    let other = udp_exchange(h.udp, &query("notads.example.net.", RecordType::A)).await;
    assert_ne!(ede_codes(&other), [ede::BLOCKED]);
    // Over TCP as well.
    let mut tcp = h.tcp_client().await;
    let r = tcp
        .ask(&query_edns("ads.example.net.", RecordType::A, 1232))
        .await
        .unwrap();
    assert_eq!(r.header.rcode, Rcode::NxDomain);
}

#[tokio::test]
async fn blocked_domain_null_ip_and_refused_modes() {
    let h = Harness::start(blocking("null_ip")).await;
    let a = udp_exchange(h.udp, &query("ads.example.net.", RecordType::A)).await;
    assert_eq!(a.header.rcode, Rcode::NoError);
    assert!(matches!(&a.answers[0].data, RData::A(ip) if ip.is_unspecified()));
    let aaaa = udp_exchange(h.udp, &query("ads.example.net.", RecordType::Aaaa)).await;
    assert!(matches!(&aaaa.answers[0].data, RData::Aaaa(ip) if ip.is_unspecified()));
    let mx = udp_exchange(h.udp, &query("ads.example.net.", RecordType::Mx)).await;
    assert_eq!(mx.header.rcode, Rcode::NoError);
    assert_eq!(mx.answers.len(), 0);

    let h = Harness::start(blocking("refused")).await;
    let r = udp_exchange(h.udp, &query("ads.example.net.", RecordType::A)).await;
    assert_eq!(r.header.rcode, Rcode::Refused);
}

#[tokio::test]
async fn custom_rules_block_allow_and_allow_wins() {
    let h = Harness::start(Opts {
        block_mode: "nxdomain",
        ..blocking("nxdomain")
    })
    .await;
    let rule = |kind: &str, domain: &str| json!({"kind": kind, "domain": domain});
    let (s, b) = h
        .api_send(
            Method::POST,
            "/rules",
            Some(rule("block", "evil.example.org")),
        )
        .await;
    assert_eq!(s, 201, "{b}");
    let r = eventually(Duration::from_secs(20), "custom rule applied", || async {
        let r = udp_exchange(h.udp, &query_edns("evil.example.org.", RecordType::A, 1232)).await;
        (r.header.rcode == Rcode::NxDomain).then_some(r)
    })
    .await;
    assert_eq!(ede_codes(&r), [ede::FILTERED]);

    // The allowlist beats the blocklist.
    let (s, b) = h
        .api_send(
            Method::POST,
            "/rules",
            Some(rule("allow", "ads.example.net")),
        )
        .await;
    assert_eq!(s, 201, "{b}");
    eventually(Duration::from_secs(20), "allow rule applied", || async {
        let r = udp_exchange(h.udp, &query_edns("ads.example.net.", RecordType::A, 1232)).await;
        (!ede_codes(&r).contains(&ede::BLOCKED)).then_some(())
    })
    .await;
}
