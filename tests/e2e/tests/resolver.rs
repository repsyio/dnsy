//! Forwarding to the fake upstream: caching, failures, extended errors and serve-stale.

use std::time::Duration;

use dnsy_e2e::clients::{Framed, query_edns};
use dnsy_e2e::upstream::{a, rec};
use dnsy_e2e::{Harness, Opts, Reply, eventually, query, udp_exchange};
use dnsy_proto::{EdnsOption, Message, RData, Rcode, RecordType, ede};

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

fn forwarding() -> Opts {
    Opts {
        upstream: true,
        ..Opts::default()
    }
}

fn up(h: &Harness) -> &dnsy_e2e::FakeUpstream {
    h.upstream.as_ref().unwrap()
}

fn first_a(m: &Message) -> String {
    match &m.answers[0].data {
        RData::A(ip) => ip.to_string(),
        other => panic!("not an A record: {other:?}"),
    }
}

#[tokio::test]
async fn forwarded_query_cached() {
    let h = Harness::start(forwarding()).await;
    up(&h).on(
        "fwd.test.",
        RecordType::A,
        Reply::Answer(vec![a("fwd.test.", 30, "203.0.113.5")]),
    );
    let q = query("fwd.test.", RecordType::A);
    let first = udp_exchange(h.udp, &q).await;
    assert_eq!(first.header.rcode, Rcode::NoError);
    assert!(!first.header.aa && first.header.ra);
    assert_eq!(first_a(&first), "203.0.113.5");
    assert_eq!(first.answers[0].ttl, 30);
    assert_eq!(up(&h).count("fwd.test.", RecordType::A), 1);

    // The TTL counts down while the entry sits in the cache; no new upstream query is made.
    let later = eventually(Duration::from_secs(10), "TTL to decrease", || async {
        let r = udp_exchange(h.udp, &query("fwd.test.", RecordType::A)).await;
        (r.answers[0].ttl < 30).then_some(r)
    })
    .await;
    assert_eq!(first_a(&later), "203.0.113.5");
    assert_eq!(
        up(&h).count("fwd.test.", RecordType::A),
        1,
        "answered from cache"
    );
    // Another transport shares the cache.
    let mut tcp = h.tcp_client().await;
    tcp.ask(&q).await.unwrap();
    assert_eq!(up(&h).count("fwd.test.", RecordType::A), 1);
}

#[tokio::test]
async fn cached_entry_expires_and_is_refetched() {
    let h = Harness::start(forwarding()).await;
    up(&h).on(
        "short.test.",
        RecordType::A,
        Reply::Answer(vec![a("short.test.", 1, "203.0.113.6")]),
    );
    udp_exchange(h.udp, &query("short.test.", RecordType::A)).await;
    eventually(Duration::from_secs(10), "refetch after expiry", || async {
        udp_exchange(h.udp, &query("short.test.", RecordType::A)).await;
        (up(&h).count("short.test.", RecordType::A) >= 2).then_some(())
    })
    .await;
}

#[tokio::test]
async fn negative_answers_are_cached() {
    let h = Harness::start(forwarding()).await;
    up(&h).on("gone.test.", RecordType::A, Reply::NxDomain(60));
    up(&h).on("empty.test.", RecordType::A, Reply::NoData(60));
    for _ in 0..3 {
        let nx = udp_exchange(h.udp, &query("gone.test.", RecordType::A)).await;
        assert_eq!(nx.header.rcode, Rcode::NxDomain);
        let nodata = udp_exchange(h.udp, &query("empty.test.", RecordType::A)).await;
        assert_eq!(nodata.header.rcode, Rcode::NoError);
        assert_eq!(nodata.answers.len(), 0);
    }
    assert_eq!(up(&h).count("gone.test.", RecordType::A), 1);
    assert_eq!(up(&h).count("empty.test.", RecordType::A), 1);
}

#[tokio::test]
async fn forwarded_cname_chain_is_returned_whole() {
    let h = Harness::start(forwarding()).await;
    up(&h).on(
        "alias.test.",
        RecordType::A,
        Reply::Answer(vec![
            rec("alias.test.", 60, RecordType::Cname, "target.test."),
            a("target.test.", 60, "203.0.113.7"),
        ]),
    );
    let r = udp_exchange(h.udp, &query("alias.test.", RecordType::A)).await;
    assert_eq!(r.answers.len(), 2);
    assert_eq!(r.answers[0].rtype, RecordType::Cname);
    assert_eq!(
        first_a(&Message {
            answers: vec![r.answers[1].clone()],
            ..r.clone()
        }),
        "203.0.113.7"
    );
}

#[tokio::test]
async fn upstream_down_servfail() {
    let h = Harness::start(Opts {
        resolver_timeout_ms: 300,
        ..forwarding()
    })
    .await;
    up(&h).set_default(Reply::Drop);
    let r = udp_exchange(h.udp, &query_edns("dead.test.", RecordType::A, 1232)).await;
    assert_eq!(r.header.rcode, Rcode::ServFail);
    assert!(
        ede_codes(&r)
            .iter()
            .any(|c| [ede::NO_REACHABLE_AUTHORITY, ede::NETWORK_ERROR].contains(c)),
        "an upstream timeout is explained with an EDE, got {:?}",
        ede_codes(&r)
    );
    // The failure is not sticky: once the upstream is back the next query succeeds.
    up(&h).on(
        "dead.test.",
        RecordType::A,
        Reply::Answer(vec![a("dead.test.", 60, "203.0.113.4")]),
    );
    let eventual = eventually(Duration::from_secs(15), "recovery", || async {
        let r = udp_exchange(h.udp, &query("dead.test.", RecordType::A)).await;
        (r.header.rcode == Rcode::NoError).then_some(r)
    })
    .await;
    assert_eq!(first_a(&eventual), "203.0.113.4");
}

#[tokio::test]
async fn upstream_error_responses_and_garbage() {
    let h = Harness::start(Opts {
        resolver_timeout_ms: 300,
        ..forwarding()
    })
    .await;
    up(&h).on("refused.test.", RecordType::A, Reply::Rcode(Rcode::Refused));
    up(&h).on(
        "servfail.test.",
        RecordType::A,
        Reply::Rcode(Rcode::ServFail),
    );
    up(&h).on(
        "garbage.test.",
        RecordType::A,
        Reply::Garbage(vec![1, 2, 3]),
    );
    up(&h).on(
        "wrongid.test.",
        RecordType::A,
        Reply::WrongId(Box::new(Reply::Answer(vec![a(
            "wrongid.test.",
            60,
            "203.0.113.9",
        )]))),
    );
    // An upstream SERVFAIL is cached for `servfail_ttl`: asking again is not forwarded again.
    for _ in 0..2 {
        let r = udp_exchange(h.udp, &query("servfail.test.", RecordType::A)).await;
        assert_eq!(r.header.rcode, Rcode::ServFail);
    }
    assert_eq!(up(&h).count("servfail.test.", RecordType::A), 1);
    for name in ["garbage.test.", "wrongid.test."] {
        let r = udp_exchange(h.udp, &query_edns(name, RecordType::A, 1232)).await;
        assert_eq!(r.header.rcode, Rcode::ServFail, "{name}");
        assert!(
            r.answers.is_empty(),
            "{name}: a mismatching response is never trusted"
        );
    }
    let r = udp_exchange(h.udp, &query("refused.test.", RecordType::A)).await;
    assert_ne!(r.header.rcode, Rcode::NoError);
}

#[tokio::test]
async fn slow_upstream_within_timeout_still_answers() {
    let h = Harness::start(Opts {
        resolver_timeout_ms: 3000,
        ..forwarding()
    })
    .await;
    up(&h).on(
        "slow.test.",
        RecordType::A,
        Reply::Delay(
            Duration::from_millis(400),
            Box::new(Reply::Answer(vec![a("slow.test.", 60, "203.0.113.8")])),
        ),
    );
    let r = udp_exchange(h.udp, &query("slow.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), "203.0.113.8");
}

fn stale_opts() -> Opts {
    Opts {
        resolver_timeout_ms: 300,
        serve_stale: Some((3600, 30, 400)),
        ..forwarding()
    }
}

#[tokio::test]
async fn stale_served_when_upstream_down_with_ede3() {
    let h = Harness::start(stale_opts()).await;
    up(&h).on(
        "stale.test.",
        RecordType::A,
        Reply::Answer(vec![a("stale.test.", 1, "203.0.113.10")]),
    );
    let fresh = udp_exchange(h.udp, &query_edns("stale.test.", RecordType::A, 1232)).await;
    assert_eq!(first_a(&fresh), "203.0.113.10");
    assert_eq!(ede_codes(&fresh).len(), 0);

    up(&h).go_dark();
    // After the 1 s TTL the entry is stale; the answer then comes with EDE 3 and the stale TTL.
    let stale = eventually(Duration::from_secs(15), "a stale answer", || async {
        let r = udp_exchange(h.udp, &query_edns("stale.test.", RecordType::A, 1232)).await;
        ede_codes(&r).contains(&ede::STALE_ANSWER).then_some(r)
    })
    .await;
    assert_eq!(first_a(&stale), "203.0.113.10");
    assert_eq!(stale.answers[0].ttl, 30);
    assert_eq!(stale.header.rcode, Rcode::NoError);
}

#[tokio::test]
async fn stale_nxdomain_ede19() {
    let h = Harness::start(stale_opts()).await;
    up(&h).on("nx.test.", RecordType::A, Reply::NxDomain(1));
    let fresh = udp_exchange(h.udp, &query("nx.test.", RecordType::A)).await;
    assert_eq!(fresh.header.rcode, Rcode::NxDomain);
    up(&h).go_dark();
    let stale = eventually(Duration::from_secs(15), "a stale NXDOMAIN", || async {
        let r = udp_exchange(h.udp, &query_edns("nx.test.", RecordType::A, 1232)).await;
        ede_codes(&r).contains(&ede::STALE_NXDOMAIN).then_some(r)
    })
    .await;
    assert_eq!(stale.header.rcode, Rcode::NxDomain);
}

#[tokio::test]
async fn stale_is_replaced_when_upstream_recovers() {
    let h = Harness::start(stale_opts()).await;
    up(&h).on(
        "recover.test.",
        RecordType::A,
        Reply::Answer(vec![a("recover.test.", 1, "203.0.113.11")]),
    );
    udp_exchange(h.udp, &query("recover.test.", RecordType::A)).await;
    up(&h).on(
        "recover.test.",
        RecordType::A,
        Reply::Answer(vec![a("recover.test.", 60, "203.0.113.12")]),
    );
    let r = eventually(Duration::from_secs(15), "refreshed answer", || async {
        let r = udp_exchange(h.udp, &query_edns("recover.test.", RecordType::A, 1232)).await;
        (first_a(&r) == "203.0.113.12").then_some(r)
    })
    .await;
    assert!(ede_codes(&r).is_empty(), "a refreshed answer is not stale");
}

#[tokio::test]
async fn no_stale_without_serve_stale_servfails() {
    let h = Harness::start(Opts {
        resolver_timeout_ms: 300,
        ..forwarding()
    })
    .await;
    up(&h).on(
        "nostale.test.",
        RecordType::A,
        Reply::Answer(vec![a("nostale.test.", 1, "203.0.113.13")]),
    );
    udp_exchange(h.udp, &query("nostale.test.", RecordType::A)).await;
    up(&h).go_dark();
    eventually(Duration::from_secs(15), "SERVFAIL after expiry", || async {
        let r = udp_exchange(h.udp, &query("nostale.test.", RecordType::A)).await;
        (r.header.rcode == Rcode::ServFail).then_some(())
    })
    .await;
}

#[tokio::test]
async fn forwarding_works_over_tcp_and_for_many_names_at_once() {
    let h = Harness::start(forwarding()).await;
    for i in 0..20 {
        let name = format!("n{i}.test.");
        up(&h).on(
            &name,
            RecordType::A,
            Reply::Answer(vec![a(&name, 60, "203.0.113.20")]),
        );
    }
    let mut tcp = Framed::connect_tcp(h.tcp).await;
    for i in 0..20 {
        tcp.send(&query(&format!("n{i}.test."), RecordType::A))
            .await
            .unwrap();
    }
    for _ in 0..20 {
        let r = tcp.recv().await.unwrap();
        assert_eq!(r.header.rcode, Rcode::NoError);
        assert_eq!(first_a(&r), "203.0.113.20");
    }
}

fn with_do(mut q: Message) -> Message {
    q.edns = Some(dnsy_proto::Edns {
        dnssec_ok: true,
        ..dnsy_proto::Edns::default()
    });
    q
}

/// The harness serves a signed root from the fake upstream: validation sets AD on good data and
/// fails tampered data (the full DNSSEC matrix belongs to the DNSSEC suite).
#[tokio::test]
async fn signed_upstream_validates_and_tampering_is_servfail() {
    let upstream = dnsy_e2e::FakeUpstream::start().await;
    let fixture = upstream.serve_signed_root(vec![
        a("host.", 300, "203.0.113.30"),
        a("fake.", 300, "203.0.113.31"),
    ]);
    // Tampered: the signed RRset with a different address.
    let mut forged = fixture.rrset("fake.", RecordType::A);
    forged[0].data = RData::A("203.0.113.66".parse().unwrap());
    upstream.on("fake.", RecordType::A, Reply::Answer(forged));

    let trust_anchor = fixture.trust_anchor.clone();
    let h = Harness::start_with(
        Opts {
            validation: "strict",
            trust_anchors: vec![trust_anchor],
            ..Opts::default()
        },
        Some(upstream),
    )
    .await;

    let good = eventually(Duration::from_secs(20), "a validated answer", || async {
        let r = udp_exchange(h.udp, &with_do(query("host.", RecordType::A))).await;
        (r.header.rcode == Rcode::NoError).then_some(r)
    })
    .await;
    assert!(good.header.ad, "validated data carries AD");
    assert_eq!(first_a(&good), "203.0.113.30");

    let bad = udp_exchange(h.udp, &with_do(query("fake.", RecordType::A))).await;
    assert_eq!(bad.header.rcode, Rcode::ServFail);
    assert_eq!(bad.answers.len(), 0);
    assert!(
        !ede_codes(&bad).is_empty(),
        "a bogus answer is explained with an EDE"
    );
}
