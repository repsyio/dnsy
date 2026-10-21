//! Plain DNS over UDP and TCP against a local zone: happy flows and wire-level edge cases.

use dnsy_e2e::clients::{query_edns, wire};
use dnsy_e2e::zones::example_zone;
use dnsy_e2e::{Harness, Opts, eventually, query, udp_exchange, udp_raw, udp_silent};
use dnsy_proto::{Class, Message, Opcode, RData, Rcode, RecordType};
use std::time::Duration;

async fn start() -> Harness {
    Harness::start(Opts::default().zone("example.test.", example_zone())).await
}

fn a_records(m: &Message) -> Vec<String> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(ip) => Some(ip.to_string()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn udp_local_zone() {
    let h = start().await;
    let q = query("www.example.test.", RecordType::A);
    let r = udp_exchange(h.udp, &q).await;
    assert_eq!(r.header.id, q.header.id);
    assert!(r.header.qr && r.header.aa && r.header.rd);
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert_eq!(a_records(&r), ["192.0.2.7"]);
    assert_eq!(r.answers[0].ttl, 300);
}

#[tokio::test]
async fn tcp_local_zone() {
    let h = start().await;
    let mut c = h.tcp_client().await;
    let q = query("www.example.test.", RecordType::Aaaa);
    let r = c.ask(&q).await.unwrap();
    assert_eq!(r.header.id, q.header.id);
    assert!(r.header.aa);
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert!(matches!(r.answers[0].data, RData::Aaaa(_)));
}

#[tokio::test]
async fn name_matching_is_case_insensitive() {
    let h = start().await;
    let r = udp_exchange(h.udp, &query("WwW.ExAmPlE.TeSt.", RecordType::A)).await;
    assert_eq!(a_records(&r), ["192.0.2.7"]);
}

#[tokio::test]
async fn udp_truncation_then_tcp() {
    let h = start().await;
    let q = query("many.example.test.", RecordType::A);
    let udp = udp_exchange(h.udp, &q).await;
    assert!(
        udp.header.tc,
        "512-octet UDP limit must truncate 40 A records"
    );
    assert!(udp.answers.len() < 40);
    let mut c = h.tcp_client().await;
    let tcp = c.ask(&q).await.unwrap();
    assert!(!tcp.header.tc);
    assert_eq!(tcp.answers.len(), 40);
}

#[tokio::test]
async fn edns_buffer_size_controls_truncation() {
    let h = start().await;
    let big = udp_exchange(
        h.udp,
        &query_edns("many.example.test.", RecordType::A, 4096),
    )
    .await;
    assert!(!big.header.tc);
    assert_eq!(big.answers.len(), 40);
    assert!(
        big.edns.is_some(),
        "EDNS queries get an OPT in the response"
    );

    // An RRset that does not fit is dropped whole and TC is set.
    let small = udp_exchange(h.udp, &query_edns("many.example.test.", RecordType::A, 600)).await;
    assert!(small.header.tc);

    // A size below 512 is treated as 512 (RFC 6891 section 6.2.3): 10 records (about 250 octets)
    // fit although the client advertised 100.
    let tiny = udp_exchange(h.udp, &query_edns("some.example.test.", RecordType::A, 100)).await;
    assert!(!tiny.header.tc);
    assert_eq!(tiny.answers.len(), 10);
}

#[tokio::test]
async fn nxdomain_and_nodata_carry_the_soa() {
    let h = start().await;
    let nx = udp_exchange(h.udp, &query("missing.example.test.", RecordType::A)).await;
    assert_eq!(nx.header.rcode, Rcode::NxDomain);
    assert!(nx.header.aa && nx.answers.is_empty());
    assert!(matches!(nx.authority[0].data, RData::Soa(_)));
    assert_eq!(nx.authority[0].ttl, 300);

    let nodata = udp_exchange(h.udp, &query("www.example.test.", RecordType::Mx)).await;
    assert_eq!(nodata.header.rcode, Rcode::NoError);
    assert_eq!(nodata.answers.len(), 0);
    assert!(matches!(nodata.authority[0].data, RData::Soa(_)));

    // Empty non-terminals exist (RFC 8020 reading of RFC 4592).
    let ent = udp_exchange(h.udp, &query("_tcp.srv.example.test.", RecordType::A)).await;
    assert_eq!(ent.header.rcode, Rcode::NoError);
    assert_eq!(ent.answers.len(), 0);
}

#[tokio::test]
async fn wildcard_and_cname_chain() {
    let h = start().await;
    let w = udp_exchange(h.udp, &query("anything.wild.example.test.", RecordType::A)).await;
    assert_eq!(a_records(&w), ["192.0.2.99"]);
    assert_eq!(w.answers[0].name.to_string(), "anything.wild.example.test.");

    let chain = udp_exchange(h.udp, &query("hop1.example.test.", RecordType::A)).await;
    let kinds: Vec<_> = chain.answers.iter().map(|r| r.rtype).collect();
    assert_eq!(
        kinds,
        [
            RecordType::Cname,
            RecordType::Cname,
            RecordType::Cname,
            RecordType::A
        ]
    );
    assert_eq!(a_records(&chain), ["192.0.2.7"]);

    // Asking for the CNAME itself does not follow it.
    let own = udp_exchange(h.udp, &query("alias.example.test.", RecordType::Cname)).await;
    assert_eq!(own.answers.len(), 1);
    assert_eq!(own.answers[0].rtype, RecordType::Cname);

    // A chain leaving the zone ends at the CNAME.
    let out = udp_exchange(h.udp, &query("out.example.test.", RecordType::A)).await;
    assert_eq!(out.answers.len(), 1);
    assert_eq!(out.answers[0].rtype, RecordType::Cname);
}

#[tokio::test]
async fn wrong_class_is_not_answered_from_the_zone() {
    let h = start().await;
    let mut q = query("www.example.test.", RecordType::A);
    q.questions[0].qclass = Class::Ch;
    let r = udp_exchange(h.udp, &q).await;
    assert_eq!(r.answers.len(), 0);
    assert_ne!(r.header.rcode, Rcode::NoError, "CH is not served");
}

#[tokio::test]
async fn malformed_packet_formerr() {
    let h = start().await;
    // Valid header claiming one question, then a label that runs past the end.
    let mut bad = query("www.example.test.", RecordType::A);
    bad.header.id = 0xBEEF;
    let mut bytes = wire(&bad);
    bytes.truncate(20);
    let r = Message::decode(
        &udp_raw(h.udp, &bytes, Duration::from_secs(5))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r.header.id, 0xBEEF);
    assert_eq!(r.header.rcode, Rcode::FormErr);
    assert!(r.header.qr);

    // Trailing garbage after a valid query.
    let mut padded = wire(&query("www.example.test.", RecordType::A));
    padded.extend_from_slice(&[0xde, 0xad]);
    let r = Message::decode(
        &udp_raw(h.udp, &padded, Duration::from_secs(5))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r.header.rcode, Rcode::FormErr);

    // The server still answers afterwards.
    let ok = udp_exchange(h.udp, &query("www.example.test.", RecordType::A)).await;
    assert_eq!(ok.header.rcode, Rcode::NoError);
}

#[tokio::test]
async fn short_packets_and_stray_responses_are_dropped() {
    let h = start().await;
    for len in [0usize, 1, 5, 11] {
        assert!(
            udp_raw(h.udp, &vec![0xAB; len], Duration::from_millis(300))
                .await
                .is_none(),
            "a {len}-octet packet gets no reply"
        );
    }
    // A malformed packet that is itself a response must not be answered (no FORMERR ping-pong).
    let mut resp = wire(&query("www.example.test.", RecordType::A));
    resp[2] |= 0x80;
    resp.truncate(20);
    assert!(
        udp_raw(h.udp, &resp, Duration::from_millis(300))
            .await
            .is_none()
    );
    // Alive afterwards.
    let ok = udp_exchange(h.udp, &query("www.example.test.", RecordType::A)).await;
    assert_eq!(ok.header.rcode, Rcode::NoError);
}

#[tokio::test]
async fn oversized_udp_datagram_is_handled() {
    let h = start().await;
    let mut big = wire(&query("www.example.test.", RecordType::A));
    big.resize(4000, 0);
    // Trailing zeroes make the packet malformed: FORMERR or silence, never a crash.
    if let Some(bytes) = udp_raw(h.udp, &big, Duration::from_secs(2)).await {
        let r = Message::decode(&bytes).unwrap();
        assert_eq!(r.header.rcode, Rcode::FormErr);
    }
    let ok = udp_exchange(h.udp, &query("www.example.test.", RecordType::A)).await;
    assert_eq!(ok.header.rcode, Rcode::NoError);
}

#[tokio::test]
async fn unsupported_opcode_and_edns_version() {
    let h = start().await;
    let mut q = query("www.example.test.", RecordType::A);
    q.header.opcode = Opcode::Update;
    let r = udp_exchange(h.udp, &q).await;
    assert_eq!(r.header.rcode, Rcode::NotImp);

    let mut v1 = query_edns("www.example.test.", RecordType::A, 1232);
    v1.edns.as_mut().unwrap().version = 1;
    let r = udp_exchange(h.udp, &v1).await;
    assert_eq!(r.header.rcode, Rcode::BadVers);
}

#[tokio::test]
async fn tcp_pipelining_and_reuse() {
    let h = start().await;
    let mut c = h.tcp_client().await;
    let qs: Vec<_> = ["www", "alias", "hop1"]
        .iter()
        .map(|n| query(&format!("{n}.example.test."), RecordType::A))
        .collect();
    for q in &qs {
        c.send(q).await.unwrap();
    }
    let mut ids = Vec::new();
    for _ in &qs {
        let r = c.recv().await.unwrap();
        assert_eq!(r.header.rcode, Rcode::NoError);
        ids.push(r.header.id);
    }
    ids.sort_unstable();
    let mut want: Vec<_> = qs.iter().map(|q| q.header.id).collect();
    want.sort_unstable();
    assert_eq!(ids, want, "every pipelined query is answered once");
}

#[tokio::test]
async fn tcp_malformed_message_gets_formerr_and_connection_survives_or_closes() {
    let h = start().await;
    let mut c = h.tcp_client().await;
    let mut bytes = wire(&query("www.example.test.", RecordType::A));
    bytes.truncate(15);
    c.send_raw(&bytes).await.unwrap();
    let r = Message::decode(&c.recv_raw().await.unwrap()).unwrap();
    assert_eq!(r.header.rcode, Rcode::FormErr);
}

#[tokio::test]
async fn tcp_idle_connection_is_closed() {
    let h = Harness::start(Opts {
        tcp_idle_ms: 300,
        ..Opts::default().zone("example.test.", example_zone())
    })
    .await;
    let mut c = h.tcp_client().await;
    assert!(c.closed_within(Duration::from_secs(10)).await);
    let mut fresh = h.tcp_client().await;
    let r = fresh
        .ask(&query("www.example.test.", RecordType::A))
        .await
        .unwrap();
    assert_eq!(r.header.rcode, Rcode::NoError);
}

#[tokio::test]
async fn zone_hot_reload_visible() {
    let h = start().await;
    let q = query("fresh.example.test.", RecordType::A);
    assert_eq!(udp_exchange(h.udp, &q).await.header.rcode, Rcode::NxDomain);
    let json = dnsy_e2e::zones::zone_json(
        "example.test.",
        &[("www", "A", "192.0.2.7"), ("fresh", "A", "192.0.2.55")],
        false,
    );
    h.write_zone("example.test.", &json);

    let r = eventually(Duration::from_secs(20), "zone reload", || async {
        let r = udp_exchange(h.udp, &query("fresh.example.test.", RecordType::A)).await;
        (r.header.rcode == Rcode::NoError).then_some(r)
    })
    .await;
    assert_eq!(a_records(&r), ["192.0.2.55"]);

    // An invalid file never replaces a working zone.
    h.write_zone("example.test.", "{ not json");
    h.wait_for_log("zone file rejected").await;
    // The reload itself reads the files; that must not trigger another reload. The window is
    // several debounce periods (250 ms each).
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        h.logs().matches("zone file rejected").count(),
        1,
        "a rejected zone file is reported once, not on every reload loop:\n{}",
        h.logs()
    );
    let still = udp_exchange(h.udp, &query("fresh.example.test.", RecordType::A)).await;
    assert_eq!(a_records(&still), ["192.0.2.55"]);
}

#[tokio::test]
async fn silence_helper_sees_no_reply_to_nothing() {
    // Sanity check of the negative helper itself against a port nobody listens on.
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let q = query("www.example.test.", RecordType::A);
    assert!(udp_silent(sock.local_addr().unwrap(), &q).await);
}

/// TYPE HINFO, used by the RFC 8482 minimal ANY answer.
const HINFO: u16 = 13;

#[tokio::test]
async fn any_on_local_zone_is_answered_minimally_over_udp_and_tcp() {
    let h = start().await;
    let q = query_edns("many.example.test.", RecordType::Any, 1232);
    let bytes = udp_raw(h.udp, &wire(&q), dnsy_e2e::DEADLINE)
        .await
        .expect("a UDP reply");
    assert!(
        bytes.len() <= 100,
        "no amplification: {} octets for a {} octet query",
        bytes.len(),
        wire(&q).len()
    );
    let mut c = h.tcp_client().await;
    let tcp = c.ask(&q).await.unwrap();
    for r in [Message::decode(&bytes).unwrap(), tcp] {
        assert_eq!(r.header.rcode, Rcode::NoError);
        assert!(r.header.aa && !r.header.tc);
        assert_eq!(r.answers.len(), 1, "{:?}", r.answers);
        assert_eq!(r.answers[0].ttl, 3789);
        assert!(matches!(
            &r.answers[0].data,
            RData::Opaque { rtype: HINFO, data } if data.as_slice() == b"\x07RFC8482\x00"
        ));
    }
}

async fn start_forwarding() -> Harness {
    Harness::start(
        Opts {
            upstream: true,
            ..Opts::default()
        }
        .zone("example.test.", example_zone()),
    )
    .await
}

#[tokio::test]
async fn any_for_forwarded_name_is_refused_without_upstream() {
    let h = start_forwarding().await;
    let r = udp_exchange(h.udp, &query("www.example.org.", RecordType::Any)).await;
    assert_eq!(r.header.rcode, Rcode::Refused);
    assert_eq!(r.answers, []);
    assert_eq!(h.upstream.as_ref().unwrap().total(), 0);
}

#[tokio::test]
async fn axfr_and_ixfr_are_refused_without_upstream() {
    let h = start_forwarding().await;
    let mut c = h.tcp_client().await;
    for qtype in [RecordType::Unknown(252), RecordType::Unknown(251)] {
        for name in ["example.test.", "example.org."] {
            let q = query(name, qtype);
            let udp = udp_exchange(h.udp, &q).await;
            let tcp = c.ask(&q).await.unwrap();
            for r in [udp, tcp] {
                assert_eq!(r.header.rcode, Rcode::Refused, "{name} {qtype:?}");
                assert!(r.answers.is_empty() && r.authority.is_empty());
            }
        }
    }
    assert_eq!(h.upstream.as_ref().unwrap().total(), 0);
}
