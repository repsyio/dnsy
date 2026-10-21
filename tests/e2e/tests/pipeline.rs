//! Pipeline admission seen from the wire: identical cache misses are coalesced into one
//! upstream exchange, and a flood of queries for a slow name cannot take every UDP slot from
//! other names.

use std::time::Duration;

use dnsy_e2e::clients::wire;
use dnsy_e2e::upstream::a;
use dnsy_e2e::zones::example_zone;
use dnsy_e2e::{Harness, Opts, Reply, query, udp_exchange, udp_raw};
use dnsy_proto::{Message, RData, Rcode, RecordType};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

fn opts() -> Opts {
    Opts {
        upstream: true,
        resolver_timeout_ms: 5000,
        ..Opts::default()
    }
    .zone("example.test.", example_zone())
}

fn up(h: &Harness) -> &dnsy_e2e::FakeUpstream {
    h.upstream.as_ref().unwrap()
}

#[tokio::test]
async fn concurrent_identical_misses_reach_the_upstream_once() {
    let h = Harness::start(opts()).await;
    up(&h).on(
        "co.test.",
        RecordType::A,
        Reply::Delay(
            Duration::from_millis(500),
            Box::new(Reply::Answer(vec![a("co.test.", 300, "203.0.113.9")])),
        ),
    );
    let mut asks = JoinSet::new();
    for _ in 0..50 {
        let addr = h.udp;
        asks.spawn(async move { udp_exchange(addr, &query("co.test.", RecordType::A)).await });
    }
    for r in asks.join_all().await {
        assert_eq!(r.header.rcode, Rcode::NoError);
        assert_eq!(r.answers[0].data, RData::A("203.0.113.9".parse().unwrap()));
    }
    assert_eq!(up(&h).count("co.test.", RecordType::A), 1);
}

#[tokio::test]
async fn slow_name_flood_does_not_starve_other_names() {
    let h = Harness::start(opts()).await;
    up(&h).on(
        "slow.test.",
        RecordType::A,
        Reply::Delay(
            Duration::from_secs(3),
            Box::new(Reply::Answer(vec![a("slow.test.", 300, "203.0.113.10")])),
        ),
    );
    up(&h).on(
        "fast.test.",
        RecordType::A,
        Reply::Answer(vec![a("fast.test.", 300, "203.0.113.11")]),
    );
    // More identical slow queries than the listener has in-flight slots (1024).
    let flood = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..1500 {
        flood
            .send_to(&wire(&query("slow.test.", RecordType::A)), h.udp)
            .await
            .unwrap();
    }
    // While the slow exchange is still pending, other names are answered at once.
    for name in ["www.example.test.", "fast.test."] {
        let reply = udp_raw(
            h.udp,
            &wire(&query(name, RecordType::A)),
            Duration::from_secs(1),
        )
        .await
        .unwrap_or_else(|| panic!("{name} starved by the slow flood"));
        let r = Message::decode(&reply).unwrap();
        assert_eq!(r.header.rcode, Rcode::NoError, "{name}");
    }
    assert_eq!(
        up(&h).count("slow.test.", RecordType::A),
        1,
        "the flood is one upstream exchange"
    );
}
