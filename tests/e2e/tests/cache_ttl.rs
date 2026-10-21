//! Cache lifetimes seen from DNS: TTL decay and expiry, negative caching, TTL clamps and the
//! settings that change them at runtime. TTLs are one to a few seconds, and every wait polls
//! for its effect.

use std::time::Duration;

use dnsy_e2e::upstream::a;
use dnsy_e2e::{Auth, Harness, Opts, Reply, eventually, query, udp_exchange};
use dnsy_proto::{Message, RData, Rcode, RecordType};
use serde_json::json;

const WAIT: Duration = Duration::from_secs(15);

fn forwarding() -> Opts {
    Opts {
        upstream: true,
        ..Opts::default()
    }
}

fn up(h: &Harness) -> &dnsy_e2e::FakeUpstream {
    h.upstream.as_ref().unwrap()
}

async fn ask(h: &Harness, name: &str, ty: RecordType) -> Message {
    udp_exchange(h.udp, &query(name, ty)).await
}

fn ip(m: &Message) -> String {
    match &m.answers[0].data {
        RData::A(ip) => ip.to_string(),
        other => panic!("not an A record: {other:?}"),
    }
}

#[tokio::test]
async fn cache_ttl_expiry_refetches() {
    let h = Harness::start(forwarding()).await;
    up(&h).on(
        "ttl.test.",
        RecordType::A,
        Reply::Answer(vec![a("ttl.test.", 2, "203.0.113.1")]),
    );
    assert_eq!(
        ip(&ask(&h, "ttl.test.", RecordType::A).await),
        "203.0.113.1"
    );
    assert_eq!(up(&h).count("ttl.test.", RecordType::A), 1);
    ask(&h, "ttl.test.", RecordType::A).await;
    assert_eq!(
        up(&h).count("ttl.test.", RecordType::A),
        1,
        "a fresh entry is served from the cache"
    );

    up(&h).on(
        "ttl.test.",
        RecordType::A,
        Reply::Answer(vec![a("ttl.test.", 60, "203.0.113.2")]),
    );
    let r = eventually(WAIT, "the entry to expire and be refetched", || async {
        let r = ask(&h, "ttl.test.", RecordType::A).await;
        (ip(&r) == "203.0.113.2").then_some(r)
    })
    .await;
    assert_eq!(up(&h).count("ttl.test.", RecordType::A), 2);
    assert!(
        r.answers[0].ttl > 2,
        "the new TTL applies: {}",
        r.answers[0].ttl
    );
}

#[tokio::test]
async fn cached_ttl_counts_down_and_never_grows() {
    let h = Harness::start(forwarding()).await;
    up(&h).on(
        "decay.test.",
        RecordType::A,
        Reply::Answer(vec![a("decay.test.", 30, "203.0.113.3")]),
    );
    let first = ask(&h, "decay.test.", RecordType::A).await;
    assert_eq!(first.answers[0].ttl, 30);
    let later = eventually(WAIT, "the TTL to decrease", || async {
        let r = ask(&h, "decay.test.", RecordType::A).await;
        (r.answers[0].ttl < 30).then_some(r)
    })
    .await;
    assert!(later.answers[0].ttl >= 28, "{}", later.answers[0].ttl);
    assert_eq!(up(&h).count("decay.test.", RecordType::A), 1);
}

#[tokio::test]
async fn negative_cache_then_expiry() {
    let h = Harness::start(forwarding()).await;
    up(&h).on("nx.test.", RecordType::A, Reply::NxDomain(2));
    up(&h).on("nodata.test.", RecordType::A, Reply::NoData(2));
    for (name, rcode) in [
        ("nx.test.", Rcode::NxDomain),
        ("nodata.test.", Rcode::NoError),
    ] {
        let first = ask(&h, name, RecordType::A).await;
        assert_eq!(first.header.rcode, rcode);
        assert_eq!(first.answers.len(), 0);
        ask(&h, name, RecordType::A).await;
        assert_eq!(
            up(&h).count(name, RecordType::A),
            1,
            "{name}: the negative answer is cached"
        );
    }
    // Once the SOA-derived TTL has passed the name is asked for again, and a changed answer shows.
    up(&h).on(
        "nx.test.",
        RecordType::A,
        Reply::Answer(vec![a("nx.test.", 60, "203.0.113.4")]),
    );
    eventually(WAIT, "the negative entry to expire", || async {
        (ask(&h, "nx.test.", RecordType::A).await.header.rcode == Rcode::NoError).then_some(())
    })
    .await;
    assert_eq!(up(&h).count("nx.test.", RecordType::A), 2);
}

#[tokio::test]
async fn servfail_from_the_upstream_is_not_kept_for_long() {
    let h = Harness::start(forwarding()).await;
    up(&h).on("flaky.test.", RecordType::A, Reply::Rcode(Rcode::ServFail));
    assert_eq!(
        ask(&h, "flaky.test.", RecordType::A).await.header.rcode,
        Rcode::ServFail
    );
    up(&h).on(
        "flaky.test.",
        RecordType::A,
        Reply::Answer(vec![a("flaky.test.", 60, "203.0.113.5")]),
    );
    // `servfail_ttl` is 5 s by default: the failure may be cached briefly but must not stick.
    let r = eventually(
        Duration::from_secs(20),
        "the upstream recovery to show",
        || async {
            let r = ask(&h, "flaky.test.", RecordType::A).await;
            (r.header.rcode == Rcode::NoError).then_some(r)
        },
    )
    .await;
    assert_eq!(ip(&r), "203.0.113.5");
}

#[tokio::test]
async fn min_ttl_clamp_observed() {
    let h = Harness::start(Opts {
        cache_min_ttl: 30,
        ..forwarding()
    })
    .await;
    up(&h).on(
        "short.test.",
        RecordType::A,
        Reply::Answer(vec![a("short.test.", 1, "203.0.113.6")]),
    );
    // The miss is answered with the upstream's TTL; the clamp shows on what the cache serves.
    ask(&h, "short.test.", RecordType::A).await;
    let first = ask(&h, "short.test.", RecordType::A).await;
    assert!(
        first.answers[0].ttl >= 29,
        "raised to min_ttl: {}",
        first.answers[0].ttl
    );
    // Well past the upstream's 1 s TTL the entry is still served from the cache.
    eventually(WAIT, "time to pass", || async {
        let r = ask(&h, "short.test.", RecordType::A).await;
        (r.answers[0].ttl < first.answers[0].ttl).then_some(())
    })
    .await;
    eventually(WAIT, "two seconds of entry age", || async {
        (ask(&h, "short.test.", RecordType::A).await.answers[0].ttl <= first.answers[0].ttl - 2)
            .then_some(())
    })
    .await;
    assert_eq!(
        up(&h).count("short.test.", RecordType::A),
        1,
        "the clamped entry outlived the upstream TTL"
    );
}

#[tokio::test]
async fn max_ttl_clamp_observed() {
    let h = Harness::start(Opts {
        cache_max_ttl: 20,
        ..forwarding()
    })
    .await;
    up(&h).on(
        "long.test.",
        RecordType::A,
        Reply::Answer(vec![a("long.test.", 86_400, "203.0.113.7")]),
    );
    ask(&h, "long.test.", RecordType::A).await;
    let r = ask(&h, "long.test.", RecordType::A).await;
    assert!(
        r.answers[0].ttl <= 20,
        "capped at max_ttl: {}",
        r.answers[0].ttl
    );
}

#[tokio::test]
async fn ttl_clamps_change_at_runtime_through_settings() {
    let h = Harness::start(forwarding()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    up(&h).on(
        "before.test.",
        RecordType::A,
        Reply::Answer(vec![a("before.test.", 3600, "203.0.113.8")]),
    );
    up(&h).on(
        "after.test.",
        RecordType::A,
        Reply::Answer(vec![a("after.test.", 3600, "203.0.113.9")]),
    );
    assert_eq!(
        ask(&h, "before.test.", RecordType::A).await.answers[0].ttl,
        3600
    );

    api.patch("/settings", admin, &json!({"cache": {"max_ttl": 10}}))
        .await
        .ok(200);
    let r = eventually(WAIT, "the new max_ttl to apply to new entries", || async {
        let r = ask(&h, "after.test.", RecordType::A).await;
        (r.answers[0].ttl <= 10).then_some(r)
    })
    .await;
    assert!(r.answers[0].ttl <= 10);
    // A raised floor above the cap is refused as a whole and changes nothing.
    api.patch("/settings", admin, &json!({"cache": {"min_ttl": 500}}))
        .await
        .problem(422);
    assert_eq!(
        api.get("/settings", admin).await.ok(200)["cache"]["min_ttl"],
        0
    );
}
