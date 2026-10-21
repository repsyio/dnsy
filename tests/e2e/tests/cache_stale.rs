//! Serve-stale and prefetch: answers when the upstream is down, how long stale data is kept,
//! what the API and the query log say about it, and refreshing popular entries early.

use std::time::Duration;

use dnsy_e2e::clients::query_edns;
use dnsy_e2e::upstream::a;
use dnsy_e2e::{Auth, Harness, Opts, Reply, eventually, udp_exchange};
use dnsy_proto::{EdnsOption, Message, RData, Rcode, RecordType, ede};
use serde_json::json;

const WAIT: Duration = Duration::from_secs(20);

fn stale_opts(max_stale: u32) -> Opts {
    Opts {
        upstream: true,
        resolver_timeout_ms: 300,
        serve_stale: Some((max_stale, 30, 400)),
        ..Opts::default()
    }
}

fn up(h: &Harness) -> &dnsy_e2e::FakeUpstream {
    h.upstream.as_ref().unwrap()
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

fn ip(m: &Message) -> String {
    match &m.answers[0].data {
        RData::A(ip) => ip.to_string(),
        other => panic!("not an A record: {other:?}"),
    }
}

async fn ask(h: &Harness, name: &str) -> Message {
    udp_exchange(h.udp, &query_edns(name, RecordType::A, 1232)).await
}

#[tokio::test]
async fn stale_answer_when_upstream_down_is_visible_in_stats_and_log() {
    let h = Harness::start(stale_opts(3600)).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    up(&h).on(
        "stale.test.",
        RecordType::A,
        Reply::Answer(vec![a("stale.test.", 1, "203.0.113.1")]),
    );
    assert_eq!(ip(&ask(&h, "stale.test.").await), "203.0.113.1");
    assert_eq!(api.get("/cache", admin).await.ok(200)["stale_served"], 0);

    up(&h).go_dark();
    let stale = eventually(WAIT, "a stale answer with EDE 3", || async {
        let r = ask(&h, "stale.test.").await;
        ede_codes(&r).contains(&ede::STALE_ANSWER).then_some(r)
    })
    .await;
    assert_eq!(stale.header.rcode, Rcode::NoError);
    assert_eq!(ip(&stale), "203.0.113.1");
    assert_eq!(stale.answers[0].ttl, 30, "the configured stale answer TTL");

    assert!(
        api.get("/cache", admin).await.ok(200)["stale_served"]
            .as_u64()
            .unwrap()
            >= 1
    );
    let logged = eventually(WAIT, "a cache_stale log entry", || async {
        let p = api.get("/querylog?source=cache_stale", admin).await.ok(200);
        p["entries"].as_array().unwrap().first().cloned()
    })
    .await;
    assert_eq!(logged["qname"], "stale.test.");
    let summary = api.get("/stats/summary", admin).await.ok(200);
    assert!(summary["stale_answers"].as_u64().unwrap() >= 1, "{summary}");
}

#[tokio::test]
async fn stale_expires_after_max_stale() {
    let h = Harness::start(stale_opts(3)).await;
    up(&h).on(
        "brief.test.",
        RecordType::A,
        Reply::Answer(vec![a("brief.test.", 1, "203.0.113.2")]),
    );
    ask(&h, "brief.test.").await;
    up(&h).go_dark();
    // Stale first (1 s TTL + up to 3 s), then nothing is left and the client gets SERVFAIL.
    eventually(WAIT, "the stale answer", || async {
        ede_codes(&ask(&h, "brief.test.").await)
            .contains(&ede::STALE_ANSWER)
            .then_some(())
    })
    .await;
    let gone = eventually(WAIT, "the stale entry to expire", || async {
        let r = ask(&h, "brief.test.").await;
        (r.header.rcode == Rcode::ServFail).then_some(r)
    })
    .await;
    assert_eq!(gone.answers.len(), 0);
    assert!(!ede_codes(&gone).contains(&ede::STALE_ANSWER));
}

#[tokio::test]
async fn serve_stale_can_be_switched_on_at_runtime() {
    let h = Harness::start(Opts {
        serve_stale: None,
        ..stale_opts(3600)
    })
    .await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    assert_eq!(
        api.get("/settings", admin).await.ok(200)["cache"]["serve_stale"]["enabled"],
        false
    );
    api.patch(
        "/settings",
        admin,
        &json!({"cache": {"serve_stale": {"enabled": true}}}),
    )
    .await
    .ok(200);
    assert_eq!(
        api.get("/settings", admin).await.ok(200)["cache"]["serve_stale"]["enabled"],
        true
    );

    up(&h).on(
        "late.test.",
        RecordType::A,
        Reply::Answer(vec![a("late.test.", 1, "203.0.113.3")]),
    );
    ask(&h, "late.test.").await;
    up(&h).go_dark();
    let stale = eventually(
        WAIT,
        "a stale answer after enabling serve-stale",
        || async {
            let r = ask(&h, "late.test.").await;
            ede_codes(&r).contains(&ede::STALE_ANSWER).then_some(r)
        },
    )
    .await;
    assert_eq!(ip(&stale), "203.0.113.3");
}

#[tokio::test]
async fn flushing_the_cache_removes_the_stale_fallback() {
    let h = Harness::start(stale_opts(3600)).await;
    let api = h.rest();
    up(&h).on(
        "gone.test.",
        RecordType::A,
        Reply::Answer(vec![a("gone.test.", 1, "203.0.113.4")]),
    );
    ask(&h, "gone.test.").await;
    up(&h).go_dark();
    eventually(WAIT, "a stale answer", || async {
        ede_codes(&ask(&h, "gone.test.").await)
            .contains(&ede::STALE_ANSWER)
            .then_some(())
    })
    .await;
    api.delete("/cache", Auth::Bearer(&h.api_token))
        .await
        .ok(200);
    assert_eq!(
        ask(&h, "gone.test.").await.header.rcode,
        Rcode::ServFail,
        "nothing left to serve"
    );
}

#[tokio::test]
async fn prefetch_refreshes_before_expiry() {
    // min_hits 1 and "10 % .. 100 %" of the TTL remaining: the first cache hit starts a refresh
    // while the entry (60 s) is nowhere near expiry.
    let h = Harness::start(Opts {
        prefetch: Some((1, 100)),
        upstream: true,
        ..Opts::default()
    })
    .await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    up(&h).on(
        "pop.test.",
        RecordType::A,
        Reply::Answer(vec![a("pop.test.", 60, "203.0.113.10")]),
    );
    assert_eq!(ip(&ask(&h, "pop.test.").await), "203.0.113.10");
    assert_eq!(up(&h).count("pop.test.", RecordType::A), 1);

    up(&h).on(
        "pop.test.",
        RecordType::A,
        Reply::Answer(vec![a("pop.test.", 60, "203.0.113.11")]),
    );
    // This hit is still answered from the cache and kicks off the background refresh.
    assert_eq!(ip(&ask(&h, "pop.test.").await), "203.0.113.10");
    eventually(WAIT, "the prefetch to reach the upstream", || async {
        (up(&h).count("pop.test.", RecordType::A) == 2).then_some(())
    })
    .await;
    eventually(WAIT, "the refreshed answer", || async {
        (ip(&ask(&h, "pop.test.").await) == "203.0.113.11").then_some(())
    })
    .await;
    assert!(
        api.get("/cache", admin).await.ok(200)["prefetches"]
            .as_u64()
            .unwrap()
            >= 1
    );
}

#[tokio::test]
async fn prefetch_is_off_unless_enabled_and_toggles_at_runtime() {
    let h = Harness::start(Opts {
        upstream: true,
        ..Opts::default()
    })
    .await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    up(&h).on(
        "quiet.test.",
        RecordType::A,
        Reply::Answer(vec![a("quiet.test.", 60, "203.0.113.12")]),
    );
    for _ in 0..8 {
        ask(&h, "quiet.test.").await;
    }
    // Silence window: no refresh may reach the upstream.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(up(&h).count("quiet.test.", RecordType::A), 1);
    assert_eq!(api.get("/cache", admin).await.ok(200)["prefetches"], 0);
    assert_eq!(
        api.get("/settings", admin).await.ok(200)["cache"]["prefetch"]["enabled"],
        false
    );
    api.patch(
        "/settings",
        admin,
        &json!({"cache": {"prefetch": {"enabled": true}}}),
    )
    .await
    .ok(200);
    assert_eq!(
        api.get("/settings", admin).await.ok(200)["cache"]["prefetch"]["enabled"],
        true
    );
}
