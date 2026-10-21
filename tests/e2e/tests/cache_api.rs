//! The resolver cache through the REST API: stats, flush by name and in full, and what each of
//! them does to the DNS path.

use dnsy_e2e::upstream::a;
use dnsy_e2e::{Auth, Harness, Opts, Reply, query, udp_exchange};
use dnsy_proto::{Message, RData, Rcode, RecordType};
use serde_json::Value;

fn forwarding() -> Opts {
    Opts {
        upstream: true,
        ..Opts::default().zone("example.test.", dnsy_e2e::zones::example_zone())
    }
}

fn script(h: &Harness, name: &str, ip: &str) {
    h.upstream
        .as_ref()
        .unwrap()
        .on(name, RecordType::A, Reply::Answer(vec![a(name, 300, ip)]));
}

fn upstream_hits(h: &Harness, name: &str) -> usize {
    h.upstream.as_ref().unwrap().count(name, RecordType::A)
}

async fn ask(h: &Harness, name: &str) -> Message {
    udp_exchange(h.udp, &query(name, RecordType::A)).await
}

fn ip(m: &Message) -> String {
    match &m.answers[0].data {
        RData::A(ip) => ip.to_string(),
        other => panic!("not an A record: {other:?}"),
    }
}

async fn stats(h: &Harness) -> Value {
    h.rest()
        .get("/cache", Auth::Bearer(&h.api_token))
        .await
        .ok(200)
}

#[tokio::test]
async fn cache_stats_reflect_traffic() {
    let h = Harness::start(forwarding()).await;
    let s = stats(&h).await;
    for key in [
        "entries",
        "capacity",
        "hits",
        "misses",
        "inserts",
        "evictions",
        "expired",
        "stale_served",
        "prefetches",
    ] {
        assert!(s[key].is_u64(), "{key} in {s}");
    }
    assert_eq!(
        (
            s["entries"].as_u64(),
            s["hits"].as_u64(),
            s["misses"].as_u64()
        ),
        (Some(0), Some(0), Some(0))
    );
    assert_eq!(s["hit_ratio"], 0.0);
    assert!(s["capacity"].as_u64().unwrap() > 0);

    script(&h, "one.test.", "203.0.113.1");
    script(&h, "two.test.", "203.0.113.2");
    ask(&h, "one.test.").await; // miss + insert
    ask(&h, "one.test.").await; // hit
    ask(&h, "one.test.").await; // hit
    ask(&h, "two.test.").await; // miss + insert
    let s = stats(&h).await;
    assert_eq!(
        (s["entries"].as_u64(), s["inserts"].as_u64()),
        (Some(2), Some(2)),
        "{s}"
    );
    assert_eq!(
        (s["hits"].as_u64(), s["misses"].as_u64()),
        (Some(2), Some(2)),
        "{s}"
    );
    assert!((s["hit_ratio"].as_f64().unwrap() - 0.5).abs() < 1e-9, "{s}");
    assert_eq!(
        (
            s["stale_served"].as_u64(),
            s["evictions"].as_u64(),
            s["prefetches"].as_u64()
        ),
        (Some(0), Some(0), Some(0))
    );
    assert_eq!(upstream_hits(&h, "one.test."), 1);
}

#[tokio::test]
async fn local_zone_answers_never_enter_the_cache() {
    let h = Harness::start(forwarding()).await;
    for _ in 0..3 {
        assert!(ask(&h, "www.example.test.").await.header.aa);
    }
    assert_eq!(
        ask(&h, "missing.example.test.").await.header.rcode,
        Rcode::NxDomain
    );
    let s = stats(&h).await;
    assert_eq!(
        (
            s["entries"].as_u64(),
            s["inserts"].as_u64(),
            s["hits"].as_u64(),
            s["misses"].as_u64()
        ),
        (Some(0), Some(0), Some(0), Some(0)),
        "{s}"
    );
    assert_eq!(
        h.upstream.as_ref().unwrap().total(),
        0,
        "local data is never forwarded"
    );
}

#[tokio::test]
async fn flush_by_name_forces_a_refetch_of_that_name_only() {
    let h = Harness::start(forwarding()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    script(&h, "a.flush.test.", "203.0.113.1");
    script(&h, "b.flush.test.", "203.0.113.2");
    ask(&h, "a.flush.test.").await;
    ask(&h, "b.flush.test.").await;
    ask(&h, "a.flush.test.").await;
    assert_eq!(upstream_hits(&h, "a.flush.test."), 1);

    // The upstream's answer changes; the cache keeps serving the old one until the flush.
    script(&h, "a.flush.test.", "203.0.113.99");
    assert_eq!(ip(&ask(&h, "a.flush.test.").await), "203.0.113.1");
    let flushed = api
        .delete("/cache/entries?name=a.flush.test.", admin)
        .await
        .ok(200);
    assert_eq!(flushed["removed"], 1);
    assert_eq!(stats(&h).await["entries"], 1);
    assert_eq!(
        ip(&ask(&h, "a.flush.test.").await),
        "203.0.113.99",
        "refetched"
    );
    assert_eq!(upstream_hits(&h, "a.flush.test."), 2);
    // The other name was untouched.
    ask(&h, "b.flush.test.").await;
    assert_eq!(upstream_hits(&h, "b.flush.test."), 1);
    // A name that is not cached removes nothing; case does not matter.
    assert_eq!(
        api.delete("/cache/entries?name=nothing.flush.test.", admin)
            .await
            .ok(200)["removed"],
        0
    );
    assert_eq!(
        api.delete("/cache/entries?name=B.Flush.TEST.", admin)
            .await
            .ok(200)["removed"],
        1
    );
}

#[tokio::test]
async fn flush_subtree_removes_everything_below_a_name() {
    let h = Harness::start(forwarding()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    for n in [
        "x.tree.test.",
        "deep.x.tree.test.",
        "tree.test.",
        "other.test.",
    ] {
        script(&h, n, "203.0.113.5");
        ask(&h, n).await;
    }
    // Without `subtree` only the exact name goes.
    assert_eq!(
        api.delete("/cache/entries?name=x.tree.test.", admin)
            .await
            .ok(200)["removed"],
        1
    );
    ask(&h, "x.tree.test.").await;
    let r = api
        .delete("/cache/entries?name=tree.test.&subtree=true", admin)
        .await
        .ok(200);
    assert_eq!(r["removed"], 3, "{r}");
    assert_eq!(stats(&h).await["entries"], 1, "only other.test. is left");
}

#[tokio::test]
async fn flush_all_via_api_empties_the_cache_and_forces_upstream_hits() {
    let h = Harness::start(forwarding()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    for i in 0..5 {
        let n = format!("n{i}.all.test.");
        script(&h, &n, "203.0.113.7");
        ask(&h, &n).await;
    }
    assert_eq!(stats(&h).await["entries"], 5);
    let r = api.delete("/cache", admin).await.ok(200);
    assert_eq!(r["removed"], 5);
    assert_eq!(stats(&h).await["entries"], 0);
    assert_eq!(
        api.delete("/cache", admin).await.ok(200)["removed"],
        0,
        "flushing twice is harmless"
    );
    for i in 0..5 {
        let n = format!("n{i}.all.test.");
        ask(&h, &n).await;
        assert_eq!(upstream_hits(&h, &n), 2, "{n} was fetched again");
    }
}

#[tokio::test]
async fn cache_endpoints_validate_input_and_check_roles() {
    let h = Harness::start(forwarding()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    for bad in [
        "/cache/entries",
        "/cache/entries?name=",
        "/cache/entries?name=a..b",
        "/cache/entries?name=x.test.&subtree=maybe",
    ] {
        let r = api.delete(bad, admin).await;
        assert!(
            matches!(r.status, 400 | 422),
            "{bad}: {} {}",
            r.status,
            r.text
        );
        r.problem(r.status);
    }
    let viewer = api
        .token_for(&h.api_token, "cvic", "viewer", &["api:read"])
        .await;
    let v = Auth::Bearer(&viewer);
    api.get("/cache", v).await.ok(200);
    api.delete("/cache", v).await.problem(403);
    api.delete("/cache/entries?name=x.test.", v)
        .await
        .problem(403);
    api.get("/cache", Auth::None).await.problem(401);
    api.delete("/cache", Auth::None).await.problem(401);
    let operator = api
        .token_for(&h.api_token, "cop", "operator", &["api:read", "api:write"])
        .await;
    api.delete("/cache", Auth::Bearer(&operator)).await.ok(200);
}
