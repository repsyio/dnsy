//! Query log, stats and the live tail: what the API reports about DNS queries just made.

use std::time::Duration;

use dnsy_e2e::upstream::a;
use dnsy_e2e::zones::example_zone;
use dnsy_e2e::{Auth, Harness, Opts, Reply, eventually, query, udp_exchange};
use dnsy_proto::{Rcode, RecordType};
use serde_json::Value;

const WAIT: Duration = Duration::from_secs(15);

fn opts() -> Opts {
    Opts {
        upstream: true,
        blocked: vec!["ads.example.net".into()],
        block_mode: "nxdomain",
        ..Opts::default().zone("example.test.", example_zone())
    }
}

async fn ask(h: &Harness, name: &str, ty: RecordType) -> Rcode {
    udp_exchange(h.udp, &query(name, ty)).await.header.rcode
}

/// Polls the query log until `filter` matches at least `n` entries and returns them.
async fn log_entries(h: &Harness, filter: &str, n: usize) -> Vec<Value> {
    let api = h.rest();
    eventually(WAIT, &format!("{n} log entries for `{filter}`"), || async {
        let page = api
            .get(&format!("/querylog?{filter}"), Auth::Bearer(&h.api_token))
            .await
            .ok(200);
        let entries = page["entries"].as_array().unwrap().clone();
        (entries.len() >= n).then_some(entries)
    })
    .await
}

#[tokio::test]
async fn query_log_records_each_kind_of_answer_with_its_source() {
    let h = Harness::start(opts()).await;
    h.upstream.as_ref().unwrap().on(
        "up.test.",
        RecordType::A,
        Reply::Answer(vec![a("up.test.", 60, "203.0.113.9")]),
    );
    assert_eq!(
        ask(&h, "www.example.test.", RecordType::A).await,
        Rcode::NoError
    );
    assert_eq!(
        ask(&h, "missing.example.test.", RecordType::A).await,
        Rcode::NxDomain
    );
    assert_eq!(
        ask(&h, "ads.example.net.", RecordType::A).await,
        Rcode::NxDomain
    );
    assert_eq!(ask(&h, "up.test.", RecordType::A).await, Rcode::NoError);
    assert_eq!(ask(&h, "up.test.", RecordType::A).await, Rcode::NoError); // from the cache
    assert_eq!(
        ask(&h, "www.example.test.", RecordType::Aaaa).await,
        Rcode::NoError
    );

    let own = log_entries(&h, "domain=www.example.test", 2).await;
    let a_entry = own
        .iter()
        .find(|e| e["qtype"] == "A")
        .expect("the A query is logged");
    assert_eq!(a_entry["qname"], "www.example.test.");
    assert_eq!(a_entry["transport"], "udp");
    assert_eq!(a_entry["source"], "authoritative");
    assert_eq!(a_entry["client"], "127.0.0.1");
    assert!(a_entry["ts_ms"].as_i64().unwrap() > 1_600_000_000_000);
    assert!(a_entry["latency_us"].is_u64() && a_entry["id"].is_i64());
    assert_eq!(a_entry["dnssec"], "unchecked");
    assert!(own.iter().any(|e| e["qtype"] == "AAAA"));

    assert_eq!(
        log_entries(&h, "source=blocked", 1).await[0]["qname"],
        "ads.example.net."
    );
    let upstream_hits = log_entries(&h, "domain=up.test", 2).await;
    let sources: Vec<_> = upstream_hits
        .iter()
        .map(|e| e["source"].as_str().unwrap())
        .collect();
    assert!(
        sources.contains(&"upstream") && sources.contains(&"cache"),
        "{sources:?}"
    );
    // Newest first.
    let all = log_entries(&h, "limit=500", 6).await;
    let times: Vec<i64> = all.iter().map(|e| e["ts_ms"].as_i64().unwrap()).collect();
    assert!(times.windows(2).all(|w| w[0] >= w[1]), "{times:?}");
}

#[tokio::test]
async fn query_log_filters_combine() {
    let h = Harness::start(opts()).await;
    for (n, t) in [
        ("www.example.test.", RecordType::A),
        ("www.example.test.", RecordType::Aaaa),
        ("txt.example.test.", RecordType::Txt),
        ("nope.example.test.", RecordType::A),
    ] {
        ask(&h, n, t).await;
    }
    log_entries(&h, "limit=500", 4).await;
    let count = |filter: &'static str| {
        let h = &h;
        async move {
            h.rest()
                .get(&format!("/querylog?{filter}"), Auth::Bearer(&h.api_token))
                .await
                .ok(200)["entries"]
                .as_array()
                .unwrap()
                .len()
        }
    };
    assert_eq!(count("type=AAAA").await, 1);
    assert_eq!(count("type=28").await, 1, "types by number");
    assert_eq!(count("outcome=NXDOMAIN").await, 1);
    assert_eq!(
        count("outcome=nxdomain").await,
        1,
        "names are case-insensitive"
    );
    assert_eq!(count("domain=WWW").await, 2, "substring, case-insensitive");
    assert_eq!(count("client=127.0.0.1").await, 4);
    assert_eq!(count("client=10.9.8.7").await, 0);
    assert_eq!(count("domain=www&type=A").await, 1);
    assert_eq!(count("from=0&to=1").await, 0);
    assert_eq!(count("from=0").await, 4);
    assert_eq!(count("source=authoritative&outcome=NOERROR").await, 3);
    assert_eq!(count("domain=%25").await, 0, "wildcards are literal");
}

#[tokio::test]
async fn query_log_paging_walks_every_entry_once() {
    let h = Harness::start(opts()).await;
    for i in 0..7 {
        ask(&h, &format!("n{i}.example.test."), RecordType::A).await;
    }
    log_entries(&h, "domain=example.test&limit=500", 7).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let mut ids = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let url = match &cursor {
            Some(c) => format!("/querylog?limit=3&cursor={c}"),
            None => "/querylog?limit=3".to_owned(),
        };
        let p = api.get(&url, admin).await.ok(200);
        let entries = p["entries"].as_array().unwrap();
        assert!(entries.len() <= 3);
        ids.extend(entries.iter().map(|e| e["id"].as_i64().unwrap()));
        pages += 1;
        match p["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_owned()),
            None => break,
        }
        assert!(pages < 20, "paging terminates");
    }
    assert_eq!(ids.len(), 7);
    let mut unique = ids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 7, "no entry twice: {ids:?}");
    assert!(
        ids.windows(2).all(|w| w[0] > w[1]),
        "ids strictly descend: {ids:?}"
    );
    // A page that exactly fits has no cursor.
    assert!(api.get("/querylog?limit=500", admin).await.ok(200)["next_cursor"].is_null());
}

#[tokio::test]
async fn query_log_parameter_validation() {
    let h = Harness::start(opts()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    for bad in [
        "limit=0",
        "limit=501",
        "limit=x",
        "cursor=garbage",
        "cursor=",
        "type=NOTATYPE",
        "outcome=NOPE",
        "source=sideways",
        "dnssec=maybe",
        "from=abc",
    ] {
        let r = api.get(&format!("/querylog?{bad}"), admin).await;
        assert!(
            matches!(r.status, 400 | 422),
            "{bad}: {} {}",
            r.status,
            r.text
        );
        r.problem(r.status);
    }
    api.get("/querylog?limit=500", admin).await.ok(200);
    api.get("/querylog", Auth::None).await.problem(401);
}

#[tokio::test]
async fn stats_summary_follows_the_traffic() {
    let h = Harness::start(opts()).await;
    h.upstream.as_ref().unwrap().on(
        "up.test.",
        RecordType::A,
        Reply::Answer(vec![a("up.test.", 60, "203.0.113.9")]),
    );
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let before = api.get("/stats/summary", admin).await.ok(200);
    assert_eq!(before["total"], 0);
    assert_eq!(before["blocked_ratio"], 0.0);

    for _ in 0..3 {
        ask(&h, "www.example.test.", RecordType::A).await;
    }
    ask(&h, "ads.example.net.", RecordType::A).await;
    ask(&h, "missing.example.test.", RecordType::A).await;
    ask(&h, "up.test.", RecordType::A).await;
    ask(&h, "up.test.", RecordType::A).await;

    let s = eventually(WAIT, "the summary to count 7 queries", || async {
        let s = api.get("/stats/summary", admin).await.ok(200);
        (s["total"] == 7).then_some(s)
    })
    .await;
    assert_eq!(s["blocked"], 1);
    assert!(
        (s["blocked_ratio"].as_f64().unwrap() - 1.0 / 7.0).abs() < 1e-9,
        "{s}"
    );
    assert_eq!(s["by_source"]["authoritative"], 4);
    assert_eq!(s["by_source"]["blocked"], 1);
    assert_eq!(s["by_source"]["upstream"], 1);
    assert_eq!(s["by_source"]["cache"], 1);
    assert_eq!(
        s["by_rcode"]
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_u64().unwrap())
            .sum::<u64>(),
        7
    );
    assert_eq!(s["cache_hits"], 1);
    assert!(s["max_latency_us"].as_u64().unwrap() >= s["avg_latency_us"].as_u64().unwrap());
    assert!(s["from"].as_i64().unwrap() < s["to"].as_i64().unwrap());
}

#[tokio::test]
async fn stats_top_lists_and_timeseries() {
    let h = Harness::start(opts()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    for _ in 0..3 {
        ask(&h, "www.example.test.", RecordType::A).await;
    }
    ask(&h, "txt.example.test.", RecordType::Txt).await;
    for _ in 0..2 {
        ask(&h, "ads.example.net.", RecordType::A).await;
    }
    eventually(WAIT, "the top list", || async {
        let t = api.get("/stats/top-domains", admin).await.ok(200);
        (t.as_array()
            .unwrap()
            .iter()
            .map(|i| i["count"].as_u64().unwrap())
            .sum::<u64>()
            == 6)
            .then_some(())
    })
    .await;
    let top = api.get("/stats/top-domains?limit=2", admin).await.ok(200);
    let top = top.as_array().unwrap();
    assert_eq!(top.len(), 2);
    assert_eq!(
        (top[0]["key"].as_str(), top[0]["count"].as_u64()),
        (Some("www.example.test."), Some(3))
    );
    assert_eq!(top[1]["count"], 2);
    let blocked = api.get("/stats/top-blocked", admin).await.ok(200);
    assert_eq!(
        (blocked[0]["key"].as_str(), blocked[0]["count"].as_u64()),
        (Some("ads.example.net."), Some(2))
    );
    assert_eq!(blocked.as_array().unwrap().len(), 1);
    let clients = api.get("/stats/top-clients", admin).await.ok(200);
    assert_eq!(
        (clients[0]["key"].as_str(), clients[0]["count"].as_u64()),
        (Some("127.0.0.1"), Some(6))
    );

    let series = api.get("/stats/timeseries?bucket=60", admin).await.ok(200);
    let total: u64 = series
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["total"].as_u64().unwrap())
        .sum();
    assert_eq!(total, 6);
    assert!(
        series
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["start_ms"].as_i64().unwrap() % 60_000 == 0)
    );
    assert_eq!(
        series
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["blocked"].as_u64().unwrap())
            .sum::<u64>(),
        2
    );
}

#[tokio::test]
async fn stats_parameter_validation() {
    let h = Harness::start(opts()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    for bad in [
        "/stats/summary?from=2000&to=1000",
        "/stats/summary?from=1000&to=1000",
        "/stats/summary?from=0&to=99999999999999",
        "/stats/summary?from=abc",
        "/stats/timeseries?bucket=0",
        "/stats/timeseries?bucket=61",
        "/stats/timeseries?bucket=60&from=0&to=99999999999",
        "/stats/top-domains?limit=0",
        "/stats/top-domains?limit=101",
        "/stats/top-clients?limit=-1",
    ] {
        let r = api.get(bad, admin).await;
        assert!(
            matches!(r.status, 400 | 422),
            "{bad}: {} {}",
            r.status,
            r.text
        );
        r.problem(r.status);
    }
    for ok in [
        "/stats/summary",
        "/stats/top-domains?limit=100",
        "/stats/timeseries?bucket=300",
        "/stats/top-blocked?limit=1",
    ] {
        api.get(ok, admin).await.ok(200);
    }
}

#[tokio::test]
async fn live_tail_streams_new_queries_as_server_sent_events() {
    let h = Harness::start(opts()).await;
    let api = h.rest();
    let mut stream = api
        .req(reqwest::Method::GET, "/querylog/stream")
        .bearer(&h.api_token)
        .stream()
        .await;
    assert_eq!(stream.status, 200);
    let ct = stream
        .headers
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/event-stream"), "{ct}");

    // Queries made after the stream opened arrive as `query` events; poll by re-asking until the
    // first one is seen (the tail follows the log at its own pace).
    ask(&h, "tail-one.example.test.", RecordType::A).await;
    let (event, data) = stream.next_event(WAIT).await;
    assert_eq!(event, "query");
    let rec: Value = serde_json::from_str(&data).expect("event data is JSON");
    assert_eq!(rec["qname"], "tail-one.example.test.");
    assert_eq!(rec["rcode"], "NXDOMAIN");

    ask(&h, "tail-two.example.test.", RecordType::A).await;
    ask(&h, "tail-three.example.test.", RecordType::A).await;
    let mut names = Vec::new();
    while names.len() < 2 {
        let (event, data) = stream.next_event(WAIT).await;
        assert_eq!(event, "query");
        names.push(
            serde_json::from_str::<Value>(&data).unwrap()["qname"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    names.sort();
    assert_eq!(
        names,
        ["tail-three.example.test.", "tail-two.example.test."]
    );
}

#[tokio::test]
async fn live_tail_honours_filters_and_credentials() {
    let h = Harness::start(opts()).await;
    let api = h.rest();
    let viewer = api
        .token_for(&h.api_token, "wanda", "viewer", &["api:read"])
        .await;
    api.req(reqwest::Method::GET, "/querylog/stream")
        .bearer(&viewer)
        .send()
        .await
        .problem(403);
    api.req(reqwest::Method::GET, "/querylog/stream")
        .send()
        .await
        .problem(401);
    api.req(reqwest::Method::GET, "/querylog/stream?type=bogus")
        .bearer(&h.api_token)
        .send()
        .await
        .problem(400);

    let mut stream = api
        .req(reqwest::Method::GET, "/querylog/stream?source=blocked")
        .bearer(&h.api_token)
        .stream()
        .await;
    assert_eq!(stream.status, 200);
    ask(&h, "www.example.test.", RecordType::A).await;
    ask(&h, "ads.example.net.", RecordType::A).await;
    let (_, data) = stream.next_event(WAIT).await;
    let rec: Value = serde_json::from_str(&data).unwrap();
    assert_eq!(
        rec["qname"], "ads.example.net.",
        "the unblocked query is filtered out"
    );
    assert_eq!(rec["source"], "blocked");
}
