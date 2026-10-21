//! Query log, live tail, stats and cache endpoints.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode};
use dnsy_core::{DnssecStatus, Role, Scope, Transport};
use dnsy_observe::{AnswerSource, QueryEvent, QueryEventSink, QueryLogWriter, WriterConfig};
use dnsy_proto::{
    Class, Header, Message, Name, Opcode, Question, RData, Rcode, Record, RecordType,
};
use dnsy_resolver::{Cache, CacheKey};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::{ApiConfig, ApiState, router};

struct Fx {
    state: ApiState,
    _dir: tempfile::TempDir,
}

impl Fx {
    fn new(f: impl FnOnce(ApiState) -> ApiState) -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
        let mut state = f(ApiState::new(store));
        state.observe.live_tail_poll = Duration::from_millis(20);
        Fx { state, _dir: dir }
    }

    fn app(&self) -> Router {
        router(
            self.state.clone(),
            ApiConfig {
                tls: false,
                ..ApiConfig::default()
            },
        )
    }

    async fn token(&self, name: &str, role: Role, scopes: &[Scope]) -> String {
        let user = self
            .state
            .auth
            .users
            .create(name, "pw-pw-pw", role)
            .await
            .unwrap();
        self.state
            .auth
            .tokens
            .create(user.id, "t", scopes, None)
            .await
            .unwrap()
            .0
    }

    async fn viewer(&self) -> String {
        self.token("viewer", Role::Viewer, &[Scope::ApiRead]).await
    }

    async fn operator(&self) -> String {
        self.token("op", Role::Operator, &[Scope::ApiRead, Scope::ApiWrite])
            .await
    }

    async fn call(&self, method: Method, uri: &str, token: Option<&str>) -> Response<Body> {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        self.app()
            .oneshot(b.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn get_json(&self, uri: &str, token: &str) -> (StatusCode, serde_json::Value) {
        let res = self.call(Method::GET, uri, Some(token)).await;
        let status = res.status();
        (status, json(res).await)
    }

    async fn ingest(&self, events: Vec<QueryEvent>) {
        let (w, task) = QueryLogWriter::spawn(
            self.state.observe.store.clone(),
            WriterConfig {
                flush_interval: Duration::from_millis(5),
                redact_client_ip: self.state.observe.redact_client_ip,
                ..WriterConfig::default()
            },
        );
        for e in events {
            w.record(e);
        }
        drop(w);
        task.await.unwrap();
    }
}

async fn json(res: Response<Body>) -> serde_json::Value {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

fn event(qname: &str, ts_ms: i64) -> QueryEvent {
    QueryEvent {
        ts_unix_ms: ts_ms,
        client: "192.0.2.77".parse().unwrap(),
        transport: Transport::Udp,
        principal: None,
        qname: Name::from_ascii(qname).unwrap(),
        qtype: RecordType::A,
        rcode: Rcode::NoError,
        source: AnswerSource::Upstream("198.51.100.1:53".parse().unwrap()),
        dnssec: DnssecStatus::Unchecked,
        latency_us: 1000,
    }
}

fn name_at(entries: &serde_json::Value) -> Vec<String> {
    entries["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["qname"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn querylog_filters_and_cursor() {
    let f = Fx::new(|s| s);
    let t = f.viewer().await;
    let base = now_ms();
    let mut blocked = event("ads.example.", base + 2);
    blocked.source = AnswerSource::Blocked { list: "ads".into() };
    blocked.rcode = Rcode::NxDomain;
    blocked.qtype = RecordType::Aaaa;
    blocked.client = "192.0.2.9".parse().unwrap();
    let mut secure = event("secure.example.", base + 3);
    secure.dnssec = DnssecStatus::Secure;
    secure.source = AnswerSource::CacheStale;
    f.ingest(vec![
        event("a.example.", base),
        event("b.example.", base + 1),
        blocked,
        secure,
    ])
    .await;

    // Keyset pagination: newest first, no overlap, last page has no cursor.
    let (st, p1) = f.get_json("/api/v1/querylog?limit=3", &t).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        name_at(&p1),
        ["secure.example.", "ads.example.", "b.example."]
    );
    let cursor = p1["next_cursor"].as_str().unwrap();
    let (_, p2) = f
        .get_json(&format!("/api/v1/querylog?limit=3&cursor={cursor}"), &t)
        .await;
    assert_eq!(name_at(&p2), ["a.example."]);
    assert!(p2["next_cursor"].is_null());

    let q = |qs: &str| format!("/api/v1/querylog?{qs}");
    for (qs, want) in [
        ("type=AAAA", vec!["ads.example."]),
        ("type=28", vec!["ads.example."]),
        ("outcome=nxdomain", vec!["ads.example."]),
        ("source=blocked", vec!["ads.example."]),
        ("source=cache_stale", vec!["secure.example."]),
        ("dnssec=secure", vec!["secure.example."]),
        ("client=192.0.2.9", vec!["ads.example."]),
        ("domain=B.EXA", vec!["b.example."]),
    ] {
        let (st, body) = f.get_json(&q(qs), &t).await;
        assert_eq!(st, StatusCode::OK, "{qs}");
        assert_eq!(name_at(&body), want, "{qs}");
    }
    let from = base + 1;
    let to = base + 3;
    let (_, body) = f.get_json(&q(&format!("from={from}&to={to}")), &t).await;
    assert_eq!(name_at(&body), ["ads.example.", "b.example."]);

    let e = &p1["entries"][1];
    assert_eq!(e["qtype"], "AAAA");
    assert_eq!(e["rcode"], "NXDOMAIN");
    assert_eq!(e["source"], "blocked");
    assert_eq!(e["source_detail"], "ads");
}

#[tokio::test]
async fn querylog_rejects_bad_input() {
    let f = Fx::new(|s| s);
    let t = f.viewer().await;
    for qs in [
        "limit=0",
        "limit=501",
        "cursor=garbage",
        "type=NOPE",
        "outcome=NOPE",
        "source=nope",
        "dnssec=nope",
        "client=not-an-ip",
        "from=10&to=10",
    ] {
        let res = f
            .call(Method::GET, &format!("/api/v1/querylog?{qs}"), Some(&t))
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{qs}");
    }
    let res = f.call(Method::GET, "/api/v1/querylog", None).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

async fn next_event(body: &mut Body) -> String {
    let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("an SSE frame in time")
        .unwrap()
        .unwrap();
    String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap()
}

#[tokio::test]
async fn sse_stream_emits_new_events() {
    let f = Fx::new(|s| s);
    let t = f.operator().await;
    f.ingest(vec![event("old.example.", now_ms())]).await;
    let res = f
        .call(Method::GET, "/api/v1/querylog/stream?domain=live", Some(&t))
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["content-type"], "text/event-stream");
    let mut body = res.into_body();

    f.ingest(vec![
        event("other.example.", now_ms()),
        event("live1.example.", now_ms()),
        event("live2.example.", now_ms()),
    ])
    .await;
    let first = next_event(&mut body).await;
    assert!(first.contains("event: query"), "{first}");
    assert!(first.contains("live1.example."), "{first}");
    assert!(!first.contains("old.example."));
    let second = next_event(&mut body).await;
    assert!(second.contains("live2.example."), "{second}");
}

#[tokio::test]
async fn sse_requires_write_scope_and_is_capped() {
    let f = Fx::new(|s| s.with_live_tail_limits(1, 1, 0));
    let viewer = f.viewer().await;
    let res = f
        .call(Method::GET, "/api/v1/querylog/stream", Some(&viewer))
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let op = f.operator().await;
    let first = f
        .call(Method::GET, "/api/v1/querylog/stream", Some(&op))
        .await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = f
        .call(Method::GET, "/api/v1/querylog/stream", Some(&op))
        .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    // Closing the stream frees the slot.
    drop(first);
    let third = f
        .call(Method::GET, "/api/v1/querylog/stream", Some(&op))
        .await;
    assert_eq!(third.status(), StatusCode::OK);
}

#[tokio::test]
async fn stats_top_domains_shape() {
    let f = Fx::new(|s| s);
    let t = f.viewer().await;
    let now = now_ms();
    let mut blocked = event("ads.example.", now);
    blocked.source = AnswerSource::Blocked { list: "ads".into() };
    f.ingest(vec![
        event("a.example.", now),
        event("a.example.", now),
        event("b.example.", now),
        blocked,
    ])
    .await;

    let (st, top) = f.get_json("/api/v1/stats/top-domains?limit=2", &t).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(top.as_array().unwrap().len(), 2);
    assert_eq!(top[0]["key"], "a.example.");
    assert_eq!(top[0]["count"], 2);

    let (_, blocked) = f.get_json("/api/v1/stats/top-blocked", &t).await;
    assert_eq!(blocked[0]["key"], "ads.example.");
    let (_, clients) = f.get_json("/api/v1/stats/top-clients", &t).await;
    assert_eq!(clients[0]["key"], "192.0.2.77");
    assert_eq!(clients[0]["count"], 4);

    let (_, s) = f.get_json("/api/v1/stats/summary", &t).await;
    assert_eq!(s["total"], 4);
    assert_eq!(s["blocked"], 1);
    assert!((s["blocked_ratio"].as_f64().unwrap() - 0.25).abs() < 1e-9);
    assert_eq!(s["by_source"]["upstream"], 3);
    assert_eq!(s["dnssec"]["unchecked"], 4);
    assert_eq!(s["avg_latency_us"], 1000);
    assert_eq!(s["querylog_dropped"], 0);
    assert_eq!(s["querylog_flush_errors"], 0);

    let (_, series) = f.get_json("/api/v1/stats/timeseries?bucket=60", &t).await;
    assert_eq!(series[0]["total"], 4);
    assert_eq!(series[0]["blocked"], 1);
}

#[tokio::test]
async fn invalid_range_400() {
    let f = Fx::new(|s| s);
    let t = f.operator().await;
    for uri in [
        "/api/v1/stats/summary?from=100&to=100",
        "/api/v1/stats/summary?from=200&to=100",
        "/api/v1/stats/summary?from=0&to=99999999999999",
        "/api/v1/stats/top-domains?limit=0",
        "/api/v1/stats/top-clients?limit=101",
        "/api/v1/stats/timeseries?bucket=90",
        "/api/v1/stats/timeseries?bucket=0",
        "/api/v1/stats/timeseries?from=0&to=31536000000&bucket=60",
        "/api/v1/stats/summary?from=abc",
        "/api/v1/stats/summary?from=-9223372036854775808&to=9223372036854775807",
        "/api/v1/stats/summary?from=-9223372036854775808&to=100",
        "/api/v1/stats/summary?from=0&to=9223372036854775807",
        "/api/v1/stats/summary?to=-9223372036854775808",
        "/api/v1/stats/top-domains?from=9223372036854775807&to=9223372036854775807",
        "/api/v1/stats/timeseries?from=-9223372036854775808&to=9223372036854775807&bucket=60",
        "/api/v1/stats/timeseries?from=0&to=60000&bucket=18446744073709551615",
        "/api/v1/querylog?from=-9223372036854775808",
        "/api/v1/querylog?to=9223372036854775807",
        "/api/v1/querylog/stream?from=-9223372036854775808",
    ] {
        let res = f.call(Method::GET, uri, Some(&t)).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "{uri}");
        if !uri.ends_with("abc") {
            assert_eq!(res.headers()["content-type"], "application/problem+json");
        }
    }
    let res = f.call(Method::GET, "/api/v1/stats/summary", None).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

fn cache_with(names: &[&str]) -> Arc<Cache> {
    let cache = Arc::new(Cache::new(dnsy_resolver::CacheOptions::default()));
    for n in names {
        let name = Name::from_ascii(n).unwrap();
        let msg = Message {
            header: Header {
                id: 1,
                qr: true,
                opcode: Opcode::Query,
                aa: false,
                tc: false,
                rd: true,
                ra: true,
                ad: false,
                cd: false,
                rcode: Rcode::NoError,
            },
            questions: vec![Question {
                name: name.clone(),
                qtype: RecordType::A,
                qclass: Class::In,
            }],
            answers: vec![Record {
                name: name.clone(),
                rtype: RecordType::A,
                class: Class::In,
                ttl: 300,
                data: RData::A([192, 0, 2, 1].into()),
            }],
            authority: Vec::new(),
            additional: Vec::new(),
            edns: None,
        };
        let key = CacheKey {
            name,
            qtype: RecordType::A,
            qclass: Class::In,
            do_bit: false,
            cd_bit: false,
        };
        cache.insert(
            key,
            &msg,
            DnssecStatus::Unchecked,
            std::time::Instant::now(),
        );
    }
    cache
}

#[tokio::test]
async fn cache_stats_shape() {
    let cache = cache_with(&["a.example.", "b.example."]);
    let f = Fx::new(|s| s.with_cache(cache));
    let t = f.viewer().await;
    let (st, body) = f.get_json("/api/v1/cache", &t).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["entries"], 2);
    assert_eq!(body["capacity"], 100_000);
    assert_eq!(body["inserts"], 2);
    assert_eq!(body["hit_ratio"], 0.0);
    for k in [
        "hits",
        "misses",
        "evictions",
        "expired",
        "stale_served",
        "prefetches",
    ] {
        assert!(body[k].is_u64(), "{k}");
    }
}

#[tokio::test]
async fn cache_unavailable_without_cache() {
    let f = Fx::new(|s| s);
    let t = f.operator().await;
    let res = f.call(Method::GET, "/api/v1/cache", Some(&t)).await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let res = f.call(Method::DELETE, "/api/v1/cache", Some(&t)).await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn cache_flush_all_requires_write_scope() {
    let cache = cache_with(&["a.example.", "b.example."]);
    let f = Fx::new(|s| s.with_cache(cache.clone()));
    let viewer = f.viewer().await;
    let res = f.call(Method::DELETE, "/api/v1/cache", Some(&viewer)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = f.call(Method::DELETE, "/api/v1/cache", None).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // A read-only token of an operator is refused too.
    let ro = f.token("ro-op", Role::Operator, &[Scope::ApiRead]).await;
    let res = f.call(Method::DELETE, "/api/v1/cache", Some(&ro)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(cache.stats().entries, 2);

    let op = f.operator().await;
    let res = f.call(Method::DELETE, "/api/v1/cache", Some(&op)).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(json(res).await["removed"], 2);
    assert_eq!(cache.stats().entries, 0);
}

#[tokio::test]
async fn cache_flush_by_name_counts() {
    let cache = cache_with(&["a.example.", "www.a.example.", "b.example."]);
    let f = Fx::new(|s| s.with_cache(cache.clone()));
    let op = f.operator().await;
    let del = |qs: &'static str| {
        let (f, op) = (&f, &op);
        async move {
            let res = f
                .call(
                    Method::DELETE,
                    &format!("/api/v1/cache/entries?{qs}"),
                    Some(op),
                )
                .await;
            (res.status(), json(res).await)
        }
    };
    let (st, body) = del("name=A.Example").await;
    assert_eq!((st, body["removed"].as_u64()), (StatusCode::OK, Some(1)));
    let (_, body) = del("name=a.example.").await;
    assert_eq!(body["removed"], 0);
    let (_, body) = del("name=example.&subtree=true").await;
    assert_eq!(body["removed"], 2);
    assert_eq!(cache.stats().entries, 0);
    assert_eq!(del("name=").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(del("subtree=true").await.0, StatusCode::BAD_REQUEST);
    let viewer = f.viewer().await;
    let res = f
        .call(
            Method::DELETE,
            "/api/v1/cache/entries?name=x",
            Some(&viewer),
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn client_ips_are_redacted_when_configured() {
    let f = Fx::new(|s| s.with_redact_client_ip(true));
    let t = f.viewer().await;
    f.ingest(vec![event("a.example.", now_ms())]).await;

    let (_, log) = f.get_json("/api/v1/querylog", &t).await;
    assert_eq!(log["entries"][0]["client"], "192.0.2.0");
    // Filtering by the full address finds the redacted row.
    let (_, log) = f.get_json("/api/v1/querylog?client=192.0.2.77", &t).await;
    assert_eq!(log["entries"].as_array().unwrap().len(), 1);
    let (_, top) = f.get_json("/api/v1/stats/top-clients", &t).await;
    assert_eq!(top[0]["key"], "192.0.2.0");

    // Rows written unredacted (setting turned on later) are still shown redacted.
    let g = Fx::new(|s| s);
    g.ingest(vec![event("a.example.", now_ms())]).await;
    let mut state = g.state.clone();
    state.observe.redact_client_ip = true;
    let app = router(
        state,
        ApiConfig {
            tls: false,
            ..ApiConfig::default()
        },
    );
    let tk = g.viewer().await;
    let req = Request::builder()
        .uri("/api/v1/querylog")
        .header("authorization", format!("Bearer {tk}"))
        .body(Body::empty())
        .unwrap();
    let body = json(app.oneshot(req).await.unwrap()).await;
    assert_eq!(body["entries"][0]["client"], "192.0.2.0");
}

#[tokio::test]
async fn tokens_never_leak_through_log_or_stats() {
    let f = Fx::new(|s| s);
    let secret = format!("dnsy_{}_{}", "ABCDEFGHIJKLM", "x".repeat(43));
    let mut e = event("a.example.", now_ms());
    e.principal = Some(format!("doh:{secret}"));
    e.source = AnswerSource::Blocked {
        list: format!("list-{secret}"),
    };
    let mut leaky = event(&format!("{secret}.example."), now_ms());
    leaky.client = "192.0.2.78".parse().unwrap();
    f.ingest(vec![e, leaky]).await;
    let t = f.operator().await;

    for uri in [
        "/api/v1/querylog",
        "/api/v1/stats/top-domains",
        "/api/v1/stats/top-blocked",
        "/api/v1/stats/summary",
    ] {
        let res = f.call(Method::GET, uri, Some(&t)).await;
        let text = String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec())
            .unwrap();
        assert!(!text.contains(&secret), "{uri} leaked a token: {text}");
        assert!(!text.contains("ABCDEFGHIJKLM"), "{uri}");
    }
    let res = f.call(Method::GET, "/api/v1/querylog", Some(&t)).await;
    assert!(json(res).await.to_string().contains("[redacted]"));

    // The live tail goes through the same conversion.
    let res = f
        .call(Method::GET, "/api/v1/querylog/stream", Some(&t))
        .await;
    let mut body = res.into_body();
    let mut leaky = event(&format!("{secret}.example."), now_ms());
    leaky.principal = Some(secret.clone());
    f.ingest(vec![leaky]).await;
    let ev = next_event(&mut body).await;
    assert!(ev.contains("[redacted]") && !ev.contains(&secret), "{ev}");
}

#[tokio::test]
async fn summary_reports_lost_query_log_events() {
    let f = Fx::new(|s| s);
    let t = f.viewer().await;
    f.state
        .observe
        .store
        .write(|tx| Ok(tx.execute_batch("DROP TABLE query_log")?))
        .await
        .unwrap();
    f.ingest(vec![
        event("a.example.", now_ms()),
        event("b.example.", now_ms()),
    ])
    .await;
    let (st, s) = f.get_json("/api/v1/stats/summary", &t).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(s["querylog_dropped"], 2);
    assert_eq!(s["querylog_flush_errors"], 1);
}

#[tokio::test]
async fn live_tail_cap_is_per_principal() {
    let f = Fx::new(|s| s.with_live_tail_limits(8, 2, 0));
    let a = f
        .token("op-a", Role::Operator, &[Scope::ApiRead, Scope::ApiWrite])
        .await;
    let b = f
        .token("op-b", Role::Operator, &[Scope::ApiRead, Scope::ApiWrite])
        .await;
    let uri = "/api/v1/querylog/stream";
    let a1 = f.call(Method::GET, uri, Some(&a)).await;
    let a2 = f.call(Method::GET, uri, Some(&a)).await;
    assert_eq!(a1.status(), StatusCode::OK);
    assert_eq!(a2.status(), StatusCode::OK);
    let a3 = f.call(Method::GET, uri, Some(&a)).await;
    assert_eq!(a3.status(), StatusCode::TOO_MANY_REQUESTS);
    // Another principal is unaffected, and a closed stream frees its owner's slot.
    assert_eq!(
        f.call(Method::GET, uri, Some(&b)).await.status(),
        StatusCode::OK
    );
    drop(a1);
    assert_eq!(
        f.call(Method::GET, uri, Some(&a)).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn live_tail_keeps_a_reservation_for_admins() {
    let f = Fx::new(|s| s.with_live_tail_limits(2, 2, 1));
    let op = f
        .token("op", Role::Operator, &[Scope::ApiRead, Scope::ApiWrite])
        .await;
    let admin = f
        .token("root", Role::Admin, &[Scope::ApiRead, Scope::ApiWrite])
        .await;
    let uri = "/api/v1/querylog/stream";
    let _first = f.call(Method::GET, uri, Some(&op)).await;
    assert_eq!(
        f.call(Method::GET, uri, Some(&op)).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        f.call(Method::GET, uri, Some(&admin)).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn readyz_warns_while_the_query_log_disk_is_full() {
    let fx = Fx::new(|s| s);
    let pages: i64 = fx
        .state
        .observe
        .store
        .write(|t| Ok(t.query_row("PRAGMA page_count", [], |r| r.get(0))?))
        .await
        .unwrap();
    fx.state
        .observe
        .store
        .write(move |t| Ok(t.execute_batch(&format!("PRAGMA max_page_count = {pages}"))?))
        .await
        .unwrap();
    let (w, task) = QueryLogWriter::spawn(
        fx.state.observe.store.clone(),
        WriterConfig {
            flush_interval: Duration::from_millis(5),
            ..WriterConfig::default()
        },
    );
    let ready = || async {
        let res = fx.call(Method::GET, "/readyz", None).await;
        assert_eq!(res.status(), StatusCode::OK);
        json(res).await
    };
    assert!(ready().await.get("warnings").is_none());
    for i in 0..400 {
        w.record(event(&format!("host{i}.example."), i));
    }
    let mut full = false;
    for _ in 0..200 {
        if ready().await["warnings"][0] == "querylog_disk_full" {
            full = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(full, "readyz never reported querylog_disk_full");

    fx.state
        .observe
        .store
        .write(|t| Ok(t.execute_batch("PRAGMA max_page_count = 1073741823")?))
        .await
        .unwrap();
    for _ in 0..200 {
        w.record(event("ok.example.", 1));
        if ready().await.get("warnings").is_none() {
            drop(w);
            task.await.unwrap();
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the warning never cleared");
}
