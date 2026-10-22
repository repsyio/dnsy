//! ACL, upstream, blocklist, rule, client-certificate and settings routes against a real engine.
#![expect(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "end-to-end route tests read top to bottom"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use dnsy_config::Config;
use dnsy_core::{DnssecStatus, Role, Scope, SystemClock, Transport};
use dnsy_engine::{Engine, EngineBuilder, RequestContext, Services};
use dnsy_filter::{Fetcher, FilterLimits, ListManager, SourceStore};
use dnsy_proto::{
    Class, Header, Message, Name, Opcode, Question, RData, Rcode, Record, RecordType,
};
use dnsy_resolver::groups::{Exchange, GroupMember, GroupSet, GroupSpec, Strategy, ThreadRng};
use dnsy_resolver::{CacheKey, Upstream, UpstreamClient, UpstreamConfig, UpstreamError};
use serde_json::{Value, json};
use tower::ServiceExt;

use dnsy_api::{ApiConfig, ApiState, build};

struct Fx {
    app: Router,
    engine: Arc<Engine>,
    state: ApiState,
    admin: String,
    operator: String,
    viewer: String,
    reloads: Arc<AtomicUsize>,
    dir: tempfile::TempDir,
}

fn default_group() -> GroupSet {
    GroupSet::new(
        vec![GroupSpec {
            name: "default".to_owned(),
            strategy: Strategy::Failover,
            default: true,
            domains: vec![],
            members: vec![GroupMember {
                upstream: "udp://192.0.2.1:53".parse().unwrap(),
                weight: 1,
            }],
        }],
        Arc::new(SystemClock),
        Arc::new(ThreadRng),
    )
    .unwrap()
}

async fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let config = Config::default();
    let manager = ListManager::new(
        SourceStore::new(store.clone()),
        dnsy_filter::BlockMode::NullIp,
        FilterLimits::default(),
        Fetcher::new(1 << 20, std::time::Duration::from_secs(5)),
        Arc::new(SystemClock),
    );
    let client = UpstreamClient::new(UpstreamConfig::default()).unwrap();
    let mut services = Services::bare(&config);
    services.lists = Some(manager);
    services.groups.store(Some(Arc::new(default_group())));
    let engine = Arc::new(
        EngineBuilder::new(&config, client)
            .services(&services)
            .build(),
    );
    let reloads = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reloads);
    let state = ApiState::new(store)
        .with_services(&services)
        .with_policy(Arc::clone(&engine) as Arc<dyn dnsy_engine::LivePolicy>)
        .with_config(&config)
        .with_cert_reload(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }));
    let mut tokens = Vec::new();
    for (user, role, scopes) in [
        (
            "admin",
            Role::Admin,
            vec![Scope::ApiRead, Scope::ApiWrite, Scope::Admin],
        ),
        ("op", Role::Operator, vec![Scope::ApiRead, Scope::ApiWrite]),
        ("viewer", Role::Viewer, vec![Scope::ApiRead]),
    ] {
        let u = state
            .auth
            .users
            .create(user, "pw-pw-pw", role)
            .await
            .unwrap();
        tokens.push(
            state
                .auth
                .tokens
                .create(u.id, "t", &scopes, None)
                .await
                .unwrap()
                .0,
        );
    }
    let app = build(
        state.clone(),
        ApiConfig {
            tls: false,
            ..ApiConfig::default()
        },
        Router::new(),
    );
    let viewer = tokens.pop().unwrap();
    let operator = tokens.pop().unwrap();
    let admin = tokens.pop().unwrap();
    Fx {
        app,
        engine,
        state,
        admin,
        operator,
        viewer,
        reloads,
        dir,
    }
}

async fn call(
    fx: &Fx,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let b = Request::builder()
        .method(method)
        .uri(format!("/api/v1{uri}"))
        .header("authorization", format!("Bearer {token}"));
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string())),
        None => b.body(Body::empty()),
    }
    .unwrap();
    let res = fx.app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn query(qname: &str) -> Message {
    Message {
        header: Header {
            id: 7,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
        },
        questions: vec![Question {
            name: name(qname),
            qtype: RecordType::A,
            qclass: Class::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
        edns: None,
    }
}

async fn ask(fx: &Fx, client: [u8; 4], qname: &str) -> Option<Message> {
    let ctx = RequestContext {
        client: (client, 40000).into(),
        transport: Transport::Udp,
        principal: None,
        received_at: Instant::now(),
    };
    fx.engine.process(&ctx, &query(qname)).await
}

async fn answer_count(fx: &Fx, client: [u8; 4], qname: &str) -> usize {
    ask(fx, client, qname).await.unwrap().answers.len()
}

#[tokio::test]
async fn acl_crud_applies_live() {
    let f = fx().await;
    let a = f.admin.clone();
    // Not blocked yet: the query reaches the (unreachable) upstream and fails, but not REFUSED.
    let before = ask(&f, [192, 0, 2, 9], "x.test.").await.unwrap();
    assert_ne!(before.header.rcode, Rcode::Refused);

    let (s, rule) = call(
        &f,
        &a,
        Method::POST,
        "/acl",
        Some(json!({"cidr": "192.0.2.0/24", "action": "refuse", "comment": "lab"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(rule["cidr"], "192.0.2.0/24");
    let after = ask(&f, [192, 0, 2, 9], "x.test.").await.unwrap();
    assert_eq!(after.header.rcode, Rcode::Refused);

    // A single address with drop beats the /24 (longest prefix) and sends nothing.
    let (s, host) = call(
        &f,
        &a,
        Method::POST,
        "/acl",
        Some(json!({"cidr": "192.0.2.9", "action": "drop"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(ask(&f, [192, 0, 2, 9], "x.test.").await.is_none());

    let (s, dup) = call(
        &f,
        &a,
        Method::POST,
        "/acl",
        Some(json!({"cidr": "192.0.2.9/32", "action": "drop"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{dup}");

    let (s, list) = call(&f, &a, Method::GET, "/acl", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list["rules"].as_array().unwrap().len(), 2);
    assert_eq!(list["default_action"], "allow");

    let id = host["id"].as_i64().unwrap();
    let (s, _) = call(&f, &a, Method::DELETE, &format!("/acl/{id}"), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        ask(&f, [192, 0, 2, 9], "x.test.")
            .await
            .unwrap()
            .header
            .rcode,
        Rcode::Refused
    );
    let (s, _) = call(&f, &a, Method::DELETE, &format!("/acl/{id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let rid = rule["id"].as_i64().unwrap();
    call(&f, &a, Method::DELETE, &format!("/acl/{rid}"), None).await;
    assert_ne!(
        ask(&f, [192, 0, 2, 9], "x.test.")
            .await
            .unwrap()
            .header
            .rcode,
        Rcode::Refused
    );
}

#[tokio::test]
async fn acl_validation_and_authorisation() {
    let f = fx().await;
    for body in [
        json!({"cidr": "not-an-ip", "action": "refuse"}),
        json!({"action": "refuse"}),
        json!({"cidr": "10.0.0.0/8", "client_cert_sha256": "00", "action": "refuse"}),
        json!({"client_cert_sha256": "zz", "action": "refuse"}),
        json!({"cidr": "10.0.0.0/8", "action": "refuse", "comment": "x".repeat(300)}),
    ] {
        let (s, _) = call(&f, &f.operator, Method::POST, "/acl", Some(body)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let fp = "ab".repeat(32);
    let (s, v) = call(
        &f,
        &f.operator,
        Method::POST,
        "/acl",
        Some(json!({"client_cert_sha256": fp, "action": "allow"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(v["client_cert_sha256"], fp);
    let (s, _) = call(
        &f,
        &f.viewer,
        Method::POST,
        "/acl",
        Some(json!({"cidr": "10.0.0.0/8", "action": "refuse"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&f, &f.viewer, Method::GET, "/acl", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&f, "bogus", Method::GET, "/acl", None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limit_is_persisted_and_applied() {
    let f = fx().await;
    let (s, _) = call(
        &f,
        &f.operator,
        Method::PUT,
        "/acl/rate-limit",
        Some(json!({"qps": 5})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        f.state.stores.rules.rate_limit_qps().await.unwrap(),
        Some(5)
    );
    let (_, acl) = call(&f, &f.viewer, Method::GET, "/acl", None).await;
    assert_eq!(acl["rate_limit_qps"], 5);
    let (_, settings) = call(&f, &f.admin, Method::GET, "/settings", None).await;
    assert_eq!(settings["limits"]["per_client_qps"], 5);
    let (s, _) = call(
        &f,
        &f.operator,
        Method::PUT,
        "/acl/rate-limit",
        Some(json!({"qps": 5_000_000})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    // Burst is 2 x qps: the third immediate query from one client is limited (dropped on UDP).
    call(
        &f,
        &f.operator,
        Method::PUT,
        "/acl/rate-limit",
        Some(json!({"qps": 1})),
    )
    .await;
    // A blocked name answers instantly, so no tokens refill between queries.
    call(
        &f,
        &f.operator,
        Method::POST,
        "/rules",
        Some(json!({"kind": "block", "domain": "r.test"})),
    )
    .await;
    let mut dropped = false;
    for _ in 0..5 {
        dropped |= ask(&f, [198, 51, 100, 1], "r.test.").await.is_none();
    }
    assert!(dropped);
}

struct Down;

impl Exchange for Down {
    fn exchange(
        &self,
        _: &Upstream,
        _: &Message,
    ) -> impl std::future::Future<Output = Result<Message, UpstreamError>> + Send {
        std::future::ready(Err(UpstreamError::Timeout))
    }
}

#[tokio::test]
async fn upstream_health_reported() {
    let f = fx().await;
    // The engine runs a group the database does not know yet; create the stored one.
    let (s, g) = call(&f, &f.admin, Method::POST, "/upstream-groups", Some(json!({
        "name": "default", "strategy": "failover", "default": true,
        "members": [{"upstream": "udp://192.0.2.1:53"}, {"upstream": "tcp://192.0.2.2", "weight": 3}],
    }))).await;
    assert_eq!(s, StatusCode::CREATED, "{g}");
    assert_eq!(g["members"].as_array().unwrap().len(), 2);
    assert_eq!(g["health"][0]["available"], true);

    // Three failed exchanges eject the first member in the live set.
    let live = f.state.live_groups.load_full().unwrap();
    for _ in 0..3 {
        let _ = live.resolve(&Down, &query("x.test.")).await;
    }
    let (s, h) = call(
        &f,
        &f.viewer,
        Method::GET,
        "/upstream-groups/default/health",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[0]["available"], false);
    assert!(h[0]["consecutive_failures"].as_u64().unwrap() >= 3);
    assert_eq!(h[1]["upstream"], "tcp://192.0.2.2:53");
    let (_, one) = call(&f, &f.viewer, Method::GET, "/upstream-groups/default", None).await;
    assert_eq!(one["health"][0]["available"], false);
    let (s, _) = call(
        &f,
        &f.viewer,
        Method::GET,
        "/upstream-groups/nope/health",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn upstream_group_crud_and_validation() {
    let f = fx().await;
    let a = f.admin.clone();
    let body = |default: bool| {
        json!({"strategy": "round_robin", "default": default,
        "domains": ["corp.example"], "members": [{"upstream": "udp://10.0.0.1"}]})
    };
    let create = |name: &str, default: bool| {
        let mut b = body(default);
        b["name"] = json!(name);
        b
    };
    // Operators may read but not change upstreams.
    let (s, _) = call(
        &f,
        &f.operator,
        Method::POST,
        "/upstream-groups",
        Some(create("x", true)),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &f,
        &a,
        Method::POST,
        "/upstream-groups",
        Some(create("main", true)),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _) = call(
        &f,
        &a,
        Method::POST,
        "/upstream-groups",
        Some(create("main", true)),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    for bad in [
        create("bad name!", false),
        {
            let mut b = create("e", false);
            b["members"] = json!([]);
            b
        },
        {
            let mut b = create("e", false);
            b["members"] = json!([{"upstream": "http://x"}]);
            b
        },
        {
            let mut b = create("e", false);
            b["members"] = json!([{"upstream": "udp://10.0.0.1", "weight": 0}]);
            b
        },
        // The pattern is already routed to "main".
        create("dup", false),
    ] {
        let (s, v) = call(&f, &a, Method::POST, "/upstream-groups", Some(bad)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    }
    // A second default demotes the first.
    let mut second = create("second", true);
    second["domains"] = json!([]);
    let (s, _) = call(&f, &a, Method::POST, "/upstream-groups", Some(second)).await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, list) = call(&f, &a, Method::GET, "/upstream-groups", None).await;
    let defaults: Vec<_> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["default"] == true)
        .collect();
    assert_eq!(defaults.len(), 1);
    assert_eq!(defaults[0]["name"], "second");
    // Routing is live: corp.example goes to "main".
    assert_eq!(
        f.state
            .live_groups
            .load_full()
            .unwrap()
            .group_for(&name("a.corp.example.")),
        "main"
    );

    // Members.
    let (s, g) = call(
        &f,
        &a,
        Method::POST,
        "/upstream-groups/main/upstreams",
        Some(json!({"upstream": "tls://10.0.0.2#dns.example", "weight": 2})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(
        g["members"][1]["upstream"],
        "tls://10.0.0.2:853#dns.example"
    );
    let (s, _) = call(
        &f,
        &a,
        Method::POST,
        "/upstream-groups/main/upstreams",
        Some(json!({"upstream": "udp://10.0.0.1:53"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, g) = call(
        &f,
        &a,
        Method::DELETE,
        "/upstream-groups/main/upstreams/0",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(g["members"].as_array().unwrap().len(), 1);
    let (s, _) = call(
        &f,
        &a,
        Method::DELETE,
        "/upstream-groups/main/upstreams/5",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &f,
        &a,
        Method::DELETE,
        "/upstream-groups/main/upstreams/0",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = call(
        &f,
        &a,
        Method::POST,
        "/upstream-groups/none/upstreams",
        Some(json!({"upstream": "udp://10.0.0.9"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Replace, and delete rules: the default group cannot go while others remain.
    let (s, g) = call(
        &f,
        &a,
        Method::PUT,
        "/upstream-groups/main",
        Some(json!({
        "strategy": "weighted", "members": [{"upstream": "udp://10.0.0.7", "weight": 5}]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(g["strategy"], "weighted");
    let (s, _) = call(
        &f,
        &a,
        Method::PUT,
        "/upstream-groups/ghost",
        Some(json!({
        "strategy": "weighted", "members": [{"upstream": "udp://10.0.0.7"}]})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(&f, &a, Method::DELETE, "/upstream-groups/second", None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = call(&f, &a, Method::DELETE, "/upstream-groups/main", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&f, &a, Method::DELETE, "/upstream-groups/second", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(f.state.live_groups.load_full().is_none());
    let (s, _) = call(&f, &a, Method::GET, "/upstream-groups/second", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn custom_rule_applies_live() {
    let f = fx().await;
    let a = &f.operator;
    let unblocked = ask(&f, [192, 0, 2, 1], "ads.example.com.").await.unwrap();
    assert_eq!(unblocked.answers.len(), 0);
    let (s, rule) = call(
        &f,
        a,
        Method::POST,
        "/rules",
        Some(json!({"kind": "block", "domain": "ADS.Example.com."})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(rule["domain"], "ads.example.com");
    let blocked = ask(&f, [192, 0, 2, 1], "sub.ads.example.com.")
        .await
        .unwrap();
    assert_eq!(blocked.answers.len(), 1);
    assert!(matches!(blocked.answers[0].data, RData::A(ip) if ip.is_unspecified()));

    let (s, allow) = call(
        &f,
        a,
        Method::POST,
        "/rules",
        Some(json!({"kind": "allow", "domain": "ok.ads.example.com"})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let allowed = ask(&f, [192, 0, 2, 1], "ok.ads.example.com.")
        .await
        .unwrap();
    assert_eq!(allowed.answers.len(), 0);

    let (s, _) = call(
        &f,
        a,
        Method::POST,
        "/rules",
        Some(json!({"kind": "block", "domain": "ads.example.com"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    for bad in ["", "bad domain!", &"a.".repeat(200)] {
        let (s, _) = call(
            &f,
            a,
            Method::POST,
            "/rules",
            Some(json!({"kind": "block", "domain": bad})),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    let (_, list) = call(&f, &f.viewer, Method::GET, "/rules", None).await;
    assert_eq!(list.as_array().unwrap().len(), 2);

    let id = rule["id"].as_i64().unwrap();
    let (s, _) = call(&f, a, Method::DELETE, &format!("/rules/{id}"), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        answer_count(&f, [192, 0, 2, 1], "sub.ads.example.com.").await,
        0
    );
    let (s, _) = call(&f, a, Method::DELETE, &format!("/rules/{id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let aid = allow["id"].as_i64().unwrap();
    call(&f, a, Method::DELETE, &format!("/rules/{aid}"), None).await;
    let (s, _) = call(
        &f,
        &f.viewer,
        Method::POST,
        "/rules",
        Some(json!({"kind": "block", "domain": "x.example"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn new_blocklist_is_populated_without_waiting_for_the_schedule() {
    let f = fx().await;
    let list = f.dir.path().join("fresh.txt");
    std::fs::write(&list, "fresh.example\n").unwrap();
    let body = json!({
        "name": "fresh", "location": list.to_str().unwrap(),
        "format": "domains", "allow_private": true,
    });
    let (s, created) = call(&f, &f.admin, Method::POST, "/blocklists", Some(body)).await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    assert_eq!(created["entries"], 1, "{created}");
    assert!(created["last_fetched"].is_i64(), "{created}");
    assert_eq!(
        ask(&f, [192, 0, 2, 1], "fresh.example.")
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    // A disabled source is not fetched.
    let list2 = f.dir.path().join("off.txt");
    std::fs::write(&list2, "off.example\n").unwrap();
    let off = json!({
        "name": "off", "location": list2.to_str().unwrap(),
        "format": "domains", "allow_private": true, "enabled": false,
    });
    let (s, created) = call(&f, &f.admin, Method::POST, "/blocklists", Some(off)).await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    assert!(created["last_fetched"].is_null(), "{created}");
}

#[tokio::test]
async fn blocklist_refresh_endpoint() {
    let f = fx().await;
    let list = f.dir.path().join("list.txt");
    std::fs::write(&list, "listed.example\nother.example\n").unwrap();
    let path = list.to_str().unwrap();

    // File sources read the server's disk: admin scope only, and they need allow_private.
    let file =
        json!({"name": "local", "location": path, "format": "domains", "allow_private": true});
    let (s, _) = call(
        &f,
        &f.operator,
        Method::POST,
        "/blocklists",
        Some(file.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &f,
        &f.operator,
        Method::POST,
        "/blocklists",
        Some(json!({"name": "local", "location": path})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = call(
        &f,
        &f.admin,
        Method::POST,
        "/blocklists",
        Some(json!({"name": "local", "location": path})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, created) = call(&f, &f.admin, Method::POST, "/blocklists", Some(file)).await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    assert_eq!(created["allow_private"], true);
    assert_eq!(created["entries"], 2, "fetched on create");
    let id = created["id"].as_i64().unwrap();

    let (s, r) = call(
        &f,
        &f.operator,
        Method::POST,
        &format!("/blocklists/{id}/refresh"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    assert_eq!(r["outcome"], "updated");
    assert_eq!(r["entries"], 2);
    assert_eq!(
        ask(&f, [192, 0, 2, 1], "listed.example.")
            .await
            .unwrap()
            .answers
            .len(),
        1
    );

    let (_, all) = call(&f, &f.viewer, Method::GET, "/blocklists", None).await;
    assert_eq!(all[0]["entries"], 2);
    assert!(all[0]["last_status"].as_str().is_some());

    // Disable drops its entries from the filter, enable does not refetch (kept until refresh).
    let (s, v) = call(
        &f,
        &f.operator,
        Method::PATCH,
        &format!("/blocklists/{id}"),
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["enabled"], false);
    assert_eq!(answer_count(&f, [192, 0, 2, 1], "listed.example.").await, 0);
    let (s, _) = call(
        &f,
        &f.operator,
        Method::PATCH,
        "/blocklists/999",
        Some(json!({"enabled": true})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, _) = call(
        &f,
        &f.operator,
        Method::POST,
        "/blocklists/999/refresh",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    std::fs::remove_file(&list).unwrap();
    call(
        &f,
        &f.operator,
        Method::PATCH,
        &format!("/blocklists/{id}"),
        Some(json!({"enabled": true})),
    )
    .await;
    let (s, v) = call(
        &f,
        &f.operator,
        Method::POST,
        &format!("/blocklists/{id}/refresh"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");

    let (s, _) = call(
        &f,
        &f.operator,
        Method::DELETE,
        &format!("/blocklists/{id}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        &f,
        &f.operator,
        Method::DELETE,
        &format!("/blocklists/{id}"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn blocklist_url_ssrf_and_validation() {
    let f = fx().await;
    let post = |token: String, body: Value| {
        let f = &f;
        async move { call(f, &token, Method::POST, "/blocklists", Some(body)).await }
    };
    // Non-public literal targets and localhost are refused for operators and for admins who do
    // not opt in; opting in is admin-only.
    for (i, url) in [
        "http://127.0.0.1/list",
        "http://10.1.2.3/list",
        "http://[::1]/list",
        "http://169.254.169.254/latest",
        "http://127.1/list",
        "http://localhost/list",
        "http://svc.localhost./list",
    ]
    .into_iter()
    .enumerate()
    {
        let body = json!({"name": format!("n{i}"), "location": url});
        assert_eq!(
            post(f.operator.clone(), body.clone()).await.0,
            StatusCode::FORBIDDEN,
            "{url}"
        );
        assert_eq!(
            post(f.admin.clone(), body).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{url}"
        );
        let with = json!({"name": format!("n{i}"), "location": url, "allow_private": true});
        assert_eq!(
            post(f.operator.clone(), with.clone()).await.0,
            StatusCode::FORBIDDEN,
            "{url}"
        );
        assert_eq!(
            post(f.admin.clone(), with).await.0,
            StatusCode::CREATED,
            "{url}"
        );
    }
    // A public URL needs only the write scope; the fetcher re-checks the resolved address.
    let (s, v) = post(
        f.operator.clone(),
        json!({"name": "pub", "location": "https://lists.example.org/hosts.txt",
        "interval_secs": 3600, "format": "hosts", "enabled": false}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(v["format"], "hosts");
    assert_eq!(v["interval_secs"], 3600);
    let (s, _) = post(
        f.operator.clone(),
        json!({"name": "pub2", "location": "https://lists.example.org/hosts.txt"}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    for body in [
        json!({"name": "a", "location": "ftp://example.org/x"}),
        json!({"name": "a", "location": "http://user:pw@example.org/x"}),
        json!({"name": "a", "location": "https://example.org/x", "interval_secs": 5}),
        json!({"name": "", "location": "https://example.org/y"}),
    ] {
        let (s, _) = post(f.operator.clone(), body).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let (s, _) = post(
        f.viewer.clone(),
        json!({"name": "v", "location": "https://example.org/z"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Refresh of a private source without opt-in never connects: the fetch is refused.
    let id = f
        .state
        .stores
        .sources
        .add(dnsy_filter::NewSource {
            name: "sneaky".into(),
            location: "http://127.0.0.1:9/list".into(),
            format: dnsy_filter::ListFormat::Auto,
            enabled: true,
            interval_secs: 60,
            allow_private: false,
        })
        .await
        .unwrap();
    let (s, v) = call(
        &f,
        &f.operator,
        Method::POST,
        &format!("/blocklists/{id}/refresh"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
}

fn fp(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

#[tokio::test]
async fn client_cert_fingerprint_crud() {
    let f = fx().await;
    let a = &f.admin;
    for t in [&f.operator, &f.viewer] {
        assert_eq!(
            call(&f, t, Method::GET, "/client-certs", None).await.0,
            StatusCode::FORBIDDEN
        );
        let (s, _) = call(
            &f,
            t,
            Method::POST,
            "/client-certs",
            Some(json!({"sha256": fp(1), "label": "x"})),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }
    assert_eq!(f.reloads.load(Ordering::SeqCst), 0);

    let colons = (0..32).map(|_| "AB").collect::<Vec<_>>().join(":");
    let (s, c) = call(
        &f,
        a,
        Method::POST,
        "/client-certs",
        Some(json!({"sha256": colons, "label": "laptop", "expires_at": 4_102_444_800_i64})),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    assert_eq!(c["sha256"], "ab".repeat(32));
    assert_eq!(c["enabled"], true);
    assert_eq!(c["expired"], false);
    assert_eq!(f.reloads.load(Ordering::SeqCst), 1);
    let id = c["id"].as_i64().unwrap();

    let (s, _) = call(
        &f,
        a,
        Method::POST,
        "/client-certs",
        Some(json!({"sha256": "ab".repeat(32), "label": "dup"})),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    for bad in [
        json!({"sha256": "abcd", "label": "x"}),
        json!({"sha256": "zz".repeat(32), "label": "x"}),
        json!({"sha256": fp(2), "label": "   "}),
        json!({"sha256": fp(2), "label": "l".repeat(129)}),
        json!({"sha256": fp(2), "label": "x", "expires_at": 1}),
    ] {
        let (s, _) = call(&f, a, Method::POST, "/client-certs", Some(bad)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    }
    assert_eq!(f.reloads.load(Ordering::SeqCst), 1);

    let (s, v) = call(
        &f,
        a,
        Method::PATCH,
        &format!("/client-certs/{id}"),
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["enabled"], false);
    assert_eq!(f.reloads.load(Ordering::SeqCst), 2);
    assert_eq!(f.state.auth.client_certs.active().await.unwrap().len(), 0);
    let (s, _) = call(
        &f,
        a,
        Method::PATCH,
        "/client-certs/99",
        Some(json!({"enabled": true})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (_, list) = call(&f, a, Method::GET, "/client-certs", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Removing reloads the allowlist so open connections are re-checked.
    let (s, _) = call(&f, a, Method::DELETE, &format!("/client-certs/{id}"), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(f.reloads.load(Ordering::SeqCst), 3);
    let (s, _) = call(&f, a, Method::DELETE, &format!("/client-certs/{id}"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(f.reloads.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn failed_allowlist_reload_is_an_error() {
    let f = fx().await;
    let state = f
        .state
        .clone()
        .with_cert_reload(Arc::new(|| Box::pin(async { Err("disk".to_owned()) })));
    let app = build(
        state,
        ApiConfig {
            tls: false,
            ..ApiConfig::default()
        },
        Router::new(),
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/client-certs")
        .header("authorization", format!("Bearer {}", f.admin))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"sha256": fp(9), "label": "x"}).to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn settings_patch_validates() {
    let f = fx().await;
    let a = &f.admin;
    for t in [&f.operator, &f.viewer] {
        assert_eq!(
            call(&f, t, Method::GET, "/settings", None).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&f, t, Method::PATCH, "/settings", Some(json!({})))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let (s, before) = call(&f, a, Method::GET, "/settings", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(before["filter"]["block_mode"], "null_ip");
    assert_eq!(before["cache"]["serve_stale"]["enabled"], true);

    for bad in [
        json!({"cache": {"min_ttl": 500, "max_ttl": 100}}),
        json!({"cache": {"max_ttl": 4_000_000_000_u64}}),
        json!({"querylog": {"retention_days": 0}}),
        json!({"querylog": {"retention_days": 99_999}}),
        json!({"limits": {"per_client_qps": 2_000_000}}),
        json!({"filter": {"block_mode": "teapot"}}),
        // Everything outside the runtime subset, secrets included, is unknown.
        json!({"dnssec": {"key_passphrase_file": "/x"}}),
        json!({"api": {"tls_key": "/x"}}),
        json!({"cache": {"max_entries": 1}}),
    ] {
        let (s, v) = call(&f, a, Method::PATCH, "/settings", Some(bad.clone())).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {v}");
    }
    let (_, after) = call(&f, a, Method::GET, "/settings", None).await;
    assert_eq!(before, after);

    let (s, v) = call(
        &f,
        a,
        Method::PATCH,
        "/settings",
        Some(json!({
        "filter": {"block_mode": "refused"}, "querylog": {"retention_days": 7},
        "limits": {"per_client_qps": 60}})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["filter"]["block_mode"], "refused");
    assert_eq!(v["querylog"]["retention_days"], 7);
    assert_eq!(v["limits"]["per_client_qps"], 60);
    assert_eq!(
        f.state.stores.rules.rate_limit_qps().await.unwrap(),
        Some(60)
    );
    assert_eq!(
        *f.state.settings.retention_updates().borrow(),
        std::time::Duration::from_hours(7 * 24)
    );
    // The response never carries anything but the subset.
    let keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys.len(), 4);
    assert!(!v.to_string().contains("pass"));
}

#[tokio::test]
async fn block_mode_patch_changes_blocked_answers() {
    let f = fx().await;
    call(
        &f,
        &f.operator,
        Method::POST,
        "/rules",
        Some(json!({"kind": "block", "domain": "bad.example"})),
    )
    .await;
    assert_eq!(
        ask(&f, [192, 0, 2, 1], "bad.example.")
            .await
            .unwrap()
            .header
            .rcode,
        Rcode::NoError
    );
    for (mode, rcode) in [("nxdomain", Rcode::NxDomain), ("refused", Rcode::Refused)] {
        let (s, _) = call(
            &f,
            &f.admin,
            Method::PATCH,
            "/settings",
            Some(json!({"filter": {"block_mode": mode}})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            ask(&f, [192, 0, 2, 1], "bad.example.")
                .await
                .unwrap()
                .header
                .rcode,
            rcode
        );
    }
}

#[tokio::test]
async fn cache_settings_patch_applies_live() {
    let f = fx().await;
    let cache = f.state.cache.as_ref().unwrap();
    let key = CacheKey {
        name: name("www.example.com."),
        qtype: RecordType::A,
        qclass: Class::In,
        do_bit: false,
        cd_bit: false,
    };
    let mut answer = query("www.example.com.");
    answer.header.qr = true;
    answer.answers.push(Record {
        name: name("www.example.com."),
        rtype: RecordType::A,
        class: Class::In,
        ttl: 3600,
        data: RData::A([192, 0, 2, 1].into()),
    });
    let ttl = |key: &CacheKey| match cache.get(key, Instant::now()) {
        dnsy_resolver::CacheLookup::Fresh { msg, .. } => msg.answers[0].ttl,
        other => panic!("expected a fresh hit, got {other:?}"),
    };
    cache.insert(
        key.clone(),
        answer.clone(),
        DnssecStatus::Unchecked,
        Instant::now(),
    );
    assert!(ttl(&key) > 3000);

    let (s, v) = call(&f, &f.admin, Method::PATCH, "/settings", Some(json!({
        "cache": {"max_ttl": 120, "min_ttl": 30, "serve_stale": {"enabled": false}, "prefetch": {"enabled": false}}}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["cache"]["max_ttl"], 120);
    assert_eq!(v["cache"]["serve_stale"]["enabled"], false);
    assert_eq!(v["cache"]["prefetch"]["enabled"], false);
    cache.insert(
        key.clone(),
        answer.clone(),
        DnssecStatus::Unchecked,
        Instant::now(),
    );
    assert!(ttl(&key) <= 120);

    // Unrelated patches leave the live cache settings alone.
    call(
        &f,
        &f.admin,
        Method::PATCH,
        "/settings",
        Some(json!({"querylog": {"retention_days": 3}})),
    )
    .await;
    cache.insert(
        key.clone(),
        answer.clone(),
        DnssecStatus::Unchecked,
        Instant::now(),
    );
    assert!(ttl(&key) <= 120);
}

/// Without a running engine or certificate reload hook, every mutating handler answers 503 and
/// persists nothing, instead of reporting a success that changes nothing in the server.
#[tokio::test]
async fn mutations_fail_closed_without_engine_or_cert_reload() {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let state = ApiState::new(store);
    let user = state
        .auth
        .users
        .create("admin", "pw-pw-pw", Role::Admin)
        .await
        .unwrap();
    let token = state
        .auth
        .tokens
        .create(
            user.id,
            "t",
            &[Scope::ApiRead, Scope::ApiWrite, Scope::Admin],
            None,
        )
        .await
        .unwrap()
        .0;
    let app = build(
        state.clone(),
        ApiConfig {
            tls: false,
            ..ApiConfig::default()
        },
        Router::new(),
    );
    let send = |method: Method, uri: &'static str, body: Option<Value>| {
        let app = app.clone();
        let token = token.clone();
        async move {
            let b = Request::builder()
                .method(method)
                .uri(format!("/api/v1{uri}"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json");
            let req = b
                .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
                .unwrap();
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    let group = json!({"name": "g", "strategy": "failover", "default": true,
        "members": [{"upstream": "udp://192.0.2.1:53"}]});
    let cases = [
        (
            Method::POST,
            "/acl",
            Some(json!({"cidr": "192.0.2.0/24", "action": "refuse"})),
        ),
        (Method::DELETE, "/acl/1", None),
        (Method::PUT, "/acl/rate-limit", Some(json!({"qps": 5}))),
        (
            Method::POST,
            "/rules",
            Some(json!({"kind": "block", "domain": "r.test"})),
        ),
        (Method::DELETE, "/rules/1", None),
        (
            Method::POST,
            "/blocklists",
            Some(json!({"name": "l", "location": "https://lists.example/hosts.txt"})),
        ),
        (
            Method::PATCH,
            "/blocklists/1",
            Some(json!({"enabled": false})),
        ),
        (Method::DELETE, "/blocklists/1", None),
        (Method::POST, "/blocklists/1/refresh", None),
        (
            Method::PATCH,
            "/settings",
            Some(json!({"limits": {"per_client_qps": 5}})),
        ),
        (Method::POST, "/upstream-groups", Some(group.clone())),
        (
            Method::PUT,
            "/upstream-groups/g",
            Some(json!({"strategy": "failover", "default": true,
                "members": [{"upstream": "udp://192.0.2.1:53"}]})),
        ),
        (Method::DELETE, "/upstream-groups/g", None),
        (
            Method::POST,
            "/upstream-groups/g/upstreams",
            Some(json!({"upstream": "udp://192.0.2.9:53"})),
        ),
        (Method::DELETE, "/upstream-groups/g/upstreams/0", None),
        (
            Method::POST,
            "/client-certs",
            Some(json!({"sha256": fp(1), "label": "x"})),
        ),
        (
            Method::PATCH,
            "/client-certs/1",
            Some(json!({"enabled": false})),
        ),
        (Method::DELETE, "/client-certs/1", None),
    ];
    for (method, uri, body) in cases {
        let (status, text) = send(method.clone(), uri, body).await;
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {uri}: {text}"
        );
    }
    assert_eq!(state.stores.rules.list().await.unwrap().len(), 0);
    assert_eq!(state.auth.client_certs.list().await.unwrap().len(), 0);
    assert_eq!(state.stores.groups.list().await.unwrap().len(), 0);
    assert_eq!(state.stores.rules.rate_limit_qps().await.unwrap(), None);
}

#[tokio::test]
async fn response_ip_list_is_validated_persisted_and_role_gated() {
    let f = fx().await;
    let (s, v) = call(&f, &f.viewer, Method::GET, "/response-ip", None).await;
    assert_eq!((s, &v["cidrs"]), (StatusCode::OK, &json!([])));
    let body = json!({"cidrs": ["10.0.0.5/8", "10.0.0.0/8", "192.0.2.1"]});
    let (s, _) = call(
        &f,
        &f.viewer,
        Method::PUT,
        "/response-ip",
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(
        f.state.stores.rules.response_ip_cidrs().await.unwrap(),
        None
    );
    let (s, _) = call(
        &f,
        &f.operator,
        Method::PUT,
        "/response-ip",
        Some(json!({"cidrs": ["10.0.0.0/99"]})),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        f.state.stores.rules.response_ip_cidrs().await.unwrap(),
        None
    );
    let (s, v) = call(&f, &f.operator, Method::PUT, "/response-ip", Some(body)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["cidrs"], json!(["10.0.0.0/8", "192.0.2.1/32"]));
    assert_eq!(
        f.state.stores.rules.response_ip_cidrs().await.unwrap(),
        Some(vec!["10.0.0.0/8".to_owned(), "192.0.2.1/32".to_owned()])
    );
    let (_, v) = call(&f, &f.viewer, Method::GET, "/response-ip", None).await;
    assert_eq!(v["cidrs"], json!(["10.0.0.0/8", "192.0.2.1/32"]));
}
