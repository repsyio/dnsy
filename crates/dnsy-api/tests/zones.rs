//! Tests of the zone and record endpoints.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use dnsy_api::error::PROBLEM_JSON;
use dnsy_api::{ApiConfig, ApiState, build};
use dnsy_core::Role;
use dnsy_zone::{Zone, ZoneStore};
use serde_json::{Value, json};
use tower::ServiceExt;

struct Fx {
    app: Router,
    dir: tempfile::TempDir,
    zones: Arc<ZoneStore>,
    admin: String,
    viewer: String,
}

async fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let zones = ZoneStore::open(dir.path().join("zones")).unwrap();
    let mut state = ApiState::new(store);
    state.zones.store = Some(Arc::clone(&zones));
    let mut tokens = Vec::new();
    for (user, role, scopes) in [
        (
            "admin",
            Role::Admin,
            vec![dnsy_core::Scope::ApiRead, dnsy_core::Scope::ApiWrite],
        ),
        ("viewer", Role::Viewer, vec![dnsy_core::Scope::ApiRead]),
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
        state,
        ApiConfig {
            tls: false,
            ..ApiConfig::default()
        },
        Router::new(),
    );
    let viewer = tokens.pop().unwrap();
    let admin = tokens.pop().unwrap();
    Fx {
        app,
        dir,
        zones,
        admin,
        viewer,
    }
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Res {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

async fn call(
    fx: &Fx,
    token: &str,
    method: Method,
    uri: &str,
    extra: &[(&str, &str)],
    body: Option<Value>,
) -> Res {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string())),
        None => b.body(Body::empty()),
    }
    .unwrap();
    let res = fx.app.clone().oneshot(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let bytes = axum::body::to_bytes(body, 1 << 22).await.unwrap();
    Res {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn zone_body() -> Value {
    json!({
        "name": "Example.COM",
        "default_ttl": 300,
        "soa": {"mname": "ns1.example.com.", "rname": "hostmaster.example.com.",
                "refresh": 7200, "retry": 3600, "expire": 1_209_600, "minimum": 300},
        "records": [
            {"name": "@", "type": "NS", "value": "ns1.example.com."},
            {"name": "www", "type": "A", "value": "192.0.2.1"},
        ],
    })
}

async fn create(fx: &Fx) -> Res {
    call(
        fx,
        &fx.admin,
        Method::POST,
        "/api/v1/zones",
        &[],
        Some(zone_body()),
    )
    .await
}

async fn records(fx: &Fx, query: &str) -> Value {
    call(
        fx,
        &fx.admin,
        Method::GET,
        &format!("/api/v1/zones/example.com./records{query}"),
        &[],
        None,
    )
    .await
    .json()
}

#[tokio::test]
async fn create_zone_rejects_unknown_fields() {
    let fx = fx().await;
    let mut body = zone_body();
    body["bogus"] = json!(true);
    let res = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/api/v1/zones",
        &[],
        Some(body.clone()),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", res.body);
    assert!(res.body.contains("bogus"), "{}", res.body);
    assert!(fx.zones.snapshot().is_empty());

    assert_eq!(create(&fx).await.status, StatusCode::CREATED);
    body.as_object_mut().unwrap().remove("name");
    let res = call(
        &fx,
        &fx.admin,
        Method::PUT,
        "/api/v1/zones/example.com.",
        &[],
        Some(body),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", res.body);
}

#[tokio::test]
async fn zone_crud_writes_json_file() {
    let fx = fx().await;
    let res = create(&fx).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.body);
    assert_eq!(res.json()["name"], "example.com.");
    let file = fx.dir.path().join("zones/example.com.json");
    assert!(std::fs::read_to_string(&file).unwrap().contains("www"));

    let list = call(&fx, &fx.admin, Method::GET, "/api/v1/zones", &[], None).await;
    assert_eq!(list.json()[0]["record_count"], 2);
    let got = call(
        &fx,
        &fx.admin,
        Method::GET,
        "/api/v1/zones/EXAMPLE.com",
        &[],
        None,
    )
    .await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.json()["soa"]["serial"], 1);
    assert!(got.json()["load_error"].is_null());

    let mut replace = zone_body();
    replace.as_object_mut().unwrap().remove("name");
    replace["default_ttl"] = json!(600);
    replace["records"] = json!([{"name": "@", "type": "NS", "value": "ns2.example.com."}]);
    let res = call(
        &fx,
        &fx.admin,
        Method::PUT,
        "/api/v1/zones/example.com.",
        &[],
        Some(replace),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["soa"]["serial"], 2);
    assert_eq!(res.json()["record_count"], 1);
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("\"default_ttl\": 600")
    );

    let del = call(
        &fx,
        &fx.admin,
        Method::DELETE,
        "/api/v1/zones/example.com.",
        &[],
        None,
    )
    .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);
    assert!(!file.exists());
    let gone = call(
        &fx,
        &fx.admin,
        Method::GET,
        "/api/v1/zones/example.com.",
        &[],
        None,
    )
    .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_zone_rejects_traversal_and_duplicates() {
    let fx = fx().await;
    for bad in [
        "../evil",
        "a/b.example.",
        "..\\evil",
        "a\\046b.example.",
        ".",
        "",
        "under_score.example.",
        "bücher.example.",
    ] {
        let mut body = zone_body();
        body["name"] = json!(bad);
        let res = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones",
            &[],
            Some(body),
        )
        .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}: {}", res.body);
    }
    assert_eq!(create(&fx).await.status, StatusCode::CREATED);
    for dup in ["example.com.", "EXAMPLE.com", "Example.Com."] {
        let mut body = zone_body();
        body["name"] = json!(dup);
        let res = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones",
            &[],
            Some(body),
        )
        .await;
        assert_eq!(res.status, StatusCode::CONFLICT, "{dup}");
    }
    // Path parameters are validated the same way.
    for uri in [
        "/api/v1/zones/..%2Fetc",
        "/api/v1/zones/a%5Cb.example.",
        "/api/v1/zones/%2e%2e",
    ] {
        let res = call(&fx, &fx.admin, Method::DELETE, uri, &[], None).await;
        assert!(
            res.status == StatusCode::BAD_REQUEST || res.status == StatusCode::NOT_FOUND,
            "{uri}: {}",
            res.status
        );
    }
    // Only the one zone file exists, inside the zones directory.
    let files: Vec<_> = std::fs::read_dir(fx.dir.path().join("zones"))
        .unwrap()
        .collect();
    assert_eq!(files.len(), 1);
}

#[tokio::test]
async fn record_validation_422() {
    let fx = fx().await;
    create(&fx).await;
    let post = |body: Value| {
        call(
            &fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones/example.com./records",
            &[],
            Some(body),
        )
    };
    for body in [
        json!({"name": "x", "type": "A", "value": "not-an-ip"}),
        json!({"name": "x", "type": "A", "ttl": 2_147_483_648_u32, "value": "192.0.2.9"}),
        json!({"name": "x.other.org.", "type": "A", "value": "192.0.2.9"}),
        json!({"name": "x", "type": "HINFO", "value": "a b"}),
        json!({"name": "x", "type": "SOA", "value": "a b 1 2 3 4 5"}),
        json!({"name": "x", "type": "RRSIG", "value": "x"}),
        // CNAME may not coexist with other data (www has an A record) ...
        json!({"name": "www", "type": "CNAME", "value": "x.example.com."}),
        // ... and the apex cannot be a CNAME.
        json!({"name": "@", "type": "CNAME", "value": "x.example.com."}),
        json!({"name": "x", "type": "TXT", "value": "a".repeat(5000)}),
    ] {
        let res = post(body.clone()).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(res.headers[header::CONTENT_TYPE], PROBLEM_JSON);
    }
    // Unknown JSON fields are a client error too.
    let res = post(json!({"name": "x", "type": "A", "value": "192.0.2.9", "extra": 1})).await;
    assert!(res.status.is_client_error());
    // Nothing was written.
    assert_eq!(records(&fx, "").await["total"], 2);

    // A CNAME on a fresh name works, and then nothing else may join it.
    let ok = post(json!({"name": "blog", "type": "CNAME", "value": "www.example.com."})).await;
    assert_eq!(ok.status, StatusCode::CREATED, "{}", ok.body);
    let res = post(json!({"name": "blog", "type": "A", "value": "192.0.2.7"})).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn record_crud_bumps_serial_and_ids_are_stable() {
    let fx = fx().await;
    create(&fx).await;
    let page = records(&fx, "").await;
    let www = page["items"][1].clone();
    assert_eq!(www["name"], "www.example.com.");
    assert_eq!(www["type"], "A");
    assert_eq!(www["id"].as_str().unwrap().len(), 16);
    // The id depends only on name, type and value.
    let again = records(&fx, "").await;
    assert_eq!(again["items"][1]["id"], www["id"]);

    let uri = format!(
        "/api/v1/zones/example.com./records/{}",
        www["id"].as_str().unwrap()
    );
    let put = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &uri,
        &[],
        Some(json!({"name": "www", "type": "A", "ttl": 60, "value": "192.0.2.2"})),
    )
    .await;
    assert_eq!(put.status, StatusCode::OK, "{}", put.body);
    assert_ne!(put.json()["id"], www["id"]);
    assert_eq!(put.json()["ttl"], 60);
    // The old id is gone.
    let old = call(&fx, &fx.admin, Method::DELETE, &uri, &[], None).await;
    assert_eq!(old.status, StatusCode::NOT_FOUND);
    // Duplicates are conflicts.
    let dup = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/api/v1/zones/example.com./records",
        &[],
        Some(json!({"name": "www.example.com.", "type": "A", "value": "192.0.2.2"})),
    )
    .await;
    assert_eq!(dup.status, StatusCode::CONFLICT);

    let new_uri = format!(
        "/api/v1/zones/example.com./records/{}",
        put.json()["id"].as_str().unwrap()
    );
    let del = call(&fx, &fx.admin, Method::DELETE, &new_uri, &[], None).await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);
    assert!(del.headers.contains_key(header::ETAG));
    let zone = call(
        &fx,
        &fx.admin,
        Method::GET,
        "/api/v1/zones/example.com.",
        &[],
        None,
    )
    .await;
    // create=1, put=2, (dup rejected), delete=3.
    assert_eq!(zone.json()["soa"]["serial"], 3);
    assert_eq!(zone.json()["record_count"], 1);
}

#[tokio::test]
async fn apex_keeps_an_ns_record() {
    let fx = fx().await;
    create(&fx).await;
    let ns = records(&fx, "?type=ns").await["items"][0].clone();
    let uri = format!(
        "/api/v1/zones/example.com./records/{}",
        ns["id"].as_str().unwrap()
    );
    let del = call(&fx, &fx.admin, Method::DELETE, &uri, &[], None).await;
    assert_eq!(del.status, StatusCode::UNPROCESSABLE_ENTITY);
    let put = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &uri,
        &[],
        Some(json!({"name": "sub", "type": "NS", "value": "ns1.example.com."})),
    )
    .await;
    assert_eq!(put.status, StatusCode::UNPROCESSABLE_ENTITY);
    // A second apex NS lets the first go.
    let add = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/api/v1/zones/example.com./records",
        &[],
        Some(json!({"name": "@", "type": "NS", "value": "ns2.example.com."})),
    )
    .await;
    assert_eq!(add.status, StatusCode::CREATED);
    let del = call(&fx, &fx.admin, Method::DELETE, &uri, &[], None).await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);
    // Creating a zone without an apex NS is rejected.
    let mut body = zone_body();
    body["name"] = json!("nons.example.");
    body["records"] = json!([]);
    let res = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/api/v1/zones",
        &[],
        Some(body),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn records_are_paged_and_filtered() {
    let fx = fx().await;
    let mut body = zone_body();
    let mut rows = vec![json!({"name": "@", "type": "NS", "value": "ns1.example.com."})];
    for i in 0..25 {
        rows.push(json!({"name": format!("h{i}"), "type": "A", "value": format!("192.0.2.{i}")}));
    }
    body["records"] = json!(rows);
    assert_eq!(
        call(
            &fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones",
            &[],
            Some(body)
        )
        .await
        .status,
        StatusCode::CREATED
    );
    let p = records(&fx, "?limit=10&offset=20").await;
    assert_eq!(p["total"], 26);
    assert_eq!(p["items"].as_array().unwrap().len(), 6);
    assert_eq!(records(&fx, "?type=a").await["total"], 25);
    assert_eq!(records(&fx, "?name=h3").await["total"], 1);
    assert_eq!(records(&fx, "?name=@").await["total"], 1);
    for bad in ["?limit=0", "?limit=1001"] {
        let res = call(
            &fx,
            &fx.admin,
            Method::GET,
            &format!("/api/v1/zones/example.com./records{bad}"),
            &[],
            None,
        )
        .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn if_match_guards_writes() {
    let fx = fx().await;
    let created = create(&fx).await;
    let tag = created.headers[header::ETAG].to_str().unwrap().to_owned();
    let got = call(
        &fx,
        &fx.admin,
        Method::GET,
        "/api/v1/zones/example.com.",
        &[],
        None,
    )
    .await;
    assert_eq!(got.headers[header::ETAG].to_str().unwrap(), tag);

    let rec = json!({"name": "a", "type": "A", "value": "192.0.2.50"});
    let post = |tag: String| {
        let (fx, rec) = (&fx, rec.clone());
        async move {
            call(
                fx,
                &fx.admin,
                Method::POST,
                "/api/v1/zones/example.com./records",
                &[("if-match", tag.as_str())],
                Some(rec),
            )
            .await
        }
    };
    let stale = post("\"deadbeef\"".to_owned()).await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let ok = post(tag.clone()).await;
    assert_eq!(ok.status, StatusCode::CREATED);
    // The old tag is now stale.
    let del = call(
        &fx,
        &fx.admin,
        Method::DELETE,
        "/api/v1/zones/example.com.",
        &[("if-match", &tag)],
        None,
    )
    .await;
    assert_eq!(del.status, StatusCode::PRECONDITION_FAILED);
    let del = call(
        &fx,
        &fx.admin,
        Method::DELETE,
        "/api/v1/zones/example.com.",
        &[("if-match", "*")],
        None,
    )
    .await;
    assert_eq!(del.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn export_returns_bind_text() {
    let fx = fx().await;
    create(&fx).await;
    let res = call(
        &fx,
        &fx.viewer,
        Method::GET,
        "/api/v1/zones/example.com./export",
        &[],
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(
        res.headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/dns")
    );
    assert_eq!(
        res.headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"example.com.zone\""
    );
    assert!(res.body.starts_with("$ORIGIN example.com."), "{}", res.body);
    assert!(res.body.contains("SOA"));
    assert!(res.body.contains("192.0.2.1"));
    let missing = call(
        &fx,
        &fx.viewer,
        Method::GET,
        "/api/v1/zones/nope.example./export",
        &[],
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn authorisation_and_availability() {
    let fx = fx().await;
    create(&fx).await;
    // Viewers read but cannot write.
    let get = call(&fx, &fx.viewer, Method::GET, "/api/v1/zones", &[], None).await;
    assert_eq!(get.status, StatusCode::OK);
    let post = call(
        &fx,
        &fx.viewer,
        Method::POST,
        "/api/v1/zones/example.com./records",
        &[],
        Some(json!({"name": "a", "type": "A", "value": "192.0.2.1"})),
    )
    .await;
    assert_eq!(post.status, StatusCode::FORBIDDEN);
    let del = call(
        &fx,
        &fx.viewer,
        Method::DELETE,
        "/api/v1/zones/example.com.",
        &[],
        None,
    )
    .await;
    assert_eq!(del.status, StatusCode::FORBIDDEN);
    // No credentials.
    let anon = fx
        .app
        .clone()
        .oneshot(Request::get("/api/v1/zones").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);

    // Without a zones directory the routes answer 503.
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let state = ApiState::new(store);
    let u = state
        .auth
        .users
        .create("a", "pw-pw-pw", Role::Admin)
        .await
        .unwrap();
    let (tok, _) = state
        .auth
        .tokens
        .create(u.id, "t", &[dnsy_core::Scope::ApiRead], None)
        .await
        .unwrap();
    let bare = Fx {
        app: build(
            state,
            ApiConfig {
                tls: false,
                ..ApiConfig::default()
            },
            Router::new(),
        ),
        zones: ZoneStore::open(dir.path().join("unused")).unwrap(),
        dir,
        admin: tok.clone(),
        viewer: tok,
    };
    let res = call(&bare, &bare.admin, Method::GET, "/api/v1/zones", &[], None).await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn oversized_body_is_rejected_and_dnssec_policy_survives() {
    let fx = fx().await;
    let mut body = zone_body();
    body["records"][1]["value"] = json!("a".repeat(1 << 20));
    let res = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/api/v1/zones",
        &[],
        Some(body),
    )
    .await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);

    // A DNSSEC policy written to the file is preserved by replace and record writes.
    create(&fx).await;
    let path = fx.dir.path().join("zones/example.com.json");
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    doc["dnssec"] = json!({"enabled": false, "algorithm": 13, "key_layout": "csk",
        "denial": "nsec3", "nsec3": {"iterations": 0, "salt": "", "opt_out": false},
        "signature_validity_days": 14, "refresh_days": 5, "dnskey_ttl": 3600});
    let (zone, _) = Zone::from_json(&doc.to_string()).unwrap();
    fx.zones.write_zone(&zone).unwrap();
    let mut replace = zone_body();
    replace.as_object_mut().unwrap().remove("name");
    let res = call(
        &fx,
        &fx.admin,
        Method::PUT,
        "/api/v1/zones/example.com.",
        &[],
        Some(replace),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("\"dnssec\""), "{text}");
}
