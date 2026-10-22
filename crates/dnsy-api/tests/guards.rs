use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode, header};
use axum::routing::{get, post};
use dnsy_core::{Role, Scope};
use tower::ServiceExt;

use dnsy_api::auth::{AdminScope, Read, RequireScope, Write};
use dnsy_api::error::PROBLEM_JSON;
use dnsy_api::{ApiConfig, ApiState, openapi, router};

struct Fixture {
    state: ApiState,
    app: Router,
    _dir: tempfile::TempDir,
}

#[expect(clippy::unused_async, reason = "handlers are async")]
async fn ok() -> &'static str {
    "ok"
}

/// Real router plus three probe routes guarded by each scope marker.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let state = ApiState::new(store);
    let probes: Router<ApiState> = Router::new()
        .route(
            "/r",
            get(|_: RequireScope<Read>| ok()).post(|_: RequireScope<Read>| ok()),
        )
        .route("/w", post(|_: RequireScope<Write>| ok()))
        .route("/a", get(|_: RequireScope<AdminScope>| ok()));
    let app = dnsy_api::build(
        state.clone(),
        ApiConfig {
            tls: false,
            ..ApiConfig::default()
        },
        probes,
    );
    Fixture {
        state,
        app,
        _dir: dir,
    }
}

async fn send(app: &Router, req: Request<Body>) -> Response<Body> {
    app.clone().oneshot(req).await.unwrap()
}

fn req(method: Method, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::empty()).unwrap()
}

async fn body_json(res: Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn token(f: &Fixture, role: Role, scopes: &[Scope]) -> String {
    let user = f
        .state
        .auth
        .users
        .create("alice", "pw-pw-pw", role)
        .await
        .unwrap();
    f.state
        .auth
        .tokens
        .create(user.id, "t", scopes, None)
        .await
        .unwrap()
        .0
}

/// Returns (`session_cookie`, `csrf_cookie`) for a fresh user of `role`.
async fn session(f: &Fixture, role: Role) -> (String, String) {
    f.state
        .auth
        .users
        .create("bob", "pw-pw-pw", role)
        .await
        .unwrap();
    let (id, _) = f
        .state
        .auth
        .sessions
        .login(
            &f.state.auth.users,
            "bob",
            "pw-pw-pw",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            None,
        )
        .await
        .unwrap();
    (id, "csrf-value".to_owned())
}

#[tokio::test]
async fn unauthenticated_is_401_problem_json() {
    let f = fixture();
    let res = send(&f.app, req(Method::GET, "/r", &[])).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(res.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
    let body = body_json(res).await;
    assert_eq!(body["status"], 401);
    assert_eq!(body["title"], "Unauthorized");
}

#[tokio::test]
async fn bad_bearer_is_401() {
    let f = fixture();
    for h in ["Bearer dnsy_nope", "Basic abc", "Bearer"] {
        let res = send(&f.app, req(Method::GET, "/r", &[("authorization", h)])).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{h}");
    }
    let res = send(
        &f.app,
        req(Method::GET, "/r", &[("cookie", "dnsy_session=bogus")]),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_scope_is_403() {
    let f = fixture();
    let t = token(&f, Role::Admin, &[Scope::ApiRead]).await;
    let bearer = format!("Bearer {t}");
    let ok = send(
        &f.app,
        req(Method::GET, "/r", &[("authorization", &bearer)]),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    let res = send(
        &f.app,
        req(Method::POST, "/w", &[("authorization", &bearer)]),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(res.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
}

#[tokio::test]
async fn viewer_session_cannot_use_write_or_admin() {
    let f = fixture();
    let (sid, csrf) = session(&f, Role::Viewer).await;
    let cookie = format!("dnsy_session={sid}; dnsy_csrf={csrf}");
    let hs = [("cookie", cookie.as_str()), ("x-csrf-token", csrf.as_str())];
    assert_eq!(
        send(&f.app, req(Method::GET, "/r", &hs)).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&f.app, req(Method::POST, "/w", &hs)).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&f.app, req(Method::GET, "/a", &hs)).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn csrf_required_for_cookie_post() {
    let f = fixture();
    let (sid, csrf) = session(&f, Role::Operator).await;
    let cookie = format!("dnsy_session={sid}; dnsy_csrf={csrf}");
    // GET needs no CSRF token.
    let get_ok = send(&f.app, req(Method::GET, "/r", &[("cookie", &cookie)])).await;
    assert_eq!(get_ok.status(), StatusCode::OK);
    // POST without, or with a wrong, token is rejected.
    let none = send(&f.app, req(Method::POST, "/w", &[("cookie", &cookie)])).await;
    assert_eq!(none.status(), StatusCode::FORBIDDEN);
    assert_eq!(none.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
    let wrong = send(
        &f.app,
        req(
            Method::POST,
            "/w",
            &[("cookie", &cookie), ("x-csrf-token", "nope")],
        ),
    )
    .await;
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    // Matching token passes.
    let good = send(
        &f.app,
        req(
            Method::POST,
            "/w",
            &[("cookie", &cookie), ("x-csrf-token", &csrf)],
        ),
    )
    .await;
    assert_eq!(good.status(), StatusCode::OK);
}

#[tokio::test]
async fn bearer_post_needs_no_csrf() {
    let f = fixture();
    let t = token(&f, Role::Operator, &[Scope::ApiWrite]).await;
    let res = send(
        &f.app,
        req(
            Method::POST,
            "/w",
            &[("authorization", &format!("Bearer {t}"))],
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn throttled_error_is_429_with_retry_after() {
    use axum::response::IntoResponse;
    let res = dnsy_api::error::ApiError::from(dnsy_auth::AuthError::Throttled {
        retry_after_secs: 7,
    })
    .into_response();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.headers()[header::RETRY_AFTER], "7");
    assert_eq!(body_json(res).await["retry_after_secs"], 7);
}

#[tokio::test]
async fn health_ready_version_are_public() {
    let f = fixture();
    for (path, key) in [
        ("/healthz", "status"),
        ("/readyz", "status"),
        ("/api/v1/version", "version"),
    ] {
        let res = send(&f.app, req(Method::GET, path, &[])).await;
        assert_eq!(res.status(), StatusCode::OK, "{path}");
        assert!(body_json(res).await.get(key).is_some());
    }
}

#[tokio::test]
async fn readyz_reports_untrusted_dnssec_clock() {
    let f = fixture();
    let res = send(&f.app, req(Method::GET, "/readyz", &[])).await;
    assert!(body_json(res).await.get("warnings").is_none());

    let config = dnsy_config::Config::default();
    let client =
        dnsy_resolver::UpstreamClient::new(dnsy_resolver::UpstreamConfig::default()).unwrap();
    let engine = Arc::new(
        dnsy_engine::EngineBuilder::new(&config, client)
            .services(&dnsy_engine::Services::bare(&config))
            .build(),
    );
    let app = router(
        f.state.clone().with_policy(engine.clone()),
        ApiConfig::default(),
    );
    let res = send(&app, req(Method::GET, "/readyz", &[])).await;
    assert!(body_json(res).await.get("warnings").is_none());
    engine
        .dnssec_clock_flag()
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let res = send(&app, req(Method::GET, "/readyz", &[])).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["status"], "ready");
    assert_eq!(body["warnings"][0], "dnssec_clock_untrusted");
}

#[tokio::test]
async fn unknown_api_path_is_404_problem_json() {
    let f = fixture();
    let res = send(&f.app, req(Method::GET, "/api/v1/nope", &[])).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert_eq!(res.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
}

#[tokio::test]
async fn framework_rejections_are_problem_json() {
    let f = fixture();
    let post = |ct: &str, body: &str| {
        Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/login")
            .header(header::CONTENT_TYPE, ct)
            .body(Body::from(body.to_owned()))
            .unwrap()
    };
    for (ct, body, status) in [
        ("application/json", "{", StatusCode::BAD_REQUEST),
        (
            "application/json",
            r#"{"username": 5}"#,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("text/plain", "x", StatusCode::UNSUPPORTED_MEDIA_TYPE),
    ] {
        let res = send(&f.app, post(ct, body)).await;
        assert_eq!(res.status(), status, "{ct} {body}");
        assert_eq!(res.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
        let p = body_json(res).await;
        assert_eq!(p["status"], status.as_u16());
        assert_ne!(p["detail"].as_str().unwrap(), "");
    }
    let res = send(&f.app, req(Method::GET, "/api/v1/auth/login", &[])).await;
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(res.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
    assert!(res.headers().contains_key(header::ALLOW));
    let big = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/zones")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(vec![b' '; 2 << 20]))
        .unwrap();
    let res = send(&f.app, big).await;
    assert!(matches!(
        res.status(),
        StatusCode::PAYLOAD_TOO_LARGE | StatusCode::UNAUTHORIZED
    ));
    assert_eq!(res.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
}

#[tokio::test]
async fn security_headers_present() {
    let f = fixture();
    let res = send(&f.app, req(Method::GET, "/healthz", &[])).await;
    let h = res.headers();
    assert!(
        h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .starts_with("default-src 'self'")
    );
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    assert!(h.get(header::STRICT_TRANSPORT_SECURITY).is_none());
    // Errors carry them too.
    let err = send(&f.app, req(Method::GET, "/api/v1/nope", &[])).await;
    assert_eq!(err.headers()[header::X_FRAME_OPTIONS], "DENY");
}

#[tokio::test]
async fn hsts_only_with_tls() {
    let f = fixture();
    let app = router(
        f.state.clone(),
        ApiConfig {
            tls: true,
            ..ApiConfig::default()
        },
    );
    let res = send(&app, req(Method::GET, "/healthz", &[])).await;
    assert!(
        res.headers()
            .get(header::STRICT_TRANSPORT_SECURITY)
            .is_some()
    );
}

#[tokio::test]
async fn ui_paths_404_without_embedded_ui() {
    if cfg!(feature = "embed-ui") {
        return;
    }
    let f = fixture();
    let res = send(&f.app, req(Method::GET, "/zones", &[])).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// With the UI embedded (`--features embed-ui`), the SPA shell is served brotli-compressed
/// when accepted and the response is smaller than the identity one.
#[tokio::test]
async fn ui_serves_brotli_when_accepted() {
    if !cfg!(feature = "embed-ui") {
        return;
    }
    let f = fixture();
    let plain = send(&f.app, req(Method::GET, "/", &[])).await;
    assert_eq!(plain.status(), StatusCode::OK);
    assert!(plain.headers().get(header::CONTENT_ENCODING).is_none());
    let plain_len = body_bytes_len(plain).await;
    let br = send(
        &f.app,
        req(Method::GET, "/", &[("accept-encoding", "br, gzip")]),
    )
    .await;
    assert_eq!(br.status(), StatusCode::OK);
    assert_eq!(br.headers()[header::CONTENT_ENCODING], "br");
    assert_eq!(br.headers()[header::VARY], "Accept-Encoding");
    assert!(body_bytes_len(br).await < plain_len);
}

async fn body_bytes_len(res: axum::response::Response) -> usize {
    axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap()
        .len()
}

#[tokio::test]
async fn openapi_endpoint_serves_spec() {
    let f = fixture();
    let res = send(&f.app, req(Method::GET, "/api/openapi.json", &[])).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body["openapi"].as_str().unwrap().starts_with("3.1"));
    assert!(body["paths"]["/api/v1/version"].is_object());
}

#[test]
fn openapi_spec_matches_committed() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../openapi/dnsy.json");
    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path).expect("openapi/dnsy.json missing: run `just openapi`"),
    )
    .unwrap();
    let generated = serde_json::to_value(openapi()).unwrap();
    assert_eq!(
        committed, generated,
        "openapi/dnsy.json is stale: run `just openapi`"
    );
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl io::Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn auth_headers_not_logged() {
    let f = fixture();
    let buf = Buf::default();
    let sink = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    let res = send(
        &f.app,
        req(
            Method::GET,
            "/r?x=1",
            &[
                ("authorization", "Bearer dnsy_SECRETTOKENVALUE"),
                (
                    "cookie",
                    "dnsy_session=SECRETSESSIONVALUE; dnsy_csrf=SECRETCSRF",
                ),
            ],
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("api request"), "request not traced: {logs}");
    for secret in [
        "SECRETTOKENVALUE",
        "SECRETSESSIONVALUE",
        "SECRETCSRF",
        "x=1",
    ] {
        assert!(!logs.contains(secret), "{secret} leaked into logs");
    }
}
