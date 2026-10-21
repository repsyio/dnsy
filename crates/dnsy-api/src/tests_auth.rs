//! Tests of the auth, users and tokens endpoints.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode, header};
use dnsy_auth::BootstrapCode;
use dnsy_core::{Role, Scope};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::{ApiConfig, ApiState, router};

const PW: &str = "correct-horse";

struct Fixture {
    state: ApiState,
    app: Router,
    _dir: tempfile::TempDir,
}

fn fixture_with(bootstrap: Option<Arc<BootstrapCode>>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let mut state = ApiState::new(store);
    if let Some(code) = bootstrap {
        state = state.with_bootstrap(code);
    }
    let app = router(
        state.clone(),
        ApiConfig {
            tls: false,
            ..ApiConfig::default()
        },
    );
    Fixture {
        state,
        app,
        _dir: dir,
    }
}

fn fixture() -> Fixture {
    fixture_with(None)
}

/// A request; `auth` is either `Bearer ...` or a cookie header value.
fn req(method: Method, uri: &str, auth: Option<&Cred>, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    match auth {
        Some(Cred::Bearer(t)) => b = b.header(header::AUTHORIZATION, format!("Bearer {t}")),
        Some(Cred::Session { id, csrf }) => {
            b = b
                .header(
                    header::COOKIE,
                    format!("dnsy_session={id}; dnsy_csrf={csrf}"),
                )
                .header("x-csrf-token", csrf);
        }
        None => {}
    }
    match body {
        Some(v) => b
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

enum Cred {
    Bearer(String),
    Session { id: String, csrf: String },
}

/// Like the real listener, the request carries its peer address.
async fn call(f: &Fixture, mut r: Request<Body>) -> Response<Body> {
    r.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40_000,
        ))));
    f.app.clone().oneshot(r).await.unwrap()
}

async fn json_of(res: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn set_cookies(res: &Response<Body>) -> Vec<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

fn cookie_value(cookies: &[String], name: &str) -> String {
    let prefix = format!("{name}=");
    cookies
        .iter()
        .find_map(|c| c.strip_prefix(&prefix))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn login(f: &Fixture, username: &str, password: &str) -> Response<Body> {
    call(
        f,
        req(
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({"username": username, "password": password})),
        ),
    )
    .await
}

async fn session_for(f: &Fixture, username: &str, role: Role) -> Cred {
    f.state.auth.users.create(username, PW, role).await.unwrap();
    let res = login(f, username, PW).await;
    assert_eq!(res.status(), StatusCode::OK);
    let c = set_cookies(&res);
    Cred::Session {
        id: cookie_value(&c, "dnsy_session"),
        csrf: cookie_value(&c, "dnsy_csrf"),
    }
}

async fn status(
    f: &Fixture,
    method: Method,
    uri: &str,
    c: &Cred,
    body: Option<Value>,
) -> StatusCode {
    call(f, req(method, uri, Some(c), body)).await.status()
}

#[tokio::test]
async fn login_sets_session_and_csrf_cookies() {
    let f = fixture();
    f.state
        .auth
        .users
        .create("alice", PW, Role::Viewer)
        .await
        .unwrap();
    let res = login(&f, "alice", PW).await;
    assert_eq!(res.status(), StatusCode::OK);
    let cookies = set_cookies(&res);
    assert_eq!(cookies.len(), 2);
    let session = cookies
        .iter()
        .find(|c| c.starts_with("dnsy_session="))
        .unwrap();
    assert!(session.contains("HttpOnly") && session.contains("SameSite=Strict"));
    let csrf = cookies
        .iter()
        .find(|c| c.starts_with("dnsy_csrf="))
        .unwrap();
    assert!(!csrf.contains("HttpOnly"));
    assert!(!csrf.starts_with("dnsy_csrf=;"));
    let body = json_of(res).await;
    assert_eq!(body["username"], "alice");
    assert_eq!(body["role"], "viewer");
    assert!(body.get("password_hash").is_none());
}

#[tokio::test]
async fn login_wrong_password_401() {
    let f = fixture();
    f.state
        .auth
        .users
        .create("alice", PW, Role::Viewer)
        .await
        .unwrap();
    assert_eq!(
        login(&f, "alice", "nope-nope").await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&f, "ghost", "nope-nope").await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn login_throttled_429() {
    let f = fixture();
    f.state
        .auth
        .users
        .create("alice", PW, Role::Viewer)
        .await
        .unwrap();
    for _ in 0..dnsy_auth::MAX_FAILURES {
        assert_eq!(
            login(&f, "alice", "bad-bad-bad").await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let res = login(&f, "alice", PW).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key(header::RETRY_AFTER));
}

#[tokio::test]
async fn login_without_a_peer_address_fails_closed() {
    let f = fixture();
    f.state
        .auth
        .users
        .create("alice", PW, Role::Viewer)
        .await
        .unwrap();
    let r = req(
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({"username": "alice", "password": PW})),
    );
    let res = f.app.clone().oneshot(r).await.unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn password_over_1_kib_is_a_400_without_hashing() {
    let f = fixture();
    let res = login(&f, "alice", &"x".repeat(1025)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn me_logout_and_session_reuse() {
    let f = fixture();
    let s = session_for(&f, "alice", Role::Operator).await;
    let res = call(&f, req(Method::GET, "/api/v1/auth/me", Some(&s), None)).await;
    assert_eq!(res.status(), StatusCode::OK);
    let me = json_of(res).await;
    assert_eq!(
        (me["username"].as_str(), me["auth"].as_str()),
        (Some("alice"), Some("session"))
    );

    let res = call(&f, req(Method::POST, "/api/v1/auth/logout", Some(&s), None)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert!(set_cookies(&res).iter().all(|c| c.contains("Max-Age=0")));
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &s, None).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bootstrap_creates_first_admin_once() {
    let (code, plain) = BootstrapCode::generate(Duration::from_secs(60));
    let f = fixture_with(Some(Arc::new(code)));
    let body = |c: &str| json!({"code": c, "username": "root", "password": PW});
    let post = |b: Value| req(Method::POST, "/api/v1/auth/bootstrap", None, Some(b));

    assert_eq!(
        call(&f, post(body("wrong"))).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let res = call(
        &f,
        post(json!({"code": plain, "username": "root", "password": "short"})),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = call(&f, post(body(&plain))).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(json_of(res).await["role"], "admin");
    assert_eq!(
        call(&f, post(body(&plain))).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(login(&f, "root", PW).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn bootstrap_without_code_is_401() {
    let f = fixture();
    let r = req(
        Method::POST,
        "/api/v1/auth/bootstrap",
        None,
        Some(json!({"code": "x", "username": "root", "password": PW})),
    );
    assert_eq!(call(&f, r).await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn viewer_cannot_create_users() {
    let f = fixture();
    let s = session_for(&f, "vera", Role::Viewer).await;
    let body = json!({"username": "x", "password": PW, "role": "viewer"});
    assert_eq!(
        status(&f, Method::POST, "/api/v1/users", &s, Some(body)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&f, Method::GET, "/api/v1/users", &s, None).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn user_crud_roundtrip() {
    let f = fixture();
    let admin = session_for(&f, "root", Role::Admin).await;
    let res = call(
        &f,
        req(
            Method::POST,
            "/api/v1/users",
            Some(&admin),
            Some(json!({"username": "bob", "password": PW, "role": "viewer"})),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let id = json_of(res).await["id"].as_i64().unwrap();
    let uri = format!("/api/v1/users/{id}");

    let dup = json!({"username": "bob", "password": PW, "role": "viewer"});
    assert_eq!(
        status(&f, Method::POST, "/api/v1/users", &admin, Some(dup)).await,
        StatusCode::CONFLICT
    );
    let weak = json!({"username": "weak", "password": "short", "role": "viewer"});
    assert_eq!(
        status(&f, Method::POST, "/api/v1/users", &admin, Some(weak)).await,
        StatusCode::BAD_REQUEST
    );

    let res = call(
        &f,
        req(
            Method::PATCH,
            &uri,
            Some(&admin),
            Some(json!({"role": "operator"})),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(json_of(res).await["role"], "operator");
    let res = call(&f, req(Method::GET, "/api/v1/users", Some(&admin), None)).await;
    assert_eq!(json_of(res).await.as_array().unwrap().len(), 2);
    assert_eq!(
        status(&f, Method::GET, "/api/v1/users/9999", &admin, None).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(&f, Method::DELETE, &uri, &admin, None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status(&f, Method::GET, &uri, &admin, None).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn cannot_delete_last_admin_409() {
    let f = fixture();
    let admin = session_for(&f, "root", Role::Admin).await;
    let id = f.state.auth.users.list().await.unwrap()[0].id.0;
    let uri = format!("/api/v1/users/{id}");
    assert_eq!(
        status(&f, Method::DELETE, &uri, &admin, None).await,
        StatusCode::CONFLICT
    );
    let demote = json!({"role": "viewer"});
    assert_eq!(
        status(&f, Method::PATCH, &uri, &admin, Some(demote)).await,
        StatusCode::CONFLICT
    );
}

async fn create_token(f: &Fixture, s: &Cred, scopes: &[&str]) -> Response<Body> {
    call(
        f,
        req(
            Method::POST,
            "/api/v1/tokens",
            Some(s),
            Some(json!({"name": "ci", "scopes": scopes})),
        ),
    )
    .await
}

#[tokio::test]
async fn token_secret_returned_once() {
    let f = fixture();
    let s = session_for(&f, "root", Role::Admin).await;
    let res = create_token(&f, &s, &["api:read"]).await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let created = json_of(res).await;
    let secret = created["token"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("dnsy_"));
    assert_eq!(created["meta"]["scopes"], json!(["api:read"]));

    let res = call(&f, req(Method::GET, "/api/v1/tokens", Some(&s), None)).await;
    let text = json_of(res).await.to_string();
    assert!(!text.contains(&secret));
    assert!(text.contains("\"ci\""));

    let bearer = Cred::Bearer(secret);
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &bearer, None).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn token_name_over_128_rejected() {
    let f = fixture();
    let s = session_for(&f, "root", Role::Admin).await;
    let long = json!({"name": "n".repeat(129), "scopes": ["api:read"]});
    let res = call(
        &f,
        req(Method::POST, "/api/v1/tokens", Some(&s), Some(long)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        res.headers()[axum::http::header::CONTENT_TYPE],
        "application/problem+json"
    );
    let edge = json!({"name": "n".repeat(128), "scopes": ["api:read"]});
    let res = call(
        &f,
        req(Method::POST, "/api/v1/tokens", Some(&s), Some(edge)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn token_count_per_user_is_capped() {
    let f = fixture();
    let s = session_for(&f, "root", Role::Admin).await;
    let id = f.state.auth.users.list().await.unwrap()[0].id;
    for _ in 0..99 {
        f.state
            .auth
            .tokens
            .create(id, "bulk", &[Scope::ApiRead], None)
            .await
            .unwrap();
    }
    assert_eq!(
        create_token(&f, &s, &["api:read"]).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        create_token(&f, &s, &["api:read"]).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn username_over_64_rejected() {
    let f = fixture();
    let s = session_for(&f, "root", Role::Admin).await;
    let body = |n: usize| json!({"username": "u".repeat(n), "password": PW, "role": "viewer"});
    assert_eq!(
        status(&f, Method::POST, "/api/v1/users", &s, Some(body(65))).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        status(&f, Method::POST, "/api/v1/users", &s, Some(body(64))).await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn token_creation_rules() {
    let f = fixture();
    let viewer = session_for(&f, "vera", Role::Viewer).await;
    assert_eq!(
        create_token(&f, &viewer, &["admin"]).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        create_token(&f, &viewer, &[]).await.status(),
        StatusCode::BAD_REQUEST
    );
    let blank = json!({"name": " ", "scopes": ["api:read"]});
    assert_eq!(
        status(&f, Method::POST, "/api/v1/tokens", &viewer, Some(blank)).await,
        StatusCode::BAD_REQUEST
    );
    // A token cannot mint tokens.
    let secret = json_of(create_token(&f, &viewer, &["api:read"]).await).await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let by_token = Cred::Bearer(secret);
    let body = json!({"name": "x", "scopes": ["api:read"]});
    assert_eq!(
        status(&f, Method::POST, "/api/v1/tokens", &by_token, Some(body)).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn token_list_scoping_and_revoke() {
    let f = fixture();
    let admin = session_for(&f, "root", Role::Admin).await;
    let bob = session_for(&f, "bob", Role::Viewer).await;
    let carol = session_for(&f, "carol", Role::Viewer).await;
    let admin_tok = json_of(create_token(&f, &admin, &["api:read"]).await).await["meta"]["id"]
        .as_i64()
        .unwrap();
    let bob_tok = json_of(create_token(&f, &bob, &["api:read"]).await).await["meta"]["id"]
        .as_i64()
        .unwrap();

    let list = |c: &Cred| {
        let res = call(&f, req(Method::GET, "/api/v1/tokens", Some(c), None));
        async move { json_of(res.await).await.as_array().unwrap().len() }
    };
    assert_eq!(list(&bob).await, 1);
    assert_eq!(list(&carol).await, 0);
    assert_eq!(list(&admin).await, 2);

    // Not yours: indistinguishable from missing.
    let uri = format!("/api/v1/tokens/{admin_tok}");
    assert_eq!(
        status(&f, Method::DELETE, &uri, &bob, None).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(&f, Method::DELETE, "/api/v1/tokens/1", &bob, None).await,
        StatusCode::NOT_FOUND
    );
    // Admin revokes someone else's; revoked tokens stop working.
    let secret_res = create_token(&f, &carol, &["api:read"]).await;
    let created = json_of(secret_res).await;
    let carol_secret = Cred::Bearer(created["token"].as_str().unwrap().to_owned());
    let carol_id = created["meta"]["id"].as_i64().unwrap();
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &carol_secret, None).await,
        StatusCode::OK
    );
    let uri = format!("/api/v1/tokens/{carol_id}");
    assert_eq!(
        status(&f, Method::DELETE, &uri, &admin, None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &carol_secret, None).await,
        StatusCode::UNAUTHORIZED
    );
    let uri = format!("/api/v1/tokens/{bob_tok}");
    assert_eq!(
        status(&f, Method::DELETE, &uri, &bob, None).await,
        StatusCode::NO_CONTENT
    );
}

// --- security regressions -------------------------------------------------

#[tokio::test]
async fn demoted_user_old_admin_token_is_rejected() {
    let f = fixture();
    f.state
        .auth
        .users
        .create("root", PW, Role::Admin)
        .await
        .unwrap();
    let ann = f
        .state
        .auth
        .users
        .create("ann", PW, Role::Admin)
        .await
        .unwrap();
    let (secret, _) = f
        .state
        .auth
        .tokens
        .create(ann.id, "old", &[Scope::Admin, Scope::ApiRead], None)
        .await
        .unwrap();
    let bearer = Cred::Bearer(secret);
    assert_eq!(
        status(&f, Method::GET, "/api/v1/users", &bearer, None).await,
        StatusCode::OK
    );

    f.state
        .auth
        .users
        .update_role(ann.id, Role::Viewer)
        .await
        .unwrap();
    assert_eq!(
        status(&f, Method::GET, "/api/v1/users", &bearer, None).await,
        StatusCode::FORBIDDEN
    );
    // Still fine for what the viewer role allows.
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &bearer, None).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn password_change_ends_old_sessions_and_keeps_current_client_logged_in() {
    let f = fixture();
    let first = session_for(&f, "ann", Role::Operator).await;
    let res = login(&f, "ann", PW).await;
    let c = set_cookies(&res);
    let second = Cred::Session {
        id: cookie_value(&c, "dnsy_session"),
        csrf: cookie_value(&c, "dnsy_csrf"),
    };

    let wrong = json!({"current_password": "nope-nope", "new_password": "brand-new-pw"});
    assert_eq!(
        status(
            &f,
            Method::PUT,
            "/api/v1/auth/me/password",
            &first,
            Some(wrong)
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    let weak = json!({"current_password": PW, "new_password": "short"});
    assert_eq!(
        status(
            &f,
            Method::PUT,
            "/api/v1/auth/me/password",
            &first,
            Some(weak)
        )
        .await,
        StatusCode::BAD_REQUEST
    );

    let change = json!({"current_password": PW, "new_password": "brand-new-pw"});
    let res = call(
        &f,
        req(
            Method::PUT,
            "/api/v1/auth/me/password",
            Some(&first),
            Some(change),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let c = set_cookies(&res);
    let fresh = Cred::Session {
        id: cookie_value(&c, "dnsy_session"),
        csrf: cookie_value(&c, "dnsy_csrf"),
    };

    for old in [&first, &second] {
        assert_eq!(
            status(&f, Method::GET, "/api/v1/auth/me", old, None).await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &fresh, None).await,
        StatusCode::OK
    );
    assert_eq!(
        login(&f, "ann", PW).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&f, "ann", "brand-new-pw").await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn password_change_requires_session() {
    let f = fixture();
    let u = f
        .state
        .auth
        .users
        .create("ann", PW, Role::Viewer)
        .await
        .unwrap();
    let (secret, _) = f
        .state
        .auth
        .tokens
        .create(u.id, "t", &[Scope::ApiRead], None)
        .await
        .unwrap();
    let body = json!({"current_password": PW, "new_password": "brand-new-pw"});
    let st = status(
        &f,
        Method::PUT,
        "/api/v1/auth/me/password",
        &Cred::Bearer(secret),
        Some(body),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn role_change_and_admin_password_reset_end_sessions() {
    let f = fixture();
    let admin = session_for(&f, "root", Role::Admin).await;
    let bob = session_for(&f, "bob", Role::Operator).await;
    let bob_id = f
        .state
        .auth
        .users
        .list()
        .await
        .unwrap()
        .iter()
        .find(|u| u.username == "bob")
        .unwrap()
        .id
        .0;
    let uri = format!("/api/v1/users/{bob_id}");

    let demote = json!({"role": "viewer"});
    assert_eq!(
        status(&f, Method::PATCH, &uri, &admin, Some(demote)).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &bob, None).await,
        StatusCode::UNAUTHORIZED
    );

    let again = login(&f, "bob", PW).await;
    let c = set_cookies(&again);
    let bob2 = Cred::Session {
        id: cookie_value(&c, "dnsy_session"),
        csrf: cookie_value(&c, "dnsy_csrf"),
    };
    let reset = json!({"password": "reset-by-admin"});
    assert_eq!(
        status(&f, Method::PATCH, &uri, &admin, Some(reset)).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &bob2, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&f, "bob", "reset-by-admin").await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn deleted_users_token_and_session_stop_working() {
    let f = fixture();
    let admin = session_for(&f, "root", Role::Admin).await;
    let bob = session_for(&f, "bob", Role::Operator).await;
    let bob_user = f
        .state
        .auth
        .users
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|u| u.username == "bob")
        .unwrap();
    let (secret, _) = f
        .state
        .auth
        .tokens
        .create(bob_user.id, "t", &[Scope::ApiRead], None)
        .await
        .unwrap();
    let bearer = Cred::Bearer(secret);
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &bearer, None).await,
        StatusCode::OK
    );

    let uri = format!("/api/v1/users/{}", bob_user.id.0);
    assert_eq!(
        status(&f, Method::DELETE, &uri, &admin, None).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &bearer, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&f, Method::GET, "/api/v1/auth/me", &bob, None).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn disabled_users_lose_sessions_tokens_and_login_until_enabled() {
    let f = fixture();
    let admin = session_for(&f, "root", Role::Admin).await;
    let bob = session_for(&f, "bob", Role::Operator).await;
    let bob_user = f
        .state
        .auth
        .users
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|u| u.username == "bob")
        .unwrap();
    let (secret, _) = f
        .state
        .auth
        .tokens
        .create(bob_user.id, "t", &[Scope::ApiRead], None)
        .await
        .unwrap();
    let bearer = Cred::Bearer(secret);
    let me = "/api/v1/auth/me";
    assert_eq!(
        status(&f, Method::GET, me, &bearer, None).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&f, Method::GET, me, &bob, None).await,
        StatusCode::OK
    );

    let uri = format!("/api/v1/users/{}", bob_user.id.0);
    let res = call(
        &f,
        req(
            Method::PATCH,
            &uri,
            Some(&admin),
            Some(json!({"disabled": true})),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = json_of(res).await;
    assert_eq!(body["disabled"], true);
    assert!(body["disabled_at"].as_i64().is_some());

    // Effective at once: session, token and login are all refused.
    assert_eq!(
        status(&f, Method::GET, me, &bearer, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&f, Method::GET, me, &bob, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        login(&f, "bob", PW).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let listed = call(&f, req(Method::GET, "/api/v1/users", Some(&admin), None)).await;
    let listed = json_of(listed).await;
    let entry = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "bob")
        .unwrap();
    assert_eq!(entry["disabled"], true);

    // Enabling restores the token and login, not the old session.
    let res = call(
        &f,
        req(
            Method::PATCH,
            &uri,
            Some(&admin),
            Some(json!({"disabled": false})),
        ),
    )
    .await;
    assert_eq!(json_of(res).await["disabled"], false);
    assert_eq!(
        status(&f, Method::GET, me, &bearer, None).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&f, Method::GET, me, &bob, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(login(&f, "bob", PW).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn last_active_admin_cannot_be_disabled_over_the_api() {
    let f = fixture();
    let root = session_for(&f, "root", Role::Admin).await;
    let other = session_for(&f, "other", Role::Admin).await;
    let users = f.state.auth.users.list().await.unwrap();
    let id = |name: &str| users.iter().find(|u| u.username == name).unwrap().id.0;
    let (root_uri, other_uri) = (
        format!("/api/v1/users/{}", id("root")),
        format!("/api/v1/users/{}", id("other")),
    );
    let off = || Some(json!({"disabled": true}));

    assert_eq!(
        status(&f, Method::PATCH, &other_uri, &root, off()).await,
        StatusCode::OK
    );
    // `root` is the only active admin now.
    assert_eq!(
        status(&f, Method::PATCH, &root_uri, &root, off()).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        status(&f, Method::DELETE, &root_uri, &root, None).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        status(
            &f,
            Method::PATCH,
            &root_uri,
            &root,
            Some(json!({"role": "viewer"}))
        )
        .await,
        StatusCode::CONFLICT
    );
    // The disabled admin's session is gone; non-admins cannot disable anyone.
    assert_eq!(
        status(&f, Method::GET, "/api/v1/users", &other, None).await,
        StatusCode::UNAUTHORIZED
    );
    let viewer = session_for(&f, "view", Role::Viewer).await;
    assert_eq!(
        status(&f, Method::PATCH, &root_uri, &viewer, off()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status(&f, Method::PATCH, "/api/v1/users/9999", &root, off()).await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn secure_cookie_flag_follows_tls_config() {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let state = ApiState::new(store);
    state
        .auth
        .users
        .create("alice", PW, Role::Viewer)
        .await
        .unwrap();
    let app = router(
        state,
        ApiConfig {
            tls: true,
            ..ApiConfig::default()
        },
    );
    let r = req(
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({"username": "alice", "password": PW})),
    );
    let res = app.oneshot(r).await.unwrap();
    assert!(set_cookies(&res).iter().all(|c| c.contains("; Secure")));
}

#[tokio::test]
async fn secure_cookies_true_overrides_missing_tls() {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let state = ApiState::new(store);
    state
        .auth
        .users
        .create("alice", PW, Role::Viewer)
        .await
        .unwrap();
    let config = ApiConfig {
        tls: false,
        secure_cookies: Some(true),
    };
    let app = router(state, config);
    let mut r = req(
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({"username": "alice", "password": PW})),
    );
    r.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40_000,
        ))));
    let res = app.oneshot(r).await.unwrap();
    let cookies = set_cookies(&res);
    assert_eq!(cookies.len(), 2);
    assert!(
        cookies.iter().all(|c| c.contains("; Secure")),
        "{cookies:?}"
    );
    assert!(
        res.headers()
            .contains_key(axum::http::header::STRICT_TRANSPORT_SECURITY)
    );
}

#[tokio::test]
async fn secure_cookies_false_overrides_tls() {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let state = ApiState::new(store);
    state
        .auth
        .users
        .create("alice", PW, Role::Viewer)
        .await
        .unwrap();
    let config = ApiConfig {
        tls: true,
        secure_cookies: Some(false),
    };
    let app = router(state, config);
    let r = req(
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({"username": "alice", "password": PW})),
    );
    let res = app.oneshot(r).await.unwrap();
    assert!(set_cookies(&res).iter().all(|c| !c.contains("Secure")));
    assert!(
        !res.headers()
            .contains_key(axum::http::header::STRICT_TRANSPORT_SECURITY)
    );
}
