//! REST API authentication: bootstrap, login and logout, session cookies and CSRF, tokens,
//! throttling, password change and what a demoted user's credentials can still do.

use dnsy_e2e::{Auth, Harness, Opts};
use reqwest::Method;
use serde_json::json;

const ADMIN: &str = "e2e";
const ADMIN_PW: &str = "e2e-password-1234";

async fn start() -> Harness {
    Harness::start(Opts::default()).await
}

// ---- bootstrap ----

#[tokio::test]
async fn bootstrap_creates_the_first_admin_exactly_once() {
    let h = Harness::start(Opts {
        no_users: true,
        ..Opts::default()
    })
    .await;
    let api = h.rest();
    let code = h.bootstrap_code().await;
    let body = |code: &str, pw: &str| json!({"code": code, "username": "root", "password": pw});

    // Nothing works before the bootstrap.
    api.get("/zones", Auth::None).await.problem(401);
    // A wrong code and a short password are refused and do not burn the real code.
    api.post(
        "/auth/bootstrap",
        Auth::None,
        &body("wrong", "long-enough-pw"),
    )
    .await
    .problem(401);
    api.post("/auth/bootstrap", Auth::None, &body(&code, "short"))
        .await
        .problem(400);

    let created = api
        .post(
            "/auth/bootstrap",
            Auth::None,
            &body(&code, "long-enough-pw"),
        )
        .await
        .ok(201);
    assert_eq!(created["username"], "root");
    assert_eq!(created["role"], "admin");
    assert!(created.get("password").is_none() && created.get("password_hash").is_none());

    // The new admin can log in; a second bootstrap is a conflict, with the same or a fresh code.
    let session = api.login("root", "long-enough-pw").await;
    let me = api.get("/auth/me", Auth::Session(&session)).await.ok(200);
    assert_eq!(
        (me["username"].as_str(), me["auth"].as_str()),
        (Some("root"), Some("session"))
    );
    api.post(
        "/auth/bootstrap",
        Auth::None,
        &body(&code, "long-enough-pw"),
    )
    .await
    .problem(409);
    assert!(
        !h.logs().contains("long-enough-pw"),
        "the password never reaches the log"
    );
}

#[tokio::test]
async fn bootstrap_is_closed_when_users_exist() {
    let h = start().await;
    let r = h
        .rest()
        .post(
            "/auth/bootstrap",
            Auth::None,
            &json!({"code": "anything", "username": "mallory", "password": "long-enough-pw"}),
        )
        .await;
    r.problem(409);
    assert!(
        !h.logs().contains("bootstrap code"),
        "no code is printed when users exist"
    );
}

// ---- login, cookies, logout ----

#[tokio::test]
async fn login_sets_hardened_session_and_csrf_cookies() {
    let h = start().await;
    let r = h.rest().login_resp(ADMIN, ADMIN_PW).await;
    let user = r.ok(200);
    assert_eq!(
        (user["username"].as_str(), user["role"].as_str()),
        (Some(ADMIN), Some("admin"))
    );
    assert!(
        user.to_string().to_lowercase().find("password").is_none(),
        "{user}"
    );

    let session = r.cookie_line("dnsy_session").expect("session cookie");
    assert!(session.contains("HttpOnly"), "{session}");
    assert!(session.contains("SameSite=Strict"), "{session}");
    assert!(session.contains("Path=/"), "{session}");
    assert!(session.contains("Max-Age="), "{session}");
    assert!(
        !session.contains("Secure"),
        "plain HTTP listener: {session}"
    );
    let csrf = r.cookie_line("dnsy_csrf").expect("csrf cookie");
    assert!(
        !csrf.contains("HttpOnly"),
        "the UI must read the CSRF cookie: {csrf}"
    );
    assert!(csrf.contains("SameSite=Strict"), "{csrf}");
    assert_eq!(r.header("cache-control"), Some("no-store"));
    // A fresh login rotates both values.
    let again = h.rest().login_resp(ADMIN, ADMIN_PW).await;
    assert_ne!(
        r.cookie_value("dnsy_session"),
        again.cookie_value("dnsy_session")
    );
    assert_ne!(r.cookie_value("dnsy_csrf"), again.cookie_value("dnsy_csrf"));
}

#[tokio::test]
async fn login_failures_do_not_reveal_which_part_was_wrong() {
    let h = start().await;
    let api = h.rest();
    let wrong_pw = api.login_resp(ADMIN, "not-the-password").await;
    let no_user = api.login_resp("nobody", "not-the-password").await;
    let a = wrong_pw.problem(401);
    let b = no_user.problem(401);
    assert_eq!(a, b, "same problem document for both");
    assert_eq!(wrong_pw.header("www-authenticate"), Some("Bearer"));
    assert!(wrong_pw.cookie_line("dnsy_session").is_none());

    // Malformed bodies are client errors, never a 500.
    for (body, ct) in [
        (b"{".to_vec(), "application/json"),
        (b"{\"username\": \"x\"}".to_vec(), "application/json"),
        (
            b"username=x&password=y".to_vec(),
            "application/x-www-form-urlencoded",
        ),
    ] {
        let r = api
            .req(Method::POST, "/auth/login")
            .body(body, ct)
            .send()
            .await;
        assert!(
            (400..500).contains(&r.status) && r.status != 429,
            "malformed login body gave {}: {}",
            r.status,
            r.text
        );
    }
}

#[tokio::test]
async fn session_cookie_authenticates_reads_and_mutations_need_csrf() {
    let h = start().await;
    let api = h.rest();
    let s = api.login(ADMIN, ADMIN_PW).await;
    api.get("/zones", Auth::Session(&s)).await.ok(200);
    // Reads need no CSRF header.
    api.get("/zones", Auth::SessionCookieOnly(&s)).await.ok(200);

    let acl = json!({"cidr": "198.51.100.0/24", "action": "refuse"});
    for auth in [
        Auth::SessionNoCsrfHeader(&s),
        Auth::SessionWrongCsrf(&s),
        Auth::SessionCookieOnly(&s),
    ] {
        let r = api.post("/acl", auth, &acl).await;
        r.problem(403);
    }
    assert!(
        api.get("/acl", Auth::Session(&s)).await.json()["rules"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a rejected request changed nothing"
    );
    api.post("/acl", Auth::Session(&s), &acl).await.ok(201);
    // A bearer token needs no CSRF header.
    api.post(
        "/acl",
        Auth::Bearer(&h.api_token),
        &json!({"cidr": "198.51.100.7", "action": "drop"}),
    )
    .await
    .ok(201);
}

#[tokio::test]
async fn logout_ends_the_session_and_clears_the_cookies() {
    let h = start().await;
    let api = h.rest();
    let s = api.login(ADMIN, ADMIN_PW).await;
    // Logout is a mutation: it needs the CSRF header too.
    api.post("/auth/logout", Auth::SessionNoCsrfHeader(&s), &json!({}))
        .await
        .problem(403);
    api.get("/auth/me", Auth::Session(&s)).await.ok(200);

    let out = api
        .post("/auth/logout", Auth::Session(&s), &json!({}))
        .await;
    assert_eq!(out.status, 204, "{}", out.text);
    for name in ["dnsy_session", "dnsy_csrf"] {
        let line = out.cookie_line(name).unwrap_or_default();
        assert!(line.contains("Max-Age=0"), "{name} is cleared: {line}");
    }
    api.get("/auth/me", Auth::Session(&s)).await.problem(401);
    api.post("/auth/logout", Auth::Session(&s), &json!({}))
        .await
        .problem(401);
    // Other credentials of the same user are unaffected.
    api.get("/auth/me", Auth::Bearer(&h.api_token))
        .await
        .ok(200);
}

#[tokio::test]
async fn missing_forged_and_malformed_credentials_are_401() {
    let h = start().await;
    let api = h.rest();
    api.get("/auth/me", Auth::None).await.problem(401);
    let forged = dnsy_e2e::Session {
        id: "forged-session-id".into(),
        csrf: "x".into(),
    };
    api.get("/auth/me", Auth::Session(&forged))
        .await
        .problem(401);
    api.get("/auth/me", Auth::Bearer("dnsy_not_a_real_token"))
        .await
        .problem(401);
    api.get("/auth/me", Auth::Bearer("")).await.problem(401);
    for header in ["Basic dXNlcjpwYXNz", "Bearer", "token abc", "Bearer  "] {
        let r = api
            .req(Method::GET, "/auth/me")
            .header("authorization", header)
            .send()
            .await;
        r.problem(401);
    }
    // A bad bearer token is not rescued by a valid session.
    let s = api.login(ADMIN, ADMIN_PW).await;
    let r = api
        .req(Method::GET, "/auth/me")
        .auth(Auth::Session(&s))
        .header("authorization", "Bearer bad")
        .send()
        .await;
    r.problem(401);
    assert!(
        !h.logs().contains("dnsy_not_a_real_token"),
        "credentials never reach the log"
    );
}

#[tokio::test]
async fn me_reports_how_the_caller_authenticated() {
    let h = start().await;
    let api = h.rest();
    let by_token = api
        .get("/auth/me", Auth::Bearer(&h.api_token))
        .await
        .ok(200);
    assert_eq!(by_token["auth"], "token");
    assert_eq!(by_token["username"], ADMIN);
    let s = api.login(ADMIN, ADMIN_PW).await;
    assert_eq!(
        api.get("/auth/me", Auth::Session(&s)).await.ok(200)["auth"],
        "session"
    );
}

// ---- throttling ----

#[tokio::test]
async fn repeated_failed_logins_are_throttled_with_retry_after() {
    let h = start().await;
    let api = h.rest();
    for _ in 0..5 {
        api.login_resp(ADMIN, "wrong-password").await.problem(401);
    }
    let r = api.login_resp(ADMIN, "wrong-password").await;
    let p = r.problem(429);
    let secs = p["retry_after_secs"].as_u64().expect("retry_after_secs");
    assert!((1..=15 * 60).contains(&secs), "{p}");
    assert_eq!(
        r.header("retry-after"),
        Some(secs.to_string().as_str()),
        "header matches body"
    );
    // The correct password is refused while throttled, so guessing cannot be paced.
    api.login_resp(ADMIN, ADMIN_PW).await.problem(429);
    // Throttling is per username: another account is unaffected, and the API stays usable.
    api.create_user(&h.api_token, "alice", "alice-password-1", "viewer")
        .await;
    api.login("alice", "alice-password-1").await;
    api.get("/zones", Auth::Bearer(&h.api_token)).await.ok(200);
}

#[tokio::test]
async fn a_successful_login_resets_the_failure_count() {
    let h = start().await;
    let api = h.rest();
    for _ in 0..4 {
        api.login_resp(ADMIN, "wrong").await.problem(401);
    }
    api.login(ADMIN, ADMIN_PW).await;
    for _ in 0..4 {
        api.login_resp(ADMIN, "wrong").await.problem(401);
    }
    api.login(ADMIN, ADMIN_PW).await;
}

// ---- password change ----

#[tokio::test]
async fn password_change_ends_every_session_and_starts_a_new_one() {
    let h = start().await;
    let api = h.rest();
    let first = api.login(ADMIN, ADMIN_PW).await;
    let second = api.login(ADMIN, ADMIN_PW).await;
    let path = "/auth/me/password";
    let change =
        |current: &str, new: &str| json!({"current_password": current, "new_password": new});

    // Bearer tokens cannot change passwords; wrong current password, short new password.
    api.put(
        path,
        Auth::Bearer(&h.api_token),
        &change(ADMIN_PW, "new-password-1"),
    )
    .await
    .problem(403);
    api.put(
        path,
        Auth::Session(&first),
        &change("wrong", "new-password-1"),
    )
    .await
    .problem(401);
    api.put(path, Auth::Session(&first), &change(ADMIN_PW, "short"))
        .await
        .problem(400);
    api.put(
        path,
        Auth::SessionNoCsrfHeader(&first),
        &change(ADMIN_PW, "new-password-1"),
    )
    .await
    .problem(403);
    api.get("/auth/me", Auth::Session(&first)).await.ok(200);

    let r = api
        .put(
            path,
            Auth::Session(&first),
            &change(ADMIN_PW, "new-password-1"),
        )
        .await;
    r.ok(200);
    let fresh = dnsy_e2e::api::session_of(&r);

    // Every old session is gone, including the one that made the change; the new one works.
    api.get("/auth/me", Auth::Session(&first))
        .await
        .problem(401);
    api.get("/auth/me", Auth::Session(&second))
        .await
        .problem(401);
    api.get("/auth/me", Auth::Session(&fresh)).await.ok(200);
    api.login_resp(ADMIN, ADMIN_PW).await.problem(401);
    api.login(ADMIN, "new-password-1").await;
}

// ---- tokens ----

#[tokio::test]
async fn token_lifecycle_create_use_list_revoke() {
    let h = start().await;
    let api = h.rest();
    let s = api.login(ADMIN, ADMIN_PW).await;
    let created = api
        .post(
            "/tokens",
            Auth::Session(&s),
            &json!({"name": "ci", "scopes": ["api:read"]}),
        )
        .await
        .ok(201);
    let secret = created["token"].as_str().expect("secret").to_owned();
    let id = created["meta"]["id"].as_i64().unwrap();
    assert_eq!(created["meta"]["name"], "ci");
    assert_eq!(created["meta"]["scopes"], json!(["api:read"]));
    assert_eq!(created["meta"]["revoked"], false);
    assert!(created["meta"].get("token").is_none() && created["meta"].get("secret").is_none());

    // The secret works as a bearer token for what its scope allows.
    let me = api.get("/auth/me", Auth::Bearer(&secret)).await.ok(200);
    assert_eq!(me["auth"], "token");

    // The secret is shown once: listing never contains it, `last_used_at` is recorded.
    let list = api.get("/tokens", Auth::Session(&s)).await;
    assert!(!list.text.contains(&secret), "the secret is not listed");
    let listed = list
        .json()
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == id)
        .cloned()
        .expect("token listed");
    assert!(listed["last_used_at"].is_i64(), "{listed}");

    // Revocation is immediate; revoking twice and unknown ids are 404 or idempotent, never 500.
    assert_eq!(
        api.delete(&format!("/tokens/{id}"), Auth::Session(&s))
            .await
            .status,
        204
    );
    api.get("/auth/me", Auth::Bearer(&secret))
        .await
        .problem(401);
    let listed = api.get("/tokens", Auth::Session(&s)).await.json();
    let entry = listed.as_array().unwrap().iter().find(|t| t["id"] == id);
    assert!(entry.is_none_or(|t| t["revoked"] == true), "{listed}");
    api.delete("/tokens/999999", Auth::Session(&s))
        .await
        .problem(404);
    assert!(
        !h.logs().contains(&secret),
        "the secret never reaches the log"
    );
}

#[tokio::test]
async fn token_creation_rules() {
    let h = start().await;
    let api = h.rest();
    let s = api.login(ADMIN, ADMIN_PW).await;
    let tok = |body: serde_json::Value| {
        let api = &api;
        let s = &s;
        async move { api.post("/tokens", Auth::Session(s), &body).await }
    };
    tok(json!({"name": "", "scopes": ["api:read"]}))
        .await
        .problem(400);
    tok(json!({"name": "  ", "scopes": ["api:read"]}))
        .await
        .problem(400);
    tok(json!({"name": "x", "scopes": []})).await.problem(400);
    let bad_scope = tok(json!({"name": "x", "scopes": ["root"]})).await;
    assert!((400..500).contains(&bad_scope.status), "{}", bad_scope.text);
    // A token cannot mint tokens, and a session needs its CSRF header.
    api.post(
        "/tokens",
        Auth::Bearer(&h.api_token),
        &json!({"name": "x", "scopes": ["api:read"]}),
    )
    .await
    .problem(403);
    api.post(
        "/tokens",
        Auth::SessionNoCsrfHeader(&s),
        &json!({"name": "x", "scopes": ["api:read"]}),
    )
    .await
    .problem(403);
    // An expiry in the past yields a token that does not work.
    let r = tok(json!({"name": "old", "scopes": ["api:read"], "expires_at": 1})).await;
    if r.status == 201 {
        api.get(
            "/auth/me",
            Auth::Bearer(r.json()["token"].as_str().unwrap()),
        )
        .await
        .problem(401);
    } else {
        r.problem(400);
    }
}

#[tokio::test]
async fn tokens_are_limited_to_what_the_owners_role_allows() {
    let h = start().await;
    let api = h.rest();
    api.create_user(&h.api_token, "vera", "vera-password-1", "viewer")
        .await;
    let s = api.login("vera", "vera-password-1").await;
    for scopes in [
        json!(["admin"]),
        json!(["api:write"]),
        json!(["api:read", "dns:query"]),
    ] {
        let r = api
            .post(
                "/tokens",
                Auth::Session(&s),
                &json!({"name": "t", "scopes": scopes}),
            )
            .await;
        if scopes.as_array().unwrap().iter().any(|v| v == "dns:query") {
            // dns:query is not an API scope, but a viewer's role allows nothing beyond api:read.
            assert!((r.status == 403) || r.status == 201, "{}", r.text);
        } else {
            r.problem(403);
        }
    }
    let ok = api
        .post(
            "/tokens",
            Auth::Session(&s),
            &json!({"name": "t", "scopes": ["api:read"]}),
        )
        .await;
    ok.ok(201);
}

#[tokio::test]
async fn token_ownership_is_enforced_on_list_and_revoke() {
    let h = start().await;
    let api = h.rest();
    let admin_session = api.login(ADMIN, ADMIN_PW).await;
    let made = api
        .post(
            "/tokens",
            Auth::Session(&admin_session),
            &json!({"name": "admins", "scopes": ["api:read"]}),
        )
        .await
        .ok(201);
    let admin_token_id = made["meta"]["id"].as_i64().unwrap();

    let owen = api
        .token_for(&h.api_token, "owen", "operator", &["api:read", "api:write"])
        .await;
    // Owen sees only his own token(s), and cannot revoke the admin's (404, not 403: no oracle).
    let mine = api.get("/tokens", Auth::Bearer(&owen)).await.ok(200);
    assert!(
        mine.as_array()
            .unwrap()
            .iter()
            .all(|t| t["name"] == "owen-token"),
        "{mine}"
    );
    api.delete(&format!("/tokens/{admin_token_id}"), Auth::Bearer(&owen))
        .await
        .problem(404);
    api.get("/auth/me", Auth::Bearer(made["token"].as_str().unwrap()))
        .await
        .ok(200);
    // The admin sees everyone's and may revoke Owen's.
    let all = api.get("/tokens", Auth::Bearer(&h.api_token)).await.ok(200);
    assert!(
        all.as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "owen-token")
    );
    let owen_id = all
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "owen-token")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    assert_eq!(
        api.delete(&format!("/tokens/{owen_id}"), Auth::Bearer(&h.api_token))
            .await
            .status,
        204
    );
    api.get("/auth/me", Auth::Bearer(&owen)).await.problem(401);
}

#[tokio::test]
async fn token_scopes_limit_what_a_token_may_do() {
    let h = start().await;
    let api = h.rest();
    let reader = api
        .token_for(&h.api_token, "rita", "admin", &["api:read"])
        .await;
    let writer = api
        .token_for(&h.api_token, "walt", "admin", &["api:read", "api:write"])
        .await;
    let dns_only = api
        .token_for(&h.api_token, "dana", "admin", &["dns:query"])
        .await;
    let acl = json!({"cidr": "198.51.100.0/24", "action": "refuse"});

    // Even an admin's read-only token cannot write or administer.
    api.get("/acl", Auth::Bearer(&reader)).await.ok(200);
    api.post("/acl", Auth::Bearer(&reader), &acl)
        .await
        .problem(403);
    api.get("/users", Auth::Bearer(&reader)).await.problem(403);
    // A write token may write but not use admin-only routes.
    api.post("/acl", Auth::Bearer(&writer), &acl).await.ok(201);
    api.get("/users", Auth::Bearer(&writer)).await.problem(403);
    api.get("/settings", Auth::Bearer(&writer))
        .await
        .problem(403);
    // A DNS-only token (DoH) opens nothing in the API.
    api.get("/zones", Auth::Bearer(&dns_only))
        .await
        .problem(403);
    api.get("/auth/me", Auth::Bearer(&dns_only))
        .await
        .problem(403);
}

#[tokio::test]
async fn a_demoted_users_tokens_and_sessions_lose_their_power() {
    let h = start().await;
    let api = h.rest();
    let pw = "demote-me-password";
    let uid = api.create_user(&h.api_token, "dina", pw, "admin").await;
    let session = api.login("dina", pw).await;
    let made = api
        .post(
            "/tokens",
            Auth::Session(&session),
            &json!({"name": "power", "scopes": ["admin", "api:read", "api:write"]}),
        )
        .await
        .ok(201);
    let token = made["token"].as_str().unwrap().to_owned();
    api.get("/users", Auth::Bearer(&token)).await.ok(200);
    api.post(
        "/acl",
        Auth::Bearer(&token),
        &json!({"cidr": "203.0.113.0/24", "action": "refuse"}),
    )
    .await
    .ok(201);

    let demoted = api
        .patch(
            &format!("/users/{uid}"),
            Auth::Bearer(&h.api_token),
            &json!({"role": "viewer"}),
        )
        .await
        .ok(200);
    assert_eq!(demoted["role"], "viewer");

    // The token still names admin, but the role no longer allows it; reads still work.
    api.get("/users", Auth::Bearer(&token)).await.problem(403);
    api.post(
        "/acl",
        Auth::Bearer(&token),
        &json!({"cidr": "203.0.113.9", "action": "drop"}),
    )
    .await
    .problem(403);
    api.get("/acl", Auth::Bearer(&token)).await.ok(200);
    // A role change ends the user's sessions.
    api.get("/auth/me", Auth::Session(&session))
        .await
        .problem(401);
    let relogin = api.login("dina", pw).await;
    assert_eq!(
        api.get("/auth/me", Auth::Session(&relogin)).await.ok(200)["role"],
        "viewer"
    );
}

// ---- users ----

#[tokio::test]
async fn user_administration_crud_and_conflicts() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let created = api
        .post(
            "/users",
            admin,
            &json!({"username": "carol", "password": "carol-password-1", "role": "operator"}),
        )
        .await
        .ok(201);
    let id = created["id"].as_i64().unwrap();
    assert_eq!(created["role"], "operator");
    assert!(!created.to_string().contains("carol-password-1"));

    api.post(
        "/users",
        admin,
        &json!({"username": "carol", "password": "another-pass-1", "role": "viewer"}),
    )
    .await
    .problem(409);
    api.post(
        "/users",
        admin,
        &json!({"username": "dave", "password": "short", "role": "viewer"}),
    )
    .await
    .problem(400);
    api.post(
        "/users",
        admin,
        &json!({"username": "", "password": "long-enough-pw", "role": "viewer"}),
    )
    .await
    .problem(400);
    let bad_role = api
        .post(
            "/users",
            admin,
            &json!({"username": "eve", "password": "long-enough-pw", "role": "root"}),
        )
        .await;
    assert!((400..500).contains(&bad_role.status), "{}", bad_role.text);

    assert_eq!(
        api.get(&format!("/users/{id}"), admin).await.ok(200)["username"],
        "carol"
    );
    api.get("/users/987654", admin).await.problem(404);
    api.patch("/users/987654", admin, &json!({"role": "viewer"}))
        .await
        .problem(404);
    api.patch(&format!("/users/{id}"), admin, &json!({"password": "tiny"}))
        .await
        .problem(400);
    // Password reset: the old password stops working, the new one works.
    api.patch(
        &format!("/users/{id}"),
        admin,
        &json!({"password": "reset-password-1"}),
    )
    .await
    .ok(200);
    api.login_resp("carol", "carol-password-1")
        .await
        .problem(401);
    api.login("carol", "reset-password-1").await;

    // Deleting a user takes the user's tokens with them.
    let tok = api
        .token_for(&h.api_token, "frank", "viewer", &["api:read"])
        .await;
    let frank = api
        .get("/users", admin)
        .await
        .json()
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "frank")
        .unwrap()["id"]
        .as_i64()
        .unwrap();
    assert_eq!(
        api.delete(&format!("/users/{frank}"), admin).await.status,
        204
    );
    api.get("/auth/me", Auth::Bearer(&tok)).await.problem(401);
    api.delete(&format!("/users/{frank}"), admin)
        .await
        .problem(404);
}

#[tokio::test]
async fn the_last_admin_cannot_be_deleted_or_demoted() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let me = api.get("/auth/me", admin).await.ok(200)["id"]
        .as_i64()
        .unwrap();
    api.delete(&format!("/users/{me}"), admin)
        .await
        .problem(409);
    api.patch(&format!("/users/{me}"), admin, &json!({"role": "operator"}))
        .await
        .problem(409);
    // With a second admin the first may go.
    let second = api
        .create_user(&h.api_token, "second", "second-password-1", "admin")
        .await;
    api.patch(&format!("/users/{me}"), admin, &json!({"role": "viewer"}))
        .await
        .ok(200);
    // The demoted admin's own token is a viewer's now.
    api.delete(&format!("/users/{second}"), admin)
        .await
        .problem(403);
}

// ---- roles ----

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one table-driven role matrix")]
async fn roles_gate_every_mutating_route_group() {
    let h = start().await;
    let api = h.rest();
    let viewer = api
        .token_for(&h.api_token, "vic", "viewer", &["api:read"])
        .await;
    let operator = api
        .token_for(&h.api_token, "olga", "operator", &["api:read", "api:write"])
        .await;
    let admin = h.api_token.clone();

    // (method, path, body, lowest role allowed): allowed callers must not get 401/403.
    let table: Vec<(Method, &str, serde_json::Value, &str)> = vec![
        (Method::POST, "/zones", json!({}), "operator"),
        (Method::PUT, "/zones/nope.test.", json!({}), "operator"),
        (Method::DELETE, "/zones/nope.test.", json!(null), "operator"),
        (
            Method::POST,
            "/zones/nope.test./records",
            json!({}),
            "operator",
        ),
        (Method::POST, "/acl", json!({}), "operator"),
        (Method::DELETE, "/acl/99999", json!(null), "operator"),
        (Method::PUT, "/acl/rate-limit", json!({}), "operator"),
        (Method::POST, "/rules", json!({}), "operator"),
        (Method::DELETE, "/rules/99999", json!(null), "operator"),
        (Method::POST, "/blocklists", json!({}), "operator"),
        (Method::DELETE, "/blocklists/99999", json!(null), "operator"),
        (Method::PATCH, "/blocklists/99999", json!({}), "operator"),
        (
            Method::POST,
            "/blocklists/99999/refresh",
            json!(null),
            "operator",
        ),
        (Method::DELETE, "/cache", json!(null), "operator"),
        (
            Method::DELETE,
            "/cache/entries?name=a.test.",
            json!(null),
            "operator",
        ),
        (Method::GET, "/querylog/stream", json!(null), "operator"),
        (Method::GET, "/users", json!(null), "admin"),
        (Method::POST, "/users", json!({}), "admin"),
        (Method::PATCH, "/users/1", json!({}), "admin"),
        (Method::DELETE, "/users/99999", json!(null), "admin"),
        (Method::GET, "/client-certs", json!(null), "admin"),
        (Method::POST, "/client-certs", json!({}), "admin"),
        (Method::DELETE, "/client-certs/99999", json!(null), "admin"),
        (Method::POST, "/upstream-groups", json!({}), "admin"),
        (Method::PUT, "/upstream-groups/nope", json!({}), "admin"),
        (
            Method::DELETE,
            "/upstream-groups/nope",
            json!(null),
            "admin",
        ),
        (Method::GET, "/settings", json!(null), "admin"),
        (Method::PATCH, "/settings", json!({}), "admin"),
    ];
    for (method, path, body, lowest) in table {
        for (who, token, rank) in [
            ("viewer", &viewer, 0),
            ("operator", &operator, 1),
            ("admin", &admin, 2),
        ] {
            let needed = if lowest == "admin" { 2 } else { 1 };
            let mut req = api.req(method.clone(), path).bearer(token);
            if !body.is_null() {
                req = req.json(&body);
            }
            // The stream stays open when allowed; only look at its status line.
            if path == "/querylog/stream" {
                let s = req.stream().await;
                assert_eq!(
                    s.status == 403,
                    rank < needed,
                    "{who} {method} {path}: {}",
                    s.status
                );
                continue;
            }
            let r = req.send().await;
            if rank < needed {
                assert_eq!(
                    r.status, 403,
                    "{who} {method} {path} must be forbidden: {}",
                    r.text
                );
                r.problem(403);
            } else {
                assert!(
                    r.status != 401 && r.status != 403,
                    "{who} {method} {path} must pass authorization, got {}: {}",
                    r.status,
                    r.text
                );
            }
        }
    }
    // Everyone may read.
    for path in [
        "/zones",
        "/acl",
        "/rules",
        "/blocklists",
        "/cache",
        "/stats/summary",
        "/querylog",
    ] {
        for token in [&viewer, &operator, &admin] {
            api.get(path, Auth::Bearer(token)).await.ok(200);
        }
    }
}

#[tokio::test]
async fn role_checks_apply_to_sessions_as_well() {
    let h = start().await;
    let api = h.rest();
    api.create_user(&h.api_token, "sven", "sven-password-1", "viewer")
        .await;
    let s = api.login("sven", "sven-password-1").await;
    api.get("/zones", Auth::Session(&s)).await.ok(200);
    api.post(
        "/acl",
        Auth::Session(&s),
        &json!({"cidr": "198.51.100.1", "action": "drop"}),
    )
    .await
    .problem(403);
    api.get("/users", Auth::Session(&s)).await.problem(403);
}
