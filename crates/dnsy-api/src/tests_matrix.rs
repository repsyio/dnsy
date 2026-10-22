//! Route x role matrix: every operation in `openapi/dnsy.json` is called anonymously and with a
//! viewer, operator and admin token, and the outcome class is checked against the committed
//! table below. A new route without a row, or a row without a route, fails the test.

use std::collections::BTreeSet;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use dnsy_core::{Role, Scope};
use tower::ServiceExt;

use crate::{ApiConfig, ApiState, router};

/// Who may call an operation. Scopes are flat: a role holds the scopes of the roles below it
/// only because the test mints the token that way.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Access {
    /// No credential needed.
    Public,
    /// `api:read` (viewer and up).
    Read,
    /// `api:write` (operator and up).
    Write,
    /// `admin` (admin only).
    Admin,
    /// `api:read` at the gate; the handler then also insists on a browser session (covered by
    /// `token_creation_rules` and the auth tests, since a bad body is rejected first here).
    Session,
}

use Access::{Admin, Public, Read, Session, Write};

/// `(method, OpenAPI path, access)`. Keep sorted by path.
const EXPECTED: &[(&str, &str, Access)] = &[
    ("GET", "/api/v1/acl", Read),
    ("POST", "/api/v1/acl", Write),
    ("PUT", "/api/v1/acl/rate-limit", Write),
    ("GET", "/api/v1/response-ip", Read),
    ("PUT", "/api/v1/response-ip", Write),
    ("DELETE", "/api/v1/acl/{id}", Write),
    ("POST", "/api/v1/auth/bootstrap", Public),
    ("POST", "/api/v1/auth/login", Public),
    ("POST", "/api/v1/auth/logout", Session),
    ("GET", "/api/v1/auth/me", Read),
    ("PUT", "/api/v1/auth/me/password", Session),
    ("GET", "/api/v1/blocklists", Read),
    ("POST", "/api/v1/blocklists", Write),
    ("DELETE", "/api/v1/blocklists/{id}", Write),
    ("PATCH", "/api/v1/blocklists/{id}", Write),
    ("POST", "/api/v1/blocklists/{id}/refresh", Write),
    ("GET", "/api/v1/cache", Read),
    ("DELETE", "/api/v1/cache", Write),
    ("DELETE", "/api/v1/cache/entries", Write),
    ("GET", "/api/v1/client-certs", Admin),
    ("POST", "/api/v1/client-certs", Admin),
    ("DELETE", "/api/v1/client-certs/{id}", Admin),
    ("PATCH", "/api/v1/client-certs/{id}", Admin),
    ("POST", "/api/v1/dnssec/keys/export", Admin),
    ("POST", "/api/v1/dnssec/passphrase", Admin),
    ("GET", "/api/v1/dnssec/status", Read),
    ("GET", "/api/v1/querylog", Read),
    ("GET", "/api/v1/querylog/stream", Write),
    ("GET", "/api/v1/rules", Read),
    ("POST", "/api/v1/rules", Write),
    ("DELETE", "/api/v1/rules/{id}", Write),
    ("GET", "/api/v1/settings", Admin),
    ("PATCH", "/api/v1/settings", Admin),
    ("GET", "/api/v1/settings/dnssec", Read),
    ("PATCH", "/api/v1/settings/dnssec", Admin),
    ("GET", "/api/v1/stats/dashboard", Read),
    ("GET", "/api/v1/stats/summary", Read),
    ("GET", "/api/v1/stats/timeseries", Read),
    ("GET", "/api/v1/stats/top-blocked", Read),
    ("GET", "/api/v1/stats/top-clients", Read),
    ("GET", "/api/v1/stats/top-domains", Read),
    ("GET", "/api/v1/tokens", Read),
    ("POST", "/api/v1/tokens", Session),
    ("DELETE", "/api/v1/tokens/{id}", Read),
    ("GET", "/api/v1/upstream-groups", Read),
    ("POST", "/api/v1/upstream-groups", Admin),
    ("GET", "/api/v1/upstream-groups/{name}", Read),
    ("PUT", "/api/v1/upstream-groups/{name}", Admin),
    ("DELETE", "/api/v1/upstream-groups/{name}", Admin),
    ("GET", "/api/v1/upstream-groups/{name}/health", Read),
    ("POST", "/api/v1/upstream-groups/{name}/upstreams", Admin),
    (
        "DELETE",
        "/api/v1/upstream-groups/{name}/upstreams/{index}",
        Admin,
    ),
    ("GET", "/api/v1/users", Admin),
    ("POST", "/api/v1/users", Admin),
    ("GET", "/api/v1/users/{id}", Admin),
    ("DELETE", "/api/v1/users/{id}", Admin),
    ("PATCH", "/api/v1/users/{id}", Admin),
    ("GET", "/api/v1/version", Public),
    ("GET", "/api/v1/zones", Read),
    ("POST", "/api/v1/zones", Write),
    ("GET", "/api/v1/zones/{name}", Read),
    ("PUT", "/api/v1/zones/{name}", Write),
    ("DELETE", "/api/v1/zones/{name}", Write),
    ("GET", "/api/v1/zones/{name}/dnssec", Read),
    ("PUT", "/api/v1/zones/{name}/dnssec", Admin),
    ("GET", "/api/v1/zones/{name}/dnssec/ds", Read),
    ("GET", "/api/v1/zones/{name}/dnssec/keys", Read),
    ("POST", "/api/v1/zones/{name}/dnssec/keys", Admin),
    (
        "POST",
        "/api/v1/zones/{name}/dnssec/keys/{id}/ds-confirmed",
        Admin,
    ),
    (
        "POST",
        "/api/v1/zones/{name}/dnssec/keys/{id}/rollover",
        Admin,
    ),
    ("POST", "/api/v1/zones/{name}/dnssec/rollover/abort", Admin),
    ("GET", "/api/v1/zones/{name}/export", Read),
    ("GET", "/api/v1/zones/{name}/records", Read),
    ("POST", "/api/v1/zones/{name}/records", Write),
    ("PUT", "/api/v1/zones/{name}/records/{id}", Write),
    ("DELETE", "/api/v1/zones/{name}/records/{id}", Write),
    ("GET", "/healthz", Public),
    ("GET", "/readyz", Public),
];

/// What a principal should see: refused with this status, or let through to the handler (any
/// status other than 401 and 403: success, validation failure, not found, 503 without a service).
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Refused(StatusCode),
    Allowed,
}

fn expected(access: Access, principal: Option<Role>) -> Outcome {
    let Some(role) = principal else {
        return if access == Public {
            Outcome::Allowed
        } else {
            Outcome::Refused(StatusCode::UNAUTHORIZED)
        };
    };
    let rank = |r: Role| match r {
        Role::Viewer => 0,
        Role::Operator => 1,
        Role::Admin => 2,
    };
    let needed = match access {
        Public | Read | Session => 0,
        Write => 1,
        Admin => 2,
    };
    if rank(role) >= needed {
        Outcome::Allowed
    } else {
        Outcome::Refused(StatusCode::FORBIDDEN)
    }
}

fn concrete(path: &str) -> String {
    path.replace("{id}", "999999")
        .replace("{index}", "0")
        .replace("{name}", "example.org")
}

async fn call(app: &Router, method: &str, path: &str, token: Option<&str>) -> StatusCode {
    let mut b = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).unwrap())
        .uri(concrete(path))
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    app.clone()
        .oneshot(b.body(Body::from("{}")).unwrap())
        .await
        .unwrap()
        .status()
}

#[test]
fn every_openapi_operation_has_exactly_one_expectation() {
    let spec = serde_json::to_value(crate::openapi()).unwrap();
    let mut actual = BTreeSet::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        for method in item.as_object().unwrap().keys() {
            actual.insert((method.to_uppercase(), path.clone()));
        }
    }
    let table: BTreeSet<_> = EXPECTED
        .iter()
        .map(|(m, p, _)| ((*m).to_owned(), (*p).to_owned()))
        .collect();
    assert_eq!(table.len(), EXPECTED.len(), "duplicate rows in EXPECTED");
    let missing: Vec<_> = actual.difference(&table).collect();
    let stale: Vec<_> = table.difference(&actual).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "routes without an expectation row: {missing:?}; rows without a route: {stale:?}"
    );
}

#[tokio::test]
async fn route_role_matrix_matches_the_committed_table() {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let state = ApiState::new(store);
    let mut tokens = Vec::new();
    for (name, role, scopes) in [
        ("viewer", Role::Viewer, vec![Scope::ApiRead]),
        (
            "operator",
            Role::Operator,
            vec![Scope::ApiRead, Scope::ApiWrite],
        ),
        (
            "admin",
            Role::Admin,
            vec![Scope::ApiRead, Scope::ApiWrite, Scope::Admin],
        ),
    ] {
        let user = state
            .auth
            .users
            .create(name, "pw-pw-pw-pw", role)
            .await
            .unwrap();
        let (token, _) = state
            .auth
            .tokens
            .create(user.id, "m", &scopes, None)
            .await
            .unwrap();
        tokens.push((role, token));
    }
    let app = router(state, ApiConfig::default());

    let mut wrong = Vec::new();
    for (method, path, access) in EXPECTED {
        let mut principals: Vec<(Option<Role>, Option<&str>)> = vec![(None, None)];
        principals.extend(tokens.iter().map(|(r, t)| (Some(*r), Some(t.as_str()))));
        for (role, token) in principals {
            let want = expected(*access, role);
            let status = call(&app, method, path, token).await;
            let got = if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                Outcome::Refused(status)
            } else {
                Outcome::Allowed
            };
            if got != want {
                wrong.push(format!(
                    "{method} {path} as {role:?}: want {want:?}, got {status}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
