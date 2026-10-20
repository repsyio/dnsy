//! Cross-cutting API behaviour: error mapping (400/401/404/405/413/415/422), security headers,
//! probes and the OpenAPI document.

use dnsy_e2e::{Auth, Harness, Opts};
use reqwest::Method;
use serde_json::{Value, json};

async fn start() -> Harness {
    Harness::start(Opts::default()).await
}

fn committed_spec() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../openapi/dnsy.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("openapi/dnsy.json")).expect("json")
}

#[tokio::test]
async fn unknown_routes_are_404_and_wrong_methods_405() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    // An unknown API path is a clean 404 (not the UI shell), with or without credentials.
    for auth in [Auth::None, admin] {
        let r = api
            .req(Method::GET, "/no-such-route")
            .auth(auth)
            .send()
            .await;
        assert_eq!(r.status, 404, "{}", r.text);
    }
    let r = api.raw(Method::GET, "/api/v2/zones").send().await;
    assert_eq!(r.status, 404);
    // Known paths with the wrong method.
    for (method, path) in [
        (Method::POST, "/zones/example.test./export"),
        (Method::DELETE, "/auth/me"),
        (Method::PUT, "/zones"),
        (Method::PATCH, "/cache"),
        (Method::GET, "/auth/login"),
        (Method::POST, "/stats/summary"),
    ] {
        let r = api.req(method.clone(), path).auth(admin).send().await;
        r.problem(405);
        assert!(
            r.header("allow").is_some(),
            "405 names the allowed methods: {path}"
        );
    }
}

#[tokio::test]
async fn malformed_requests_are_client_errors_in_problem_shape() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    // Broken JSON, wrong types, unknown fields and a wrong content type.
    let cases: Vec<(&str, Vec<u8>, &'static str)> = vec![
        ("/acl", b"{".to_vec(), "application/json"),
        ("/acl", b"[]".to_vec(), "application/json"),
        (
            "/acl",
            br#"{"cidr": 5, "action": "refuse"}"#.to_vec(),
            "application/json",
        ),
        (
            "/acl",
            br#"{"cidr": "10.0.0.0/8", "action": "refuse", "extra": 1}"#.to_vec(),
            "application/json",
        ),
        (
            "/acl",
            br#"{"cidr": "10.0.0.0/8", "action": "explode"}"#.to_vec(),
            "application/json",
        ),
        (
            "/acl",
            br#"{"cidr": "10.0.0.0/8", "action": "refuse"}"#.to_vec(),
            "text/plain",
        ),
        ("/acl", Vec::new(), "application/json"),
    ];
    for (path, body, ct) in cases {
        let r = api
            .req(Method::POST, path)
            .auth(admin)
            .body(body.clone(), ct)
            .send()
            .await;
        assert!(
            matches!(r.status, 400 | 415 | 422),
            "{path} {ct} {:?} gave {}: {}",
            String::from_utf8_lossy(&body),
            r.status,
            r.text
        );
        r.problem(r.status);
    }
    // Nothing was created by the rejected requests.
    assert!(
        api.get("/acl", admin).await.json()["rules"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn oversized_bodies_are_413() {
    let h = start().await;
    let api = h.rest();
    let huge = json!({"default_ttl": 300, "soa": {}, "records": [], "pad": "x".repeat(2 << 20)});
    let r = api
        .req(Method::POST, "/zones")
        .bearer(&h.api_token)
        .json(&huge)
        .send()
        .await;
    r.problem(413);
    // The server is still fine afterwards.
    api.get("/zones", Auth::Bearer(&h.api_token)).await.ok(200);
}

#[tokio::test]
async fn every_error_status_carries_a_problem_document() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let p401 = api.get("/zones", Auth::None).await;
    assert_eq!(
        p401.problem(401)["type"],
        "https://dnsy.dev/problems/unauthorized"
    );
    assert_eq!(p401.header("www-authenticate"), Some("Bearer"));
    let p404 = api.get("/zones/missing.test.", admin).await;
    assert_eq!(
        p404.problem(404)["type"],
        "https://dnsy.dev/problems/not-found"
    );
    let p400 = api.get("/zones/bad%20name", admin).await;
    assert_eq!(
        p400.problem(400)["type"],
        "https://dnsy.dev/problems/bad-request"
    );
    let p422 = api
        .post(
            "/acl",
            admin,
            &json!({"cidr": "nonsense", "action": "drop"}),
        )
        .await;
    assert_eq!(
        p422.problem(422)["type"],
        "https://dnsy.dev/problems/unprocessable"
    );
    let p409 = api
        .post(
            "/users",
            admin,
            &json!({"username": "e2e", "password": "long-enough-pw", "role": "viewer"}),
        )
        .await;
    assert_eq!(
        p409.problem(409)["type"],
        "https://dnsy.dev/problems/conflict"
    );
    // No internals in any of them.
    for r in [&p401, &p404, &p400, &p422, &p409] {
        let t = r.text.to_lowercase();
        assert!(
            !t.contains("sqlite") && !t.contains("panicked") && !t.contains("/home/"),
            "{t}"
        );
    }
}

#[tokio::test]
async fn api_responses_carry_security_headers_and_no_store() {
    let h = start().await;
    let api = h.rest();
    let r = api.get("/zones", Auth::Bearer(&h.api_token)).await;
    assert_eq!(r.header("cache-control"), Some("no-store"));
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
    assert!(
        r.header("content-security-policy")
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    // Plain HTTP listener: no HSTS.
    assert!(r.header("strict-transport-security").is_none());
    // Errors carry them too.
    let e = api.get("/zones", Auth::None).await;
    assert_eq!(e.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(e.header("cache-control"), Some("no-store"));
}

#[tokio::test]
async fn probes_and_version_need_no_credentials() {
    let h = start().await;
    let api = h.rest();
    assert_eq!(
        api.raw(Method::GET, "/healthz").send().await.ok(200)["status"],
        "ok"
    );
    assert_eq!(
        api.raw(Method::GET, "/readyz").send().await.ok(200)["status"],
        "ready"
    );
    let v = api.get("/version", Auth::None).await.ok(200);
    assert!(
        v["version"]
            .as_str()
            .is_some_and(|s| s.split('.').count() >= 3),
        "{v}"
    );
}

#[tokio::test]
async fn the_served_openapi_document_matches_the_committed_spec() {
    let h = start().await;
    let api = h.rest();
    let r = api.raw(Method::GET, "/api/openapi.json").send().await;
    assert_eq!(r.status, 200);
    assert!(
        r.header("content-type")
            .unwrap()
            .starts_with("application/json")
    );
    assert_eq!(
        r.json(),
        committed_spec(),
        "openapi/dnsy.json is stale: run `just openapi`"
    );
    let spec = r.json();
    assert_eq!(spec["info"]["title"], "DNSY REST API");
    assert!(spec["components"]["securitySchemes"]["bearer"].is_object());
    assert!(spec["components"]["securitySchemes"]["session"].is_object());
}

/// Every documented operation exists and is protected the way the spec says.
#[tokio::test]
async fn every_documented_route_exists_and_requires_credentials() {
    let h = start().await;
    let api = h.rest();
    let spec = committed_spec();
    let mut checked = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            let concrete = path
                .replace("{name}", "example.test.")
                .replace("{index}", "0")
                .replace("{id}", "1");
            let m = Method::from_bytes(method.to_uppercase().as_bytes()).unwrap();
            let secured = op["security"].as_array().is_some_and(|s| !s.is_empty());
            let r = api.raw(m.clone(), &concrete).send().await;
            if secured {
                r.problem(401);
                checked += 1;
            } else {
                assert_ne!(
                    r.status, 404,
                    "{method} {path} is documented but not routed"
                );
                assert_ne!(r.status, 405, "{method} {path}");
            }
        }
    }
    assert!(
        checked >= 50,
        "the sweep covered {checked} secured operations"
    );
}

#[tokio::test]
async fn documented_statuses_are_the_ones_the_server_returns() {
    let h = start().await;
    let api = h.rest();
    let spec = committed_spec();
    // Spot-check: the status codes of a few documented error responses really occur.
    let responses = |path: &str, method: &str| -> Vec<String> {
        spec["paths"][format!("/api/v1{path}")][method]["responses"]
            .as_object()
            .unwrap_or_else(|| panic!("{method} {path} documented"))
            .keys()
            .cloned()
            .collect()
    };
    let admin = Auth::Bearer(&h.api_token);
    let seen = [
        ("/zones/{name}", "get", api.get("/zones/none.test.", admin).await.status),
        ("/zones/{name}", "get", api.get("/zones/a%20b", admin).await.status),
        ("/zones", "post", api.post("/zones", admin, &json!({"name": "x.test.", "default_ttl": 300, "soa": {"mname": "n.", "rname": "r.", "refresh": 1, "retry": 1, "expire": 1, "minimum": 1}, "records": []})).await.status),
        ("/auth/login", "post", api.login_resp("nobody", "nothing").await.status),
    ];
    for (path, method, status) in seen {
        assert!(
            responses(path, method).contains(&status.to_string()),
            "{method} {path} returned {status}, which the spec does not document"
        );
    }
}
