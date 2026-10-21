//! Zones and records over REST: CRUD, ETag/If-Match, validation, path traversal, BIND export,
//! and the effect of every write on what the DNS listener answers.

use std::time::Duration;

use dnsy_e2e::zones::example_zone;
use dnsy_e2e::{Auth, Harness, Opts, eventually, query, udp_exchange};
use dnsy_proto::{Message, RData, Rcode, RecordType};
use reqwest::Method;
use serde_json::{Value, json};

fn soa() -> Value {
    json!({"mname": "ns1.new.test.", "rname": "hostmaster.new.test.", "refresh": 7200,
           "retry": 3600, "expire": 1_209_600, "minimum": 300})
}

fn zone_body(extra: &[Value]) -> Value {
    let mut records = vec![json!({"name": "@", "type": "NS", "value": "ns1.new.test."})];
    records.extend_from_slice(extra);
    json!({"name": "new.test.", "default_ttl": 300, "soa": soa(), "records": records})
}

async fn start() -> Harness {
    Harness::start(Opts::default().zone("example.test.", example_zone())).await
}

fn first_a(m: &Message) -> Option<String> {
    m.answers.iter().find_map(|r| match &r.data {
        RData::A(ip) => Some(ip.to_string()),
        _ => None,
    })
}

async fn ask(h: &Harness, name: &str) -> Message {
    udp_exchange(h.udp, &query(name, RecordType::A)).await
}

/// Polls until the DNS answer for `name` satisfies `pred`.
async fn dns_until(h: &Harness, name: &str, what: &str, pred: impl Fn(&Message) -> bool) -> Message {
    eventually(Duration::from_secs(10), what, || async {
        let r = ask(h, name).await;
        pred(&r).then_some(r)
    })
    .await
}

#[tokio::test]
async fn zone_create_get_list_replace_delete_changes_dns() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    api.get("/zones/new.test.", admin).await.problem(404);

    let created = api
        .post("/zones", admin, &zone_body(&[json!({"name": "www", "type": "A", "value": "192.0.2.50"})]))
        .await;
    assert_eq!(created.status, 201, "{}", created.text);
    let etag = created.header("etag").expect("ETag on create").to_owned();
    assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
    let body = created.json();
    assert_eq!(body["name"], "new.test.");
    assert_eq!(body["record_count"], 2);
    assert_eq!(body["soa"]["serial"], 1);

    let r = dns_until(&h, "www.new.test.", "the new zone to answer", |r| r.header.rcode == Rcode::NoError && !r.answers.is_empty()).await;
    assert!(r.header.aa);
    assert_eq!(first_a(&r).as_deref(), Some("192.0.2.50"));

    let got = api.get("/zones/new.test.", admin).await;
    assert_eq!(got.header("etag"), Some(etag.as_str()), "GET returns the validator of the stored state");
    let listed = api.get("/zones", admin).await.ok(200);
    let row = listed.as_array().unwrap().iter().find(|z| z["name"] == "new.test.").unwrap();
    assert_eq!((row["record_count"].as_i64(), row["dnssec_enabled"].as_bool()), (Some(2), Some(false)));
    assert!(row["load_error"].is_null());
    // Names are case-insensitive.
    api.get("/zones/NEW.Test.", admin).await.ok(200);

    // Replace: serial goes up, the ETag changes, DNS follows.
    let mut replaced = zone_body(&[json!({"name": "www", "type": "A", "value": "192.0.2.51"})]);
    replaced.as_object_mut().unwrap().remove("name");
    let put = api.put("/zones/new.test.", admin, &replaced).await;
    assert_eq!(put.status, 200, "{}", put.text);
    assert_eq!(put.json()["soa"]["serial"], 2);
    assert_ne!(put.header("etag"), Some(etag.as_str()));
    dns_until(&h, "www.new.test.", "the replaced record", |r| first_a(r).as_deref() == Some("192.0.2.51")).await;

    assert_eq!(api.delete("/zones/new.test.", admin).await.status, 204);
    api.get("/zones/new.test.", admin).await.problem(404);
    dns_until(&h, "www.new.test.", "the zone to disappear", |r| r.header.rcode != Rcode::NoError || r.answers.is_empty()).await;
    assert!(!h.zones_dir().join("new.test.json").exists());
    api.delete("/zones/new.test.", admin).await.problem(404);
    api.put("/zones/new.test.", admin, &replaced).await.problem(404);
}

#[tokio::test]
async fn zone_creation_validation() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    api.post("/zones", admin, &zone_body(&[])).await.ok(201);
    // Duplicate, also with another spelling of the same name.
    api.post("/zones", admin, &zone_body(&[])).await.problem(409);
    let mut upper = zone_body(&[]);
    upper["name"] = json!("NEW.TEST.");
    api.post("/zones", admin, &upper).await.problem(409);
    // Zones that exist as files can't be re-created either.
    let mut existing = zone_body(&[]);
    existing["name"] = json!("example.test.");
    api.post("/zones", admin, &existing).await.problem(409);

    let mut no_ns = zone_body(&[]);
    no_ns["name"] = json!("nons.test.");
    no_ns["records"] = json!([]);
    assert!(api.post("/zones", admin, &no_ns).await.problem(422)["detail"].as_str().unwrap().contains("NS"));

    for (what, mutate) in [
        ("ttl too large", Box::new(|b: &mut Value| b["default_ttl"] = json!(4_000_000_000_u64)) as Box<dyn Fn(&mut Value)>),
        ("negative ttl", Box::new(|b: &mut Value| b["default_ttl"] = json!(-1))),
        ("bad soa mname", Box::new(|b: &mut Value| b["soa"]["mname"] = json!("a..b"))),
        ("missing soa", Box::new(|b: &mut Value| { b.as_object_mut().unwrap().remove("soa"); })),
    ] {
        let mut b = zone_body(&[]);
        b["name"] = json!("v.test.");
        mutate(&mut b);
        let r = api.post("/zones", admin, &b).await;
        assert!(matches!(r.status, 400 | 422), "{what}: {} {}", r.status, r.text);
        r.problem(r.status);
    }
    assert!(api.get("/zones/v.test.", admin).await.status == 404, "a rejected create leaves nothing behind");
}

#[tokio::test]
async fn record_crud_changes_dns_and_ids_are_stable() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let base = "/zones/example.test./records";
    let created = api
        .post(base, admin, &json!({"name": "api", "type": "A", "value": "192.0.2.80", "ttl": 120}))
        .await;
    assert_eq!(created.status, 201, "{}", created.text);
    let rec = created.json();
    assert_eq!((rec["name"].as_str(), rec["type"].as_str(), rec["ttl"].as_i64()), (Some("api.example.test."), Some("A"), Some(120)));
    let id = rec["id"].as_str().unwrap().to_owned();
    let after_create = created.header("etag").unwrap().to_owned();
    let r = dns_until(&h, "api.example.test.", "the new record", |r| !r.answers.is_empty()).await;
    assert_eq!(first_a(&r).as_deref(), Some("192.0.2.80"));
    assert_eq!(r.answers[0].ttl, 120);

    // Replace by id: the value changes, the id follows the content.
    let put = api
        .put(&format!("{base}/{id}"), admin, &json!({"name": "api", "type": "A", "value": "192.0.2.81"}))
        .await;
    assert_eq!(put.status, 200, "{}", put.text);
    let new_id = put.json()["id"].as_str().unwrap().to_owned();
    assert_ne!(new_id, id);
    assert_ne!(put.header("etag").unwrap(), after_create);
    dns_until(&h, "api.example.test.", "the replaced value", |r| first_a(r).as_deref() == Some("192.0.2.81")).await;
    api.put(&format!("{base}/{id}"), admin, &json!({"name": "api", "type": "A", "value": "192.0.2.82"}))
        .await
        .problem(404);

    // Delete: 204 with the new ETag, DNS no longer has it.
    let del = api.delete(&format!("{base}/{new_id}"), admin).await;
    assert_eq!(del.status, 204);
    assert!(del.header("etag").is_some());
    dns_until(&h, "api.example.test.", "the record to go", |r| r.answers.is_empty()).await;
    api.delete(&format!("{base}/{new_id}"), admin).await.problem(404);

    // Other record types round-trip through presentation format.
    for (name, ty, value) in [("m2", "MX", "20 www.example.test."), ("t2", "TXT", "hi there"), ("a6", "AAAA", "2001:db8::99"), ("s2", "SRV", "1 2 3 www.example.test."), ("c2", "CAA", "0 issue \"ca.test\"")] {
        let r = api.post(base, admin, &json!({"name": name, "type": ty, "value": value})).await;
        assert_eq!(r.status, 201, "{ty}: {}", r.text);
        assert_eq!(r.json()["type"], ty);
    }
}

#[tokio::test]
async fn record_validation_errors() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let base = "/zones/example.test./records";
    let before = api.get(base, admin).await.ok(200)["total"].clone();
    for (what, body) in [
        ("unknown type", json!({"name": "x", "type": "BOGUS", "value": "1"})),
        ("bad A", json!({"name": "x", "type": "A", "value": "300.1.1.1"})),
        ("bad AAAA", json!({"name": "x", "type": "AAAA", "value": "1.2.3.4"})),
        ("bad MX", json!({"name": "x", "type": "MX", "value": "mail.example.test."})),
        ("name outside the zone", json!({"name": "x.other.test.", "type": "A", "value": "192.0.2.1"})),
        ("bad name", json!({"name": "a..b", "type": "A", "value": "192.0.2.1"})),
        ("ttl too large", json!({"name": "x", "type": "A", "value": "192.0.2.1", "ttl": 4_000_000_000_u64})),
        ("cname beside data", json!({"name": "www", "type": "CNAME", "value": "other.example.test."})),
        ("data beside cname", json!({"name": "alias", "type": "A", "value": "192.0.2.1"})),
        ("unknown field", json!({"name": "x", "type": "A", "value": "192.0.2.1", "extra": true})),
        ("oversized value", json!({"name": "x", "type": "TXT", "value": "y".repeat(5000)})),
    ] {
        let r = api.post(base, admin, &body).await;
        assert!(matches!(r.status, 400 | 409 | 422), "{what}: {} {}", r.status, r.text);
        r.problem(r.status);
    }
    // Exact duplicates are a conflict.
    let dup = json!({"name": "www", "type": "A", "value": "192.0.2.7"});
    api.post(base, admin, &dup).await.problem(409);
    // The last apex NS can't be removed.
    let ns = api.get(&format!("{base}?type=NS&name=@"), admin).await.ok(200);
    if let Some(first) = ns["items"].as_array().and_then(|i| i.first()) {
        let id = first["id"].as_str().unwrap();
        if ns["total"] == 1 {
            api.delete(&format!("{base}/{id}"), admin).await.problem(422);
        }
    }
    assert_eq!(api.get(base, admin).await.ok(200)["total"], before, "rejected writes changed nothing");
    api.post("/zones/missing.test./records", admin, &dup).await.problem(404);
}

#[tokio::test]
async fn record_listing_filters_and_page_boundaries() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let base = "/zones/example.test./records";
    let all = api.get(base, admin).await.ok(200);
    let total = all["total"].as_u64().unwrap();
    assert!(total > 60, "the fixture zone is large: {total}");
    assert_eq!((all["limit"].as_u64(), all["offset"].as_u64()), (Some(100), Some(0)));
    assert_eq!(all["items"].as_array().unwrap().len() as u64, total.min(100));

    let page = |q: String| {
        let api = &api;
        let h = &h;
        async move { api.get(&format!("{base}?{q}"), Auth::Bearer(&h.api_token)).await }
    };
    // Walk the whole zone in pages of 7: every record exactly once.
    let mut seen = Vec::new();
    let mut offset = 0;
    loop {
        let p = page(format!("limit=7&offset={offset}")).await.ok(200);
        let items = p["items"].as_array().unwrap();
        assert!(items.len() <= 7);
        seen.extend(items.iter().map(|i| i["id"].as_str().unwrap().to_owned()));
        if items.len() < 7 {
            break;
        }
        offset += 7;
    }
    assert_eq!(seen.len() as u64, total);
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), seen.len(), "no record repeated across pages");

    // Boundaries.
    assert_eq!(page(format!("offset={total}")).await.ok(200)["items"], json!([]));
    assert_eq!(page("offset=99999".into()).await.ok(200)["total"], total);
    assert_eq!(page("limit=1000".into()).await.status, 200);
    for bad in ["limit=0", "limit=1001", "limit=-1", "limit=abc", "offset=-1"] {
        let r = page(bad.into()).await;
        assert!(matches!(r.status, 400 | 422), "{bad}: {}", r.status);
        r.problem(r.status);
    }
    // Filters.
    let many = page("name=many&type=a".into()).await.ok(200);
    assert_eq!(many["total"], 40);
    assert!(many["items"].as_array().unwrap().iter().all(|i| i["name"] == "many.example.test." && i["type"] == "A"));
    assert_eq!(page("type=MX".into()).await.ok(200)["total"], 1);
    assert_eq!(page("name=nothing-here".into()).await.ok(200)["total"], 0);
    assert_eq!(page("name=www.example.test.".into()).await.ok(200)["total"], 2);
}

#[tokio::test]
async fn etags_and_if_match_guard_concurrent_edits() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let base = "/zones/example.test./records";
    let first = api.get(base, admin).await;
    let etag = first.header("etag").unwrap().to_owned();
    assert_eq!(api.get(base, admin).await.header("etag"), Some(etag.as_str()), "stable while unchanged");

    let rec = |n: &str| json!({"name": n, "type": "A", "value": "192.0.2.200"});
    // A stale validator is refused and changes nothing.
    api.req(Method::POST, base).bearer(&h.api_token).header("if-match", "\"deadbeef\"").json(&rec("stale")).send().await.problem(412);
    assert_eq!(api.get(&format!("{base}?name=stale"), admin).await.ok(200)["total"], 0);
    // The current validator succeeds exactly once; reusing it afterwards is stale.
    let ok = api.req(Method::POST, base).bearer(&h.api_token).header("if-match", &etag).json(&rec("one")).send().await;
    assert_eq!(ok.status, 201, "{}", ok.text);
    assert_ne!(ok.header("etag").unwrap(), etag);
    api.req(Method::POST, base).bearer(&h.api_token).header("if-match", &etag).json(&rec("two")).send().await.problem(412);
    // `*` and a list containing the current validator match.
    for list in [false, true] {
        let now = api.get(base, admin).await.header("etag").unwrap().to_owned();
        let header = if list { format!("\"nope\", {now}") } else { "*".to_owned() };
        let r = api.req(Method::POST, base).bearer(&h.api_token).header("if-match", &header).json(&rec(&format!("m{}", header.len()))).send().await;
        assert_eq!(r.status, 201, "{header}: {}", r.text);
    }
    // Zone-level PUT and DELETE honour it as well.
    let body = json!({"default_ttl": 300, "soa": soa(), "records": [{"name": "@", "type": "NS", "value": "ns1.example.test."}]});
    api.req(Method::PUT, "/zones/example.test.").bearer(&h.api_token).header("if-match", "\"old\"").json(&body).send().await.problem(412);
    api.req(Method::DELETE, "/zones/example.test.").bearer(&h.api_token).header("if-match", "\"old\"").send().await.problem(412);
    api.get("/zones/example.test.", admin).await.ok(200);
}

#[tokio::test]
async fn parallel_writers_with_the_same_validator_exactly_one_wins() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let base = "/zones/example.test./records";
    let etag = api.get(base, admin).await.header("etag").unwrap().to_owned();
    let attempt = |i: u32| {
        let (api, etag, token) = (&api, etag.clone(), h.api_token.clone());
        async move {
            api.req(Method::POST, base)
                .bearer(&token)
                .header("if-match", &etag)
                .json(&json!({"name": format!("race{i}"), "type": "A", "value": "192.0.2.150"}))
                .send()
                .await
                .status
        }
    };
    let (a, b, c, d) = tokio::join!(attempt(0), attempt(1), attempt(2), attempt(3));
    let statuses = [a, b, c, d];
    assert_eq!(statuses.iter().filter(|s| **s == 201).count(), 1, "{statuses:?}");
    assert_eq!(statuses.iter().filter(|s| **s == 412).count(), 3, "{statuses:?}");
    let all = api.get(&format!("{base}?limit=1000"), admin).await.ok(200);
    let races = all["items"].as_array().unwrap().iter().filter(|i| i["name"].as_str().unwrap().starts_with("race")).count();
    assert_eq!(races, 1, "only the winner's record exists");
}

#[tokio::test]
async fn hostile_zone_names_never_leave_the_zones_directory() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let outside = h.dir.path().join("escaped.json");
    let listing = |dir: &std::path::Path| {
        let mut v: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        v.sort();
        v
    };
    let root_before = listing(h.dir.path());
    let zones_before = listing(&h.zones_dir());

    let hostile = ["..", "../escaped", "..%2Fescaped", "%2e%2e%2fescaped", "a%2F..%2F..%2Fescaped", "..%5Cescaped", "a%00b", "%2Fetc%2Fpasswd", "a%20b", "ex%C3%A4mple.test.", ".", "-x.test.", "a/b"];
    for name in hostile {
        for (method, suffix) in [(Method::GET, ""), (Method::GET, "/records"), (Method::GET, "/export"), (Method::DELETE, ""), (Method::PUT, "")] {
            let mut body = zone_body(&[]);
            body.as_object_mut().unwrap().remove("name");
            let r = api.req(method.clone(), &format!("/zones/{name}{suffix}")).auth(admin).json(&body).send().await;
            assert!(matches!(r.status, 400 | 404 | 405), "{method} {name}{suffix}: {} {}", r.status, r.text);
            assert!(!r.text.contains("root:"), "no file content leaks");
        }
    }
    for name in ["../escaped.", "../../escaped", "/abs/path.", "a/b.test.", "..\\escaped.", "x\u{0}.test.", "", ".", "a b.test."] {
        let mut b = zone_body(&[]);
        b["name"] = json!(name);
        let r = api.post("/zones", admin, &b).await;
        assert!(matches!(r.status, 400 | 422), "{name:?}: {} {}", r.status, r.text);
        r.problem(r.status);
    }
    assert!(!outside.exists());
    assert_eq!(listing(h.dir.path()), root_before, "nothing was created next to the zones directory");
    assert_eq!(listing(&h.zones_dir()), zones_before, "nor inside it");
}

#[tokio::test]
async fn bind_export_has_download_headers_and_the_zone_content() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let r = api.get("/zones/example.test./export", admin).await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.header("content-type"), Some("text/dns; charset=utf-8"));
    assert_eq!(r.header("content-disposition"), Some("attachment; filename=\"example.test.zone\""));
    assert!(r.text.contains("SOA") && r.text.contains("www"), "{}", r.text);
    assert!(r.text.contains("192.0.2.7") && r.text.contains("example.test."), "{}", r.text);
    assert!(r.text.contains("MX") && r.text.contains("\"hello\" \"world\""));
    // Case and a missing zone.
    api.get("/zones/EXAMPLE.test./export", admin).await;
    api.get("/zones/none.test./export", admin).await.problem(404);
    // Signed export of an unsigned zone is a conflict, an invalid flag a client error.
    api.get("/zones/example.test./export?signed=true", admin).await.problem(409);
    let bad = api.get("/zones/example.test./export?signed=maybe", admin).await;
    assert!(matches!(bad.status, 400 | 422), "{}", bad.status);
    // A read-only token may export.
    let viewer = api.token_for(&h.api_token, "exporter", "viewer", &["api:read"]).await;
    assert_eq!(api.get("/zones/example.test./export", Auth::Bearer(&viewer)).await.status, 200);
}

#[tokio::test]
async fn an_invalid_file_on_disk_is_reported_and_the_old_zone_keeps_serving() {
    let h = start().await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    h.write_zone("example.test.", "{ this is not json");
    let row = eventually(Duration::from_secs(10), "a load_error on the zone", || async {
        let z = api.get("/zones", admin).await.json();
        z.as_array()?.iter().find(|z| z["name"] == "example.test." && z["load_error"].is_string()).cloned()
    })
    .await;
    assert!(!row["load_error"].as_str().unwrap().is_empty());
    let r = ask(&h, "www.example.test.").await;
    assert_eq!(first_a(&r).as_deref(), Some("192.0.2.7"), "the last good version still answers");
    assert!(api.get("/zones/example.test.", admin).await.ok(200)["load_error"].is_string());
    // Fixing the file clears the error.
    h.write_zone("example.test.", &example_zone());
    eventually(Duration::from_secs(10), "the error to clear", || async {
        api.get("/zones/example.test.", admin).await.json()["load_error"].is_null().then_some(())
    })
    .await;
}

#[tokio::test]
async fn viewers_read_zones_but_cannot_change_them() {
    let h = start().await;
    let api = h.rest();
    let viewer = api.token_for(&h.api_token, "zed", "viewer", &["api:read"]).await;
    let v = Auth::Bearer(&viewer);
    api.get("/zones", v).await.ok(200);
    api.get("/zones/example.test./records", v).await.ok(200);
    api.post("/zones", v, &zone_body(&[])).await.problem(403);
    api.post("/zones/example.test./records", v, &json!({"name": "q", "type": "A", "value": "192.0.2.1"})).await.problem(403);
    api.delete("/zones/example.test.", v).await.problem(403);
    let operator = api.token_for(&h.api_token, "opal", "operator", &["api:read", "api:write"]).await;
    api.post("/zones", Auth::Bearer(&operator), &zone_body(&[])).await.ok(201);
}
