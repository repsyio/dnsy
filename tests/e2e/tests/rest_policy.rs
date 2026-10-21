//! Filtering, access control and settings over REST, and the effect of each change on the live
//! DNS path (ACL, rules, blocklists, block mode, upstream groups, client certificates).

use std::time::Duration;

use dnsy_e2e::clients::{Framed, query_edns};
use dnsy_e2e::upstream::a;
use dnsy_e2e::{Auth, FakeUpstream, Harness, MtlsPolicy, Opts, Reply, eventually, query, udp_exchange, udp_silent};
use dnsy_proto::{EdnsOption, Message, RData, Rcode, RecordType, ede};
use serde_json::{Value, json};

fn ede_codes(m: &Message) -> Vec<u16> {
    m.edns
        .iter()
        .flat_map(|e| &e.options)
        .filter_map(|o| match o {
            EdnsOption::ExtendedError { code, .. } => Some(*code),
            _ => None,
        })
        .collect()
}

fn local() -> Opts {
    Opts::default().zone("example.test.", dnsy_e2e::zones::example_zone())
}

async fn www(h: &Harness) -> Message {
    udp_exchange(h.udp, &query_edns("www.example.test.", RecordType::A, 1232)).await
}

const WAIT: Duration = Duration::from_secs(10);

// ---- ACL ----

#[tokio::test]
async fn acl_rules_crud_validation_and_effect() {
    let h = Harness::start(local()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let overview = api.get("/acl", admin).await.ok(200);
    assert_eq!(overview["default_action"], "allow");
    assert_eq!(overview["rules"], json!([]));

    let created = api
        .post("/acl", admin, &json!({"cidr": "127.0.0.0/8", "action": "refuse", "comment": "loopback"}))
        .await
        .ok(201);
    let id = created["id"].as_i64().unwrap();
    assert_eq!((created["cidr"].as_str(), created["action"].as_str(), created["comment"].as_str()), (Some("127.0.0.0/8"), Some("refuse"), Some("loopback")));
    assert!(created["client_cert_sha256"].is_null());
    let r = eventually(WAIT, "the client to be refused", || async {
        let r = www(&h).await;
        (r.header.rcode == Rcode::Refused).then_some(r)
    })
    .await;
    assert!(r.answers.is_empty());
    assert_eq!(api.get("/acl", admin).await.ok(200)["rules"].as_array().unwrap().len(), 1);

    assert_eq!(api.delete(&format!("/acl/{id}"), admin).await.status, 204);
    eventually(WAIT, "the client to be served again", || async {
        (www(&h).await.header.rcode == Rcode::NoError).then_some(())
    })
    .await;
    api.delete(&format!("/acl/{id}"), admin).await.problem(404);
}

#[tokio::test]
async fn acl_drop_rule_silences_the_server_until_removed() {
    let h = Harness::start(local()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let id = api.post("/acl", admin, &json!({"cidr": "127.0.0.1", "action": "drop"})).await.ok(201)["id"].as_i64().unwrap();
    // A single address is stored as a /32.
    assert_eq!(api.get("/acl", admin).await.ok(200)["rules"][0]["cidr"], "127.0.0.1/32");
    eventually(WAIT, "queries to be dropped", || async {
        udp_silent(h.udp, &query("www.example.test.", RecordType::A)).await.then_some(())
    })
    .await;
    // The API itself stays reachable: the ACL guards DNS clients only.
    api.get("/zones", admin).await.ok(200);
    assert_eq!(api.delete(&format!("/acl/{id}"), admin).await.status, 204);
    eventually(WAIT, "answers after removing the drop rule", || async {
        (www(&h).await.header.rcode == Rcode::NoError).then_some(())
    })
    .await;
}

#[tokio::test]
async fn acl_validation() {
    let h = Harness::start(local()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let fp = h.pki.valid_client.fingerprint();
    for (what, body, status) in [
        ("not a network", json!({"cidr": "nonsense", "action": "drop"}), 422),
        ("prefix too long", json!({"cidr": "10.0.0.0/33", "action": "drop"}), 422),
        ("neither matcher", json!({"action": "drop"}), 422),
        ("both matchers", json!({"cidr": "10.0.0.0/8", "client_cert_sha256": fp, "action": "drop"}), 422),
        ("short fingerprint", json!({"client_cert_sha256": "abcd", "action": "drop"}), 422),
        ("non-hex fingerprint", json!({"client_cert_sha256": "z".repeat(64), "action": "drop"}), 422),
        ("long comment", json!({"cidr": "10.0.0.0/8", "action": "drop", "comment": "c".repeat(300)}), 422),
    ] {
        let r = api.post("/acl", admin, &body).await;
        assert_eq!(r.status, status, "{what}: {}", r.text);
        r.problem(status);
    }
    // Fingerprints are accepted in colon form and upper case, and stored normalised.
    let colon: String = fp.to_uppercase().as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":");
    let ok = api.post("/acl", admin, &json!({"client_cert_sha256": colon, "action": "refuse"})).await.ok(201);
    assert_eq!(ok["client_cert_sha256"], fp.to_lowercase());
    assert_eq!(api.get("/acl", admin).await.ok(200)["rules"].as_array().unwrap().len(), 1, "only the valid rule exists");
}

#[tokio::test]
async fn rate_limit_is_validated_persisted_and_enforced() {
    let h = Harness::start(local()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    assert_eq!(api.get("/acl", admin).await.ok(200)["rate_limit_qps"], 0);
    api.put("/acl/rate-limit", admin, &json!({"qps": 2_000_000_000_u64})).await.problem(422);
    api.put("/acl/rate-limit", admin, &json!({"qps": -1})).await.problem(422);
    api.put("/acl/rate-limit", admin, &json!({"qps": 1})).await.ok(200);
    assert_eq!(api.get("/acl", admin).await.ok(200)["rate_limit_qps"], 1);
    assert_eq!(api.get("/settings", admin).await.ok(200)["limits"]["per_client_qps"], 1);
    // One query per second per client: a burst gets cut off.
    eventually(WAIT, "a rate-limited query", || async {
        let mut silent = false;
        for _ in 0..6 {
            silent |= udp_silent(h.udp, &query("www.example.test.", RecordType::A)).await;
        }
        silent.then_some(())
    })
    .await;
    api.put("/acl/rate-limit", admin, &json!({"qps": 0})).await.ok(200);
    eventually(WAIT, "the limit to lift", || async {
        let mut all = true;
        for _ in 0..8 {
            all &= www(&h).await.header.rcode == Rcode::NoError;
        }
        all.then_some(())
    })
    .await;
}

// ---- custom rules ----

#[tokio::test]
async fn block_rule_via_api_gives_nxdomain_with_ede_and_delete_lifts_it() {
    let h = Harness::start(local()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    api.patch("/settings", admin, &json!({"filter": {"block_mode": "nxdomain"}})).await.ok(200);
    let rule = api.post("/rules", admin, &json!({"kind": "block", "domain": "bad.example.test"})).await.ok(201);
    assert_eq!((rule["kind"].as_str(), rule["domain"].as_str()), (Some("block"), Some("bad.example.test")));
    let id = rule["id"].as_i64().unwrap();
    // The rule shadows even a name the local zone would answer.
    let blocked = eventually(WAIT, "the rule to block", || async {
        let r = udp_exchange(h.udp, &query_edns("bad.example.test.", RecordType::A, 1232)).await;
        (r.header.rcode == Rcode::NxDomain).then_some(r)
    })
    .await;
    assert_eq!(ede_codes(&blocked), [ede::FILTERED]);
    // Sub-domains too; unrelated names untouched.
    let sub = udp_exchange(h.udp, &query("x.bad.example.test.", RecordType::A)).await;
    assert_eq!(sub.header.rcode, Rcode::NxDomain);
    assert_eq!(www(&h).await.header.rcode, Rcode::NoError);

    let listed = api.get("/rules", admin).await.ok(200);
    assert!(listed.as_array().unwrap().iter().any(|r| r["id"] == id));
    assert_eq!(api.delete(&format!("/rules/{id}"), admin).await.status, 204);
    eventually(WAIT, "the rule to be gone", || async {
        let r = udp_exchange(h.udp, &query("bad.example.test.", RecordType::A)).await;
        (r.header.rcode != Rcode::NxDomain || ede_codes(&r).is_empty()).then_some(())
    })
    .await;
    api.delete(&format!("/rules/{id}"), admin).await.problem(404);
}

#[tokio::test]
async fn rule_validation_and_duplicates() {
    let h = Harness::start(local()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    for domain in ["", "a..b", "not a domain", "-bad-.test", &"a".repeat(300)] {
        let r = api.post("/rules", admin, &json!({"kind": "block", "domain": domain})).await;
        assert!(matches!(r.status, 400 | 422), "{domain:?}: {} {}", r.status, r.text);
        r.problem(r.status);
    }
    let r = api.post("/rules", admin, &json!({"kind": "maybe", "domain": "x.test"})).await;
    assert!(matches!(r.status, 400 | 422), "{}", r.status);
    let first = api.post("/rules", admin, &json!({"kind": "block", "domain": "dup.test"})).await;
    first.ok(201);
    let again = api.post("/rules", admin, &json!({"kind": "block", "domain": "dup.test"})).await;
    assert!(matches!(again.status, 201 | 409), "{}", again.text);
}

// ---- blocklists ----

#[tokio::test]
async fn blocklist_file_source_blocks_toggles_refreshes_and_deletes() {
    let h = Harness::start(local()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let path = h.dir.path().join("mylist.txt");
    std::fs::write(&path, "listed.example.net\n0.0.0.0 hosts.example.net\n").unwrap();
    let created = api
        .post("/blocklists", admin, &json!({"name": "mine", "location": path.to_str().unwrap(), "format": "auto", "allow_private": true}))
        .await;
    assert_eq!(created.status, 201, "{}", created.text);
    let list = created.json();
    let id = list["id"].as_i64().unwrap();
    assert_eq!((list["name"].as_str(), list["enabled"].as_bool(), list["allow_private"].as_bool()), (Some("mine"), Some(true), Some(true)));

    let blocked = |name: &'static str| {
        let h = &h;
        async move {
            let r = udp_exchange(h.udp, &query_edns(name, RecordType::A, 1232)).await;
            matches!(&r.answers.first().map(|a| &a.data), Some(RData::A(ip)) if ip.is_unspecified())
        }
    };
    // A new source is loaded by refresh (or the scheduler); until then it blocks nothing.
    assert_eq!(list["entries"], 0);
    assert!(!blocked("listed.example.net.").await);
    let first = api.post(&format!("/blocklists/{id}/refresh"), admin, &json!({})).await.ok(200);
    assert_eq!(first["entries"], 2, "{first}");
    eventually(WAIT, "the list to block", || async { blocked("listed.example.net.").await.then_some(()) }).await;
    assert!(blocked("hosts.example.net.").await);
    assert!(!blocked("other.example.net.").await);
    let row = api.get("/blocklists", admin).await.ok(200);
    let row = row.as_array().unwrap().iter().find(|b| b["id"] == id).unwrap().clone();
    assert_eq!(row["entries"], 2, "{row}");

    // Disable: no longer blocking. Enable again: blocking.
    assert_eq!(api.patch(&format!("/blocklists/{id}"), admin, &json!({"enabled": false})).await.ok(200)["enabled"], false);
    eventually(WAIT, "the disabled list to stop blocking", || async { (!blocked("listed.example.net.").await).then_some(()) }).await;
    api.patch(&format!("/blocklists/{id}"), admin, &json!({"enabled": true})).await.ok(200);
    eventually(WAIT, "the enabled list to block", || async { blocked("listed.example.net.").await.then_some(()) }).await;

    // Refresh picks up edits of the file.
    std::fs::write(&path, "fresh.example.net\n").unwrap();
    let refreshed = api.post(&format!("/blocklists/{id}/refresh"), admin, &json!({})).await.ok(200);
    assert!(refreshed["outcome"].is_string(), "{refreshed}");
    eventually(WAIT, "the refreshed content", || async { (blocked("fresh.example.net.").await && !blocked("listed.example.net.").await).then_some(()) }).await;

    assert_eq!(api.delete(&format!("/blocklists/{id}"), admin).await.status, 204);
    eventually(WAIT, "the deleted list to stop blocking", || async { (!blocked("fresh.example.net.").await).then_some(()) }).await;
    api.delete(&format!("/blocklists/{id}"), admin).await.problem(404);
    api.patch("/blocklists/99999", admin, &json!({"enabled": true})).await.problem(404);
    api.post("/blocklists/99999/refresh", admin, &json!({})).await.problem(404);
}

#[tokio::test]
async fn blocklist_validation_and_ssrf_guards() {
    let h = Harness::start(local()).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let operator = api.token_for(&h.api_token, "ola", "operator", &["api:read", "api:write"]).await;
    let op = Auth::Bearer(&operator);
    let file = h.dir.path().join("x.txt");
    std::fs::write(&file, "x.test\n").unwrap();

    // Operators can't point the server at files or private/loopback addresses, even when they
    // claim allow_private; admins can.
    for location in [file.to_str().unwrap(), "http://127.0.0.1/list.txt", "http://localhost/list.txt", "http://10.1.2.3/l", "http://[::1]/l"] {
        for allow_private in [false, true] {
            let r = api.post("/blocklists", op, &json!({"name": "n", "location": location, "allow_private": allow_private})).await;
            assert!(matches!(r.status, 403 | 422), "{location} {allow_private}: {} {}", r.status, r.text);
            r.problem(r.status);
        }
    }
    assert_eq!(api.get("/blocklists", admin).await.ok(200), json!([]), "nothing was added");

    for (what, body) in [
        ("interval too short", json!({"name": "n", "location": "https://lists.example.org/a.txt", "interval_secs": 5})),
        ("interval too long", json!({"name": "n", "location": "https://lists.example.org/a.txt", "interval_secs": 100_000_000_u64})),
        ("bad scheme", json!({"name": "n", "location": "ftp://lists.example.org/a.txt"})),
        ("bad format", json!({"name": "n", "location": "https://lists.example.org/a.txt", "format": "csv"})),
        ("unknown field", json!({"name": "n", "location": "https://lists.example.org/a.txt", "colour": "red"})),
    ] {
        let r = api.post("/blocklists", admin, &body).await;
        assert!(matches!(r.status, 400 | 422), "{what}: {} {}", r.status, r.text);
        r.problem(r.status);
    }
}

// ---- settings ----

#[tokio::test]
async fn settings_view_patch_validation_and_live_effect() {
    let h = Harness::start(Opts { block_mode: "null_ip", blocked: vec!["ads.example.net".into()], ..local() }).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let s = api.get("/settings", admin).await.ok(200);
    assert_eq!(s["filter"]["block_mode"], "null_ip");
    assert!(s["cache"]["max_ttl"].is_u64() && s["querylog"]["retention_days"].is_u64());
    // Only the runtime-changeable subset is exposed: no paths, listeners or secrets.
    let text = s.to_string();
    for forbidden in ["data_dir", "listen", "passphrase", "key", "cert", "token"] {
        assert!(!text.contains(forbidden), "settings leak `{forbidden}`: {text}");
    }

    // Block mode takes effect on the next query.
    for (mode, rcode) in [("nxdomain", Rcode::NxDomain), ("refused", Rcode::Refused), ("null_ip", Rcode::NoError)] {
        api.patch("/settings", admin, &json!({"filter": {"block_mode": mode}})).await.ok(200);
        assert_eq!(api.get("/settings", admin).await.ok(200)["filter"]["block_mode"], mode);
        eventually(WAIT, "the block mode to apply", || async {
            let r = udp_exchange(h.udp, &query("ads.example.net.", RecordType::A)).await;
            (r.header.rcode == rcode).then_some(())
        })
        .await;
    }

    // Partial patches leave the rest alone; invalid ones change nothing.
    let before = api.get("/settings", admin).await.ok(200);
    api.patch("/settings", admin, &json!({"querylog": {"retention_days": 30}})).await.ok(200);
    let after = api.get("/settings", admin).await.ok(200);
    assert_eq!(after["querylog"]["retention_days"], 30);
    assert_eq!(after["cache"], before["cache"]);
    for (what, body) in [
        ("min above max", json!({"cache": {"min_ttl": 5000, "max_ttl": 10}})),
        ("unknown group", json!({"listeners": {"udp": ["0.0.0.0:53"]}})),
        ("unknown key", json!({"cache": {"nope": 1}})),
        ("bad mode", json!({"filter": {"block_mode": "explode"}})),
        ("retention too long", json!({"querylog": {"retention_days": 4_000_000}})),
        ("wrong type", json!({"limits": {"per_client_qps": "many"}})),
    ] {
        let r = api.patch("/settings", admin, &body).await;
        assert!(matches!(r.status, 400 | 422), "{what}: {} {}", r.status, r.text);
        r.problem(r.status);
    }
    let unchanged = api.get("/settings", admin).await.ok(200);
    assert_eq!(unchanged, after, "rejected patches changed nothing");
}

// ---- upstream groups ----

fn group(domains: &[&str], upstream: &str) -> Value {
    json!({"strategy": "round_robin", "default": false, "domains": domains, "members": [{"upstream": upstream}]})
}

#[tokio::test]
async fn upstream_group_routes_a_domain_to_its_own_upstream() {
    let h = Harness::start(Opts { upstream: true, ..Opts::default() }).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let default = h.upstream.as_ref().unwrap();
    default.set_default(Reply::Answer(vec![a("split.corp.test.", 60, "192.0.2.1")]));
    let other = FakeUpstream::start().await;
    other.set_default(Reply::Answer(vec![a("split.corp.test.", 60, "198.51.100.1")]));

    let groups = api.get("/upstream-groups", admin).await.ok(200);
    assert!(groups.as_array().unwrap().iter().any(|g| g["default"] == true), "the configured upstream forms a default group: {groups}");

    let mut body = group(&["corp.test"], &format!("udp://{}", other.addr()));
    body["name"] = json!("corp");
    let created = api.post("/upstream-groups", admin, &body).await;
    assert_eq!(created.status, 201, "{}", created.text);
    assert_eq!(created.json()["members"][0]["index"], 0);
    api.post("/upstream-groups", admin, &body).await.problem(409);

    let r = eventually(WAIT, "queries to reach the corp upstream", || async {
        let r = udp_exchange(h.udp, &query("split.corp.test.", RecordType::A)).await;
        matches!(&r.answers.first().map(|a| &a.data), Some(RData::A(ip)) if ip.to_string() == "198.51.100.1").then_some(r)
    })
    .await;
    assert_eq!(r.header.rcode, Rcode::NoError);
    assert!(other.total() >= 1);
    // Health is live and per member.
    let health = api.get("/upstream-groups/corp/health", admin).await.ok(200);
    assert_eq!(health.as_array().unwrap().len(), 1);
    assert_eq!(health[0]["available"], true);
    assert_eq!(api.get("/upstream-groups/corp", admin).await.ok(200)["name"], "corp");

    // Add a member, then remove the first one; the group keeps answering.
    let added = api.post("/upstream-groups/corp/upstreams", admin, &json!({"upstream": format!("udp://{}", default.addr()), "weight": 3})).await;
    assert_eq!(added.status, 201, "{}", added.text);
    assert_eq!(added.json()["members"].as_array().unwrap().len(), 2);
    assert_eq!(api.delete("/upstream-groups/corp/upstreams/0", admin).await.status, 200);
    api.delete("/upstream-groups/corp/upstreams/7", admin).await.problem(404);

    // Replace, then delete: traffic falls back to the default group.
    let replaced = api.put("/upstream-groups/corp", admin, &group(&["corp.test"], &format!("udp://{}", other.addr()))).await;
    assert_eq!(replaced.status, 200, "{}", replaced.text);
    assert_eq!(api.delete("/upstream-groups/corp", admin).await.status, 204);
    api.get("/upstream-groups/corp", admin).await.problem(404);
    api.delete("/upstream-groups/corp", admin).await.problem(404);
    eventually(WAIT, "queries to fall back to the default upstream", || async {
        let r = udp_exchange(h.udp, &query("again.corp.test.", RecordType::A)).await;
        (default.count("again.corp.test.", RecordType::A) > 0 && r.header.rcode != Rcode::Refused).then_some(())
    })
    .await;
}

#[tokio::test]
async fn upstream_group_validation() {
    let h = Harness::start(Opts { upstream: true, ..Opts::default() }).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let up = format!("udp://{}", h.upstream.as_ref().unwrap().addr());
    let named = |name: &str, mut b: Value| {
        b["name"] = json!(name);
        b
    };
    for (what, body) in [
        ("empty name", named("", group(&[], &up))),
        ("bad name chars", named("a b/c", group(&[], &up))),
        ("long name", named(&"n".repeat(100), group(&[], &up))),
        ("no members", named("g", json!({"strategy": "failover", "members": []}))),
        ("bad address", named("g", group(&[], "not an address"))),
        ("weight zero", named("g", json!({"strategy": "weighted", "members": [{"upstream": up, "weight": 0}]}))),
        ("weight huge", named("g", json!({"strategy": "weighted", "members": [{"upstream": up, "weight": 5000}]}))),
        ("bad strategy", named("g", json!({"strategy": "random", "members": [{"upstream": up}]}))),
    ] {
        let r = api.post("/upstream-groups", admin, &body).await;
        assert!(matches!(r.status, 400 | 422), "{what}: {} {}", r.status, r.text);
        r.problem(r.status);
    }
    api.get("/upstream-groups/nope", admin).await.problem(404);
    api.put("/upstream-groups/nope", admin, &group(&[], &up)).await.problem(404);
    api.get("/upstream-groups/nope/health", admin).await.problem(404);
    api.post("/upstream-groups/nope/upstreams", admin, &json!({"upstream": up})).await.problem(404);
}

// ---- client certificates ----

#[tokio::test]
async fn client_certificate_allowlist_crud_and_dot_effect() {
    let h = Harness::start(Opts { dot: Some(MtlsPolicy::Required), ..local() }).await;
    let api = h.rest();
    let admin = Auth::Bearer(&h.api_token);
    let id = h.client_cert_id.unwrap();
    let fp = h.pki.valid_client.fingerprint();
    let list = api.get("/client-certs", admin).await.ok(200);
    let row = list.as_array().unwrap().iter().find(|c| c["id"] == id).unwrap().clone();
    assert_eq!((row["sha256"].as_str(), row["label"].as_str(), row["enabled"].as_bool(), row["expired"].as_bool()), (Some(fp.as_str()), Some("e2e client"), Some(true), Some(false)));

    let try_dot = || async {
        let mut c = Framed::connect_dot(h.dot.unwrap(), &h.pki, Some(&h.pki.valid_client)).await.map_err(|e| e.to_string())?;
        c.ask(&query("www.example.test.", RecordType::A)).await.map_err(|e| e.to_string())
    };
    assert!(try_dot().await.is_ok());

    // Validation and conflicts.
    api.post("/client-certs", admin, &json!({"sha256": fp, "label": "again"})).await.problem(409);
    api.post("/client-certs", admin, &json!({"sha256": "abc", "label": "x"})).await.problem(422);
    api.post("/client-certs", admin, &json!({"sha256": "a".repeat(64), "label": ""})).await.problem(422);
    api.post("/client-certs", admin, &json!({"sha256": "b".repeat(64), "label": "old", "expires_at": 1})).await.problem(422);
    api.post("/client-certs", admin, &json!({"sha256": "c".repeat(64), "label": "l".repeat(200)})).await.problem(422);
    api.patch("/client-certs/99999", admin, &json!({"enabled": false})).await.problem(404);
    api.delete("/client-certs/99999", admin).await.problem(404);

    // Remove the fingerprint: the handshake is now rejected.
    assert_eq!(api.delete(&format!("/client-certs/{id}"), admin).await.status, 204);
    assert!(try_dot().await.is_err(), "a removed fingerprint can't connect");
    // Add it back (new id): connects again.
    let back = api.post("/client-certs", admin, &json!({"sha256": fp, "label": "back"})).await.ok(201);
    assert!(back["id"].is_i64());
    assert!(try_dot().await.is_ok());
}
