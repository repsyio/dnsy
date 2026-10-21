use std::io;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Instant;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request};
use dnsy_config::Config;
use dnsy_core::{DnssecStatus, Role, Scope};
use dnsy_dnssec::{Clock as _, ManualClock, SystemClock};
use dnsy_engine::{Engine, EngineBuilder};
use dnsy_proto::{Class, Header, Message, Opcode, Question, RData, Rcode, Record, RecordType};
use dnsy_resolver::forward::DnssecPolicy as ResolverPolicy;
use dnsy_resolver::groups::Exchange;
use dnsy_resolver::{CacheKey, Upstream, UpstreamError};
use dnsy_zone::{KdfCost, KeyStore, Passphrase, ZoneStore};
use serde_json::json;
use tower::ServiceExt;

use super::*;
use crate::{ApiConfig, build, openapi};

/// An upstream that is never asked.
struct NoUp;

impl Exchange for NoUp {
    fn exchange(
        &self,
        _: &Upstream,
        _: &Message,
    ) -> impl Future<Output = Result<Message, UpstreamError>> + Send {
        std::future::ready(Err(UpstreamError::Timeout))
    }
}

const PASSPHRASE: &str = "correct-horse-battery-staple";

struct Fx {
    app: Router,
    state: ApiState,
    zones: Arc<ZoneStore>,
    engine: Arc<Engine<NoUp>>,
    clock: ManualClock,
    admin: String,
    operator: String,
    viewer: String,
    _dir: tempfile::TempDir,
}

struct Res {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Res {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.body))
    }
}

async fn fx_with(passphrase: Option<&str>, wire_signing: bool) -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
    let zones = ZoneStore::open(dir.path().join("zones")).unwrap();
    let cfg = Config::default();
    let engine = Arc::new(
        EngineBuilder::new(&cfg, NoUp)
            .dnssec(ResolverPolicy::from_config(&cfg.dnssec).unwrap())
            .build(),
    );
    let clock = ManualClock::new(SystemClock.now());
    let mut state = ApiState::new(store.clone())
        .with_clock(Arc::new(clock.clone()))
        .with_zones(Arc::clone(&zones))
        .with_cache(Arc::clone(engine.cache()))
        .with_validation(engine.clone());
    if wire_signing {
        let keys = KeyStore::open(
            store,
            passphrase.map(Passphrase::new),
            Arc::new(SystemClock),
        )
        .with_kdf_cost(KdfCost {
            memory_kib: 64,
            iterations: 1,
        });
        state = state.with_signing(ZoneSigning::new(Arc::clone(&zones), keys));
    }
    let mut tokens = Vec::new();
    for (user, role, scopes) in [
        (
            "admin",
            Role::Admin,
            vec![Scope::ApiRead, Scope::ApiWrite, Scope::Admin],
        ),
        (
            "operator",
            Role::Operator,
            vec![Scope::ApiRead, Scope::ApiWrite],
        ),
        ("viewer", Role::Viewer, vec![Scope::ApiRead]),
    ] {
        let u = state.users.create(user, "pw-pw-pw", role).await.unwrap();
        tokens.push(
            state
                .tokens
                .create(u.id, "t", &scopes, None)
                .await
                .unwrap()
                .0,
        );
    }
    let app = build(state.clone(), ApiConfig { tls: false }, Router::new());
    let viewer = tokens.pop().unwrap();
    let operator = tokens.pop().unwrap();
    let admin = tokens.pop().unwrap();
    Fx {
        app,
        state,
        zones,
        engine,
        clock,
        admin,
        operator,
        viewer,
        _dir: dir,
    }
}

async fn fx() -> Fx {
    fx_with(None, true).await
}

async fn call_with(
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

async fn admin(fx: &Fx, method: Method, uri: &str, body: Option<Value>) -> Res {
    call_with(fx, &fx.admin, method, uri, &[], body).await
}

const Z: &str = "/api/v1/zones/example.com./dnssec";

async fn create_zone(fx: &Fx) {
    let body = json!({
        "name": "example.com",
        "default_ttl": 300,
        "soa": {"mname": "ns1.example.com.", "rname": "hostmaster.example.com.",
                "refresh": 7200, "retry": 3600, "expire": 1_209_600, "minimum": 300},
        "records": [
            {"name": "@", "type": "NS", "value": "ns1.example.com."},
            {"name": "www", "type": "A", "value": "192.0.2.1"},
        ],
    });
    let res = admin(fx, Method::POST, "/api/v1/zones", Some(body)).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.body);
}

async fn signed_zone(fx: &Fx) -> Value {
    create_zone(fx).await;
    let res = admin(fx, Method::PUT, Z, Some(json!({"enabled": true}))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    res.json()
}

fn origin() -> Name {
    Name::from_ascii("example.com.").unwrap()
}

#[tokio::test]
async fn enable_signing_generates_csk_and_signs() {
    let fx = fx().await;
    create_zone(&fx).await;
    let before = admin(&fx, Method::GET, Z, None).await.json();
    assert_eq!(before["enabled"], false);
    assert_eq!(before["keys"].as_array().unwrap().len(), 0);
    assert_eq!(before["rollover"]["state"], "idle");
    assert!(before["next_resign"].is_null());

    let view = signed_zone_view(&fx).await;
    assert_eq!(view["enabled"], true);
    assert_eq!(view["algorithm"], 13);
    assert_eq!(view["key_layout"], "csk");
    assert_eq!(view["denial"], "nsec3");
    assert_eq!(view["keys_encrypted"], false);
    let keys = view["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["role"], "csk");
    assert_eq!(keys[0]["state"], "active");
    assert!(view["next_resign"].as_i64().unwrap() > 0);
    assert!(fx.zones.snapshot().signed(&origin()).is_some());

    // The policy is in the zone file; the zone listing agrees.
    let list = admin(&fx, Method::GET, "/api/v1/zones", None).await.json();
    assert_eq!(list[0]["dnssec_enabled"], true);

    // Policy changes merge into the stored policy.
    let res = admin(
        &fx,
        Method::PUT,
        Z,
        Some(
            json!({"enabled": true, "denial": "nsec", "signature_validity_days": 20,
                    "refresh_days": 6}),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let v = res.json();
    assert_eq!(v["denial"], "nsec");
    assert_eq!(v["algorithm"], 13);
    assert_eq!(v["signature_validity_days"], 20);
    assert_eq!(v["keys"].as_array().unwrap().len(), 1);

    // KSK/ZSK layout needs a fresh zone's keys, but is accepted as a policy.
    let res = admin(
        &fx,
        Method::PUT,
        Z,
        Some(json!({"enabled": false, "nsec3": {"iterations": 0, "salt": "ab"}})),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let v = res.json();
    assert_eq!(v["enabled"], false);
    assert_eq!(v["nsec3"]["salt"], "ab");
}

async fn signed_zone_view(fx: &Fx) -> Value {
    let res = admin(fx, Method::PUT, Z, Some(json!({"enabled": true}))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    res.json()
}

#[tokio::test]
async fn policy_validation_and_availability() {
    let fx = fx().await;
    create_zone(&fx).await;
    for bad in [
        json!({"enabled": true, "algorithm": 8}),
        json!({"enabled": true, "algorithm": 14}),
        json!({"enabled": true, "nsec3": {"iterations": 5}}),
        json!({"enabled": true, "nsec3": {"salt": "zz"}}),
        json!({"enabled": true, "refresh_days": 30}),
    ] {
        let res = admin(&fx, Method::PUT, Z, Some(bad.clone())).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    let res = admin(&fx, Method::PUT, Z, Some(json!({"algorithm": 13}))).await;
    assert!(res.status.is_client_error(), "enabled is required");
    let res = admin(
        &fx,
        Method::PUT,
        "/api/v1/zones/nope.example./dnssec",
        Some(json!({"enabled": true})),
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let res = admin(&fx, Method::GET, "/api/v1/zones/nope.example./dnssec", None).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    // A failed update changed nothing.
    let view = admin(&fx, Method::GET, Z, None).await.json();
    assert_eq!(view["enabled"], false);

    // No signer wired: every zone DNSSEC route is 503, settings need the engine.
    let bare = fx_with(None, false).await;
    create_zone(&bare).await;
    for (method, uri) in [
        (Method::GET, Z.to_owned()),
        (Method::GET, format!("{Z}/keys")),
        (Method::GET, format!("{Z}/ds")),
    ] {
        let res = admin(&bare, method, &uri, None).await;
        assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
    }
    let res = admin(&bare, Method::PUT, Z, Some(json!({"enabled": true}))).await;
    assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    let mut no_engine = bare.state.clone();
    no_engine.validation = None;
    let app = build(no_engine, ApiConfig { tls: false }, Router::new());
    let req = Request::builder()
        .uri("/api/v1/settings/dnssec")
        .header("authorization", format!("Bearer {}", bare.admin))
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn key_generation_and_listing() {
    let fx = fx().await;
    create_zone(&fx).await;
    let keys = format!("{Z}/keys");
    // Signing must be on first.
    let res = admin(&fx, Method::POST, &keys, Some(json!({"role": "zsk"}))).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    signed_zone_view(&fx).await;

    let res = admin(
        &fx,
        Method::POST,
        &keys,
        Some(json!({"role": "zsk", "algorithm": 15})),
    )
    .await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.body);
    let k = res.json();
    assert_eq!(k["role"], "zsk");
    assert_eq!(k["algorithm"], 15);
    assert_eq!(k["state"], "generated");
    let res = admin(&fx, Method::POST, &keys, Some(json!({"role": "ksk"}))).await;
    assert_eq!(res.json()["algorithm"], 13, "defaults to the policy");
    let res = admin(
        &fx,
        Method::POST,
        &keys,
        Some(json!({"role": "ksk", "algorithm": 8})),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    let list = admin(&fx, Method::GET, &keys, None).await.json();
    assert_eq!(list.as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn ds_endpoint_matches_dnskey() {
    let fx = fx().await;
    signed_zone(&fx).await;
    let ds = admin(&fx, Method::GET, &format!("{Z}/ds"), None).await;
    assert_eq!(ds.status, StatusCode::OK, "{}", ds.body);
    let ds = ds.json();
    assert_eq!(ds["zone"], "example.com.");

    let signing = fx.state.signing.as_ref().unwrap();
    let dnskeys = signing.keys().dnskeys(&origin()).await.unwrap();
    assert_eq!(dnskeys.len(), 1);
    let (rec, dnskey) = &dnskeys[0];
    let records = ds["ds"].as_array().unwrap();
    assert_eq!(records.len(), 2, "SHA-256 then SHA-384");
    for (entry, digest) in records.iter().zip([DigestType::Sha256, DigestType::Sha384]) {
        let expected = ds_for(&origin(), dnskey, digest).unwrap();
        assert_eq!(entry["key_id"], rec.id);
        assert_eq!(entry["key_tag"], expected.key_tag);
        assert_eq!(entry["algorithm"], expected.algorithm);
        assert_eq!(entry["digest_type"], expected.digest_type);
        assert_eq!(
            entry["digest"].as_str().unwrap(),
            hex_upper(&expected.digest)
        );
        assert_eq!(
            entry["record"],
            format!("example.com. IN DS {expected}").as_str()
        );
    }
    assert_eq!(records[0]["digest_type"], 2);
    assert_eq!(records[1]["digest_type"], 4);
    let key = &ds["dnskey"][0];
    assert_eq!(key["flags"], 257);
    assert_eq!(
        key["public_key"],
        STANDARD.encode(&dnskey.public_key).as_str()
    );

    // The same DNSKEY is in the signed export.
    let export = admin(
        &fx,
        Method::GET,
        "/api/v1/zones/example.com./export?signed=true",
        None,
    )
    .await;
    assert!(export.body.contains(&STANDARD.encode(&dnskey.public_key)));

    // Plain text for registrars and `dig`-style tools.
    let text = call_with(
        &fx,
        &fx.admin,
        Method::GET,
        &format!("{Z}/ds"),
        &[("accept", "text/plain")],
        None,
    )
    .await;
    assert_eq!(text.status, StatusCode::OK);
    assert!(
        text.headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let lines: Vec<&str> = text.body.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("example.com. IN DS "));
    assert!(lines[2].starts_with("example.com. IN DNSKEY 257 3 13 "));

    // Unsigned zones have nothing to hand out.
    let nothing = fx_with(None, true).await;
    create_zone(&nothing).await;
    let ds = admin(&nothing, Method::GET, &format!("{Z}/ds"), None)
        .await
        .json();
    assert_eq!(ds["ds"], json!([]));
}

#[tokio::test]
async fn rollover_endpoint_starts_state_machine() {
    let fx = fx().await;
    let view = signed_zone(&fx).await;
    let old = view["keys"][0]["id"].as_i64().unwrap();
    let roll = format!("{Z}/keys/{old}/rollover");

    let res = admin(&fx, Method::POST, &roll, None).await;
    assert_eq!(res.status, StatusCode::ACCEPTED, "{}", res.body);
    let new = res.json();
    assert_eq!(new["state"], "published");
    assert_eq!(new["role"], "csk");
    let new_id = new["id"].as_i64().unwrap();
    assert_ne!(new_id, old);

    let view = admin(&fx, Method::GET, Z, None).await.json();
    assert_eq!(view["rollover"]["state"], "awaiting_ds_confirmation");
    assert_eq!(view["rollover"]["role"], "csk");
    assert_eq!(view["rollover"]["new_key_id"], new_id);
    assert_eq!(view["keys"].as_array().unwrap().len(), 2);

    // The incoming key's DS is available before it is confirmed.
    let ds = admin(&fx, Method::GET, &format!("{Z}/ds"), None)
        .await
        .json();
    assert_eq!(ds["ds"].as_array().unwrap().len(), 4);

    // One rollover at a time; only active keys roll.
    let again = admin(&fx, Method::POST, &roll, Some(json!({"algorithm": 15}))).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    let published = format!("{Z}/keys/{new_id}/rollover");
    let res = admin(&fx, Method::POST, &published, None).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    let res = admin(&fx, Method::POST, &format!("{Z}/keys/9999/rollover"), None).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let res = admin(&fx, Method::POST, &roll, Some(json!({"algorithm": 8}))).await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);

    // DS confirmation lets the machine proceed.
    let confirm = format!("{Z}/keys/{new_id}/ds-confirmed");
    let res = admin(&fx, Method::POST, &confirm, None).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let view = admin(&fx, Method::GET, Z, None).await.json();
    assert_eq!(view["rollover"]["state"], "in_progress");
    let key = view["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == new_id)
        .unwrap();
    assert!(key["ds_confirmed_at"].as_i64().is_some());
    // The active key is not a candidate for DS confirmation.
    let res = admin(
        &fx,
        Method::POST,
        &format!("{Z}/keys/{old}/ds-confirmed"),
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    let res = admin(
        &fx,
        Method::POST,
        &format!("{Z}/keys/9999/ds-confirmed"),
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn keys_of_other_zones_are_not_reachable() {
    let fx = fx().await;
    let view = signed_zone(&fx).await;
    let id = view["keys"][0]["id"].as_i64().unwrap();
    let other = json!({
        "name": "other.test", "default_ttl": 300,
        "soa": {"mname": "ns.other.test.", "rname": "h.other.test.",
                "refresh": 1, "retry": 1, "expire": 1, "minimum": 1},
        "records": [{"name": "@", "type": "NS", "value": "ns.other.test."}],
    });
    let res = admin(&fx, Method::POST, "/api/v1/zones", Some(other)).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.body);
    let base = "/api/v1/zones/other.test./dnssec";
    let res = admin(
        &fx,
        Method::POST,
        &format!("{base}/keys/{id}/rollover"),
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    let res = admin(
        &fx,
        Method::POST,
        &format!("{base}/keys/{id}/ds-confirmed"),
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn signed_export_contains_rrsigs() {
    let fx = fx().await;
    create_zone(&fx).await;
    let export = "/api/v1/zones/example.com./export";
    // Unsigned zone: the plain export works, the signed one does not.
    let res = admin(&fx, Method::GET, export, None).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(!res.body.contains("RRSIG"));
    let res = admin(&fx, Method::GET, &format!("{export}?signed=true"), None).await;
    assert_eq!(res.status, StatusCode::CONFLICT);

    signed_zone_view(&fx).await;
    let res = admin(&fx, Method::GET, &format!("{export}?signed=true"), None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(
        res.headers["content-disposition"]
            .to_str()
            .unwrap()
            .contains("example.com.signed.zone")
    );
    for needle in ["RRSIG", "DNSKEY", "NSEC3PARAM", "www"] {
        assert!(res.body.contains(needle), "{needle} missing:\n{}", res.body);
    }
    let plain = admin(&fx, Method::GET, &format!("{export}?signed=false"), None).await;
    assert!(!plain.body.contains("RRSIG"));
}

fn cache_entry(fx: &Fx) {
    let name = Name::from_ascii("www.example.org.").unwrap();
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
            data: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
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
    fx.engine
        .cache()
        .insert(key, &msg, DnssecStatus::Unchecked, Instant::now());
    assert_eq!(fx.engine.cache().stats().entries, 1);
}

#[tokio::test]
async fn validation_mode_patch_flushes_cache() {
    let fx = fx().await;
    let url = "/api/v1/settings/dnssec";
    let got = admin(&fx, Method::GET, url, None).await;
    assert_eq!(got.status, StatusCode::OK, "{}", got.body);
    let got = got.json();
    assert_eq!(got["validation"], "strict");
    assert_eq!(got["negative_trust_anchors"], json!([]));
    let anchors = got["trust_anchors"].as_array().unwrap();
    assert!(anchors.len() >= 2, "the root KSKs are listed");
    assert_eq!(anchors[0]["kind"], "ds");
    assert_eq!(anchors[0]["owner"], ".");
    assert!(anchors[0]["key_tag"].as_u64().is_some());
    assert_eq!(anchors[0]["digest"].as_str().unwrap().len(), 64);

    cache_entry(&fx);
    let res = admin(
        &fx,
        Method::PATCH,
        url,
        Some(json!({"validation": "permissive"})),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["validation"], "permissive");
    assert_eq!(fx.engine.cache().stats().entries, 0, "mode change flushes");
    assert_eq!(
        admin(&fx, Method::GET, url, None).await.json()["validation"],
        "permissive"
    );

    // The same mode again leaves the cache alone.
    cache_entry(&fx);
    admin(
        &fx,
        Method::PATCH,
        url,
        Some(json!({"validation": "permissive"})),
    )
    .await;
    assert_eq!(fx.engine.cache().stats().entries, 1);

    for bad in [
        json!({"validation": "loose"}),
        json!({}),
        json!({"negative_trust_anchors": ["."]}),
        json!({"negative_trust_anchors": ["a..b.example."]}),
        json!({"unknown": 1}),
    ] {
        let res = admin(&fx, Method::PATCH, url, Some(bad.clone())).await;
        assert!(res.status.is_client_error(), "{bad}: {}", res.status);
    }
    let too_many: Vec<String> = (0..=MAX_NTAS).map(|i| format!("n{i}.test.")).collect();
    let res = admin(
        &fx,
        Method::PATCH,
        url,
        Some(json!({"negative_trust_anchors": too_many})),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        fx.engine.cache().stats().entries,
        1,
        "rejected patches change nothing"
    );
}

#[tokio::test]
async fn nta_management_at_runtime() {
    let fx = fx().await;
    let url = "/api/v1/settings/dnssec";
    cache_entry(&fx);
    let res = admin(
        &fx,
        Method::PATCH,
        url,
        Some(
            json!({"negative_trust_anchors": ["Broken.Example", "other.test.", "broken.example."]}),
        ),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(
        res.json()["negative_trust_anchors"],
        json!(["broken.example.", "other.test."])
    );
    assert_eq!(res.json()["validation"], "strict", "mode untouched");
    assert_eq!(fx.engine.cache().stats().entries, 0, "NTA change flushes");
    assert!(
        fx.engine
            .dnssec_policy()
            .validator
            .anchors()
            .is_negative(&Name::from_ascii("a.broken.example.").unwrap(), 0)
    );
    let res = admin(
        &fx,
        Method::PATCH,
        url,
        Some(json!({"negative_trust_anchors": []})),
    )
    .await;
    assert_eq!(res.json()["negative_trust_anchors"], json!([]));
}

#[tokio::test]
async fn status_reports_mode_clock_and_counters() {
    let fx = fx().await;
    signed_zone(&fx).await;
    let res = admin(&fx, Method::GET, "/api/v1/dnssec/status", None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let s = res.json();
    assert_eq!(s["validation"], "strict");
    assert_eq!(s["clock_trusted"], true);
    assert_eq!(s["signed_zones"], 1);
    assert_eq!(s["secure"], 0);
    assert_eq!(s["bogus"], 0);
    assert!(s["counters"].is_object());
    fx.state
        .dnssec_clock_untrusted
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let s = admin(&fx, Method::GET, "/api/v1/dnssec/status", None)
        .await
        .json();
    assert_eq!(s["clock_trusted"], false);
}

#[tokio::test]
async fn viewer_cannot_change_dnssec() {
    let fx = fx().await;
    let view = signed_zone(&fx).await;
    let id = view["keys"][0]["id"].as_i64().unwrap();
    let writes: Vec<(Method, String, Value)> = vec![
        (Method::PUT, Z.to_owned(), json!({"enabled": false})),
        (Method::POST, format!("{Z}/keys"), json!({"role": "zsk"})),
        (Method::POST, format!("{Z}/keys/{id}/rollover"), json!({})),
        (
            Method::POST,
            format!("{Z}/keys/{id}/ds-confirmed"),
            json!({}),
        ),
        (
            Method::PATCH,
            "/api/v1/settings/dnssec".to_owned(),
            json!({"validation": "off"}),
        ),
    ];
    // Viewers (read) and operators (read + write) both lack the admin scope.
    for token in [&fx.viewer, &fx.operator] {
        for (method, uri, body) in &writes {
            let res = call_with(&fx, token, method.clone(), uri, &[], Some(body.clone())).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "{method} {uri}");
        }
    }
    // Nothing changed, and reading is allowed.
    assert_eq!(fx.engine.dnssec_mode(), Validation::Strict);
    let view = call_with(&fx, &fx.viewer, Method::GET, Z, &[], None)
        .await
        .json();
    assert_eq!(view["enabled"], true);
    assert_eq!(view["keys"].as_array().unwrap().len(), 1);
    for uri in [
        format!("{Z}/keys"),
        format!("{Z}/ds"),
        "/api/v1/settings/dnssec".to_owned(),
        "/api/v1/dnssec/status".to_owned(),
    ] {
        let res = call_with(&fx, &fx.viewer, Method::GET, &uri, &[], None).await;
        assert_eq!(res.status, StatusCode::OK, "{uri}");
    }
    // No token at all.
    let req = Request::builder().uri(Z).body(Body::empty()).unwrap();
    let res = fx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
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

/// Every private key blob in the database, as stored.
async fn stored_secrets(fx: &Fx) -> Vec<Vec<u8>> {
    fx.state
        .store
        .read(|c| {
            let mut stmt = c.prepare("SELECT private_key FROM dnssec_keys")?;
            Ok(stmt
                .query_map([], |r| r.get::<_, Vec<u8>>(0))?
                .collect::<Result<_, _>>()?)
        })
        .await
        .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    hex_upper(bytes).to_lowercase()
}

const BACKUP_PASSPHRASE: &str = "backup-pass-phrase-77";
const NEW_PASSPHRASE: &str = "rotated-pass-phrase-88";

async fn assert_no_secret_leaks(passphrase: Option<&str>) {
    let buf = Buf::default();
    let sink = buf.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);

    let fx = fx_with(passphrase, true).await;
    let view = signed_zone(&fx).await;
    assert_eq!(view["keys_encrypted"], passphrase.is_some());
    let id = view["keys"][0]["id"].as_i64().unwrap();

    let mut bodies = vec![view.to_string()];
    let responses = [
        (Method::GET, Z.to_owned(), None),
        (Method::GET, format!("{Z}/keys"), None),
        (
            Method::POST,
            format!("{Z}/keys"),
            Some(json!({"role": "zsk"})),
        ),
        (Method::POST, format!("{Z}/keys/{id}/rollover"), None),
        (Method::GET, format!("{Z}/ds"), None),
        (
            Method::GET,
            "/api/v1/zones/example.com./export?signed=true".to_owned(),
            None,
        ),
        (
            Method::GET,
            "/api/v1/zones/example.com./export".to_owned(),
            None,
        ),
        (Method::GET, "/api/v1/settings/dnssec".to_owned(), None),
        (Method::GET, "/api/v1/dnssec/status".to_owned(), None),
        (
            Method::POST,
            "/api/v1/dnssec/keys/export".to_owned(),
            Some(json!({"passphrase": BACKUP_PASSPHRASE})),
        ),
        (
            Method::POST,
            "/api/v1/dnssec/passphrase".to_owned(),
            Some(json!({"new_passphrase": NEW_PASSPHRASE})),
        ),
        (
            Method::POST,
            "/api/v1/dnssec/keys/export".to_owned(),
            Some(json!({"passphrase": "short"})),
        ),
        // Error responses too.
        (Method::POST, format!("{Z}/keys/{id}/rollover"), None),
        (Method::POST, format!("{Z}/keys/99999/rollover"), None),
        (
            Method::POST,
            format!("{Z}/keys"),
            Some(json!({"role": "zsk", "algorithm": 8})),
        ),
    ];
    for (method, uri, body) in responses {
        let res = admin(&fx, method, &uri, body).await;
        bodies.push(res.body);
    }

    let secrets = stored_secrets(&fx).await;
    assert!(secrets.len() >= 3, "keys were stored");
    let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.is_empty(), "the test captured logs");
    for body in &bodies {
        assert!(!body.to_lowercase().contains("private"), "{body}");
    }
    // The key store's startup warning legitimately says "private keys"; key material is what
    // must stay out.
    let mut haystacks = bodies;
    haystacks.push(logs);
    for text in &haystacks {
        assert!(!text.contains("pkcs8"), "{text}");
        if let Some(p) = passphrase {
            assert!(!text.contains(p), "passphrase leaked");
        }
        for p in [BACKUP_PASSPHRASE, NEW_PASSPHRASE] {
            assert!(!text.contains(p), "passphrase leaked");
        }
        for secret in secrets.iter().filter(|s| !s.is_empty()) {
            for encoded in [
                hex(secret),
                hex(secret).to_uppercase(),
                STANDARD.encode(secret),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
            ] {
                assert!(!text.contains(&encoded), "key material leaked");
            }
        }
    }
}

#[tokio::test]
async fn private_key_never_returned() {
    assert_no_secret_leaks(None).await;
    assert_no_secret_leaks(Some(PASSPHRASE)).await;
}

#[test]
fn openapi_has_no_private_key_field() {
    let doc = serde_json::to_value(openapi()).unwrap();
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    for name in ["KeyView", "DnssecView", "DsExport", "DnskeyRecordView"] {
        let props = schemas[name]["properties"].as_object().unwrap();
        assert!(
            props
                .keys()
                .all(|k| !k.contains("private") && !k.contains("pkcs8")),
            "{name}"
        );
    }
    assert!(doc["paths"]["/api/v1/zones/{name}/dnssec/ds"].is_object());
}

#[test]
fn key_errors_map_to_problems() {
    assert!(matches!(
        key_error(&KeyStoreError::NotFound(1)),
        ApiError::NotFound(_)
    ));
    assert!(matches!(
        key_error(&KeyStoreError::NoActiveKey(KeyRole::Ksk)),
        ApiError::Conflict(_)
    ));
    assert!(matches!(
        key_error(&KeyStoreError::InvalidState("x")),
        ApiError::Conflict(_)
    ));
    // Everything else is hidden from the client.
    assert!(matches!(
        key_error(&KeyStoreError::Decrypt),
        ApiError::Internal(_)
    ));
    assert!(matches!(
        key_error(&KeyStoreError::PassphraseRequired),
        ApiError::Internal(_)
    ));
}

// ---------------------------------------------------------------------------------------
// DNSY-70: operations gaps

fn keys_of(view: &Value) -> usize {
    view["keys"].as_array().unwrap().len()
}

#[tokio::test]
async fn enabling_signing_again_or_concurrently_keeps_one_key_set() {
    let fx = fx().await;
    create_zone(&fx).await;
    let body = || Some(json!({"enabled": true, "key_layout": "ksk_zsk"}));
    let (a, b, c) = tokio::join!(
        admin(&fx, Method::PUT, Z, body()),
        admin(&fx, Method::PUT, Z, body()),
        admin(&fx, Method::PUT, Z, body())
    );
    for r in [a, b, c] {
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    let again = admin(&fx, Method::PUT, Z, body()).await.json();
    assert_eq!(keys_of(&again), 2, "one KSK and one ZSK, no duplicates");

    // Disable, enable: the existing keys are reused.
    admin(&fx, Method::PUT, Z, Some(json!({"enabled": false}))).await;
    let back = admin(&fx, Method::PUT, Z, Some(json!({"enabled": true})))
        .await
        .json();
    assert_eq!(keys_of(&back), 2);
}

#[tokio::test]
async fn propagation_delay_is_a_policy_field() {
    let fx = fx().await;
    let view = signed_zone(&fx).await;
    assert_eq!(view["propagation_delay"], 3600);
    let res = admin(
        &fx,
        Method::PUT,
        Z,
        Some(json!({"enabled": true, "propagation_delay": 120})),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["propagation_delay"], 120);
    let res = admin(
        &fx,
        Method::PUT,
        Z,
        Some(json!({"enabled": true, "propagation_delay": 604_801})),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", res.body);
    assert_eq!(
        admin(&fx, Method::GET, Z, None).await.json()["propagation_delay"],
        120,
        "a rejected change leaves the policy alone"
    );
}

async fn split_zone(fx: &Fx) -> Value {
    create_zone(fx).await;
    let res = admin(
        fx,
        Method::PUT,
        Z,
        Some(json!({"enabled": true, "key_layout": "ksk_zsk"})),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    res.json()
}

fn key_id(view: &Value, role: &str) -> i64 {
    view["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["role"] == role && k["state"] == "active")
        .unwrap()["id"]
        .as_i64()
        .unwrap()
}

#[tokio::test]
async fn rollover_view_lists_concurrent_roles() {
    let fx = fx().await;
    let view = split_zone(&fx).await;
    assert_eq!(view["rollover"]["rollovers"], json!([]));
    let (ksk, zsk) = (key_id(&view, "ksk"), key_id(&view, "zsk"));
    let k = admin(&fx, Method::POST, &format!("{Z}/keys/{ksk}/rollover"), None).await;
    let z = admin(&fx, Method::POST, &format!("{Z}/keys/{zsk}/rollover"), None).await;
    assert_eq!(k.status, StatusCode::ACCEPTED, "{}", k.body);
    assert_eq!(z.status, StatusCode::ACCEPTED, "{}", z.body);

    let view = admin(&fx, Method::GET, Z, None).await.json();
    let roll = &view["rollover"];
    assert_eq!(roll["state"], "awaiting_ds_confirmation");
    let list = roll["rollovers"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    let find = |role: &str| list.iter().find(|r| r["role"] == role).unwrap();
    assert_eq!(find("ksk")["state"], "awaiting_ds_confirmation");
    assert_eq!(find("ksk")["new_key_id"], k.json()["id"]);
    assert_eq!(find("zsk")["state"], "in_progress");
    assert_eq!(find("zsk")["new_key_id"], z.json()["id"]);
    assert_eq!(
        roll["role"], list[0]["role"],
        "legacy fields name the first"
    );
}

#[tokio::test]
async fn abort_rollover_restores_the_previous_state() {
    let fx = fx().await;
    let view = split_zone(&fx).await;
    let abort = format!("{Z}/rollover/abort");
    let res = admin(&fx, Method::POST, &abort, None).await;
    assert_eq!(
        res.status,
        StatusCode::CONFLICT,
        "nothing to abort: {}",
        res.body
    );

    let (ksk, zsk) = (key_id(&view, "ksk"), key_id(&view, "zsk"));
    admin(&fx, Method::POST, &format!("{Z}/keys/{ksk}/rollover"), None).await;
    admin(&fx, Method::POST, &format!("{Z}/keys/{zsk}/rollover"), None).await;

    // Operators cannot abort; admins can, one role at a time.
    let denied = call_with(&fx, &fx.operator, Method::POST, &abort, &[], None).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let res = admin(&fx, Method::POST, &abort, Some(json!({"role": "ksk"}))).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let roll = res.json()["rollover"].clone();
    assert_eq!(roll["rollovers"].as_array().unwrap().len(), 1);
    assert_eq!(roll["rollovers"][0]["role"], "zsk");
    let res = admin(&fx, Method::POST, &abort, Some(json!({"role": "ksk"}))).await;
    assert_eq!(res.status, StatusCode::CONFLICT);

    let res = admin(&fx, Method::POST, &abort, None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let after = res.json();
    assert_eq!(after["rollover"]["state"], "idle");
    assert_eq!(after["rollover"]["rollovers"], json!([]));
    assert_eq!(keys_of(&after), 2, "only the original keys remain");
    assert_eq!(key_id(&after, "ksk"), ksk);
    assert_eq!(key_id(&after, "zsk"), zsk);
    let ds = admin(&fx, Method::GET, &format!("{Z}/ds"), None)
        .await
        .json();
    assert_eq!(
        ds["dnskey"].as_array().unwrap().len(),
        1,
        "DNSKEY withdrawn"
    );

    // A fresh rollover can start again.
    let res = admin(&fx, Method::POST, &format!("{Z}/keys/{zsk}/rollover"), None).await;
    assert_eq!(res.status, StatusCode::ACCEPTED);
    let res = admin(
        &fx,
        Method::POST,
        "/api/v1/zones/nope.test./dnssec/rollover/abort",
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn key_export_is_encrypted_and_admin_only() {
    let fx = fx_with(Some(PASSPHRASE), true).await;
    signed_zone(&fx).await;
    let url = "/api/v1/dnssec/keys/export";
    let res = admin(
        &fx,
        Method::POST,
        url,
        Some(json!({"passphrase": BACKUP_PASSPHRASE})),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let bundle = STANDARD
        .decode(res.json()["bundle"].as_str().unwrap())
        .unwrap();

    // The bundle restores into a store with another key passphrase.
    let dir = tempfile::tempdir().unwrap();
    let other = KeyStore::open(
        dnsy_store::Store::open(&dir.path().join("o.db")).unwrap(),
        Some(Passphrase::new("another-key-passphrase")),
        Arc::new(SystemClock),
    )
    .with_kdf_cost(KdfCost {
        memory_kib: 64,
        iterations: 1,
    });
    assert!(
        other
            .import_bundle(&bundle, &Passphrase::new("wrong-wrong-wrong"))
            .await
            .is_err()
    );
    assert_eq!(
        other
            .import_bundle(&bundle, &Passphrase::new(BACKUP_PASSPHRASE))
            .await
            .unwrap(),
        1
    );

    let one = admin(
        &fx,
        Method::POST,
        url,
        Some(json!({"passphrase": BACKUP_PASSPHRASE, "zone": "example.com."})),
    )
    .await;
    assert_eq!(one.status, StatusCode::OK);
    for (body, status) in [
        (
            json!({"passphrase": BACKUP_PASSPHRASE, "zone": "nope.test."}),
            StatusCode::NOT_FOUND,
        ),
        (
            json!({"passphrase": "short"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let res = admin(&fx, Method::POST, url, Some(body)).await;
        assert_eq!(res.status, status, "{}", res.body);
    }
    for token in [&fx.operator, &fx.viewer] {
        let res = call_with(
            &fx,
            token,
            Method::POST,
            url,
            &[],
            Some(json!({"passphrase": BACKUP_PASSPHRASE})),
        )
        .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn passphrase_change_reencrypts_keys_and_signing_continues() {
    let fx = fx_with(Some(PASSPHRASE), true).await;
    signed_zone(&fx).await;
    let before = stored_secrets(&fx).await;
    let url = "/api/v1/dnssec/passphrase";

    let res = admin(
        &fx,
        Method::POST,
        url,
        Some(json!({"new_passphrase": "short"})),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        stored_secrets(&fx).await,
        before,
        "a rejected change touches nothing"
    );
    for token in [&fx.operator, &fx.viewer] {
        let res = call_with(
            &fx,
            token,
            Method::POST,
            url,
            &[],
            Some(json!({"new_passphrase": NEW_PASSPHRASE})),
        )
        .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN);
    }

    let res = admin(
        &fx,
        Method::POST,
        url,
        Some(json!({"new_passphrase": NEW_PASSPHRASE})),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["keys_reencrypted"], 1);
    assert_ne!(stored_secrets(&fx).await, before);
    assert!(!res.body.contains(NEW_PASSPHRASE));

    // The running signer keeps working with the new passphrase: a rollover signs the DNSKEY
    // set with keys decrypted under it.
    let view = admin(&fx, Method::GET, Z, None).await.json();
    assert_eq!(view["keys_encrypted"], true);
    let old = key_id(&view, "csk");
    let res = admin(&fx, Method::POST, &format!("{Z}/keys/{old}/rollover"), None).await;
    assert_eq!(res.status, StatusCode::ACCEPTED, "{}", res.body);
    let export = admin(
        &fx,
        Method::GET,
        "/api/v1/zones/example.com./export?signed=true",
        None,
    )
    .await;
    assert_eq!(export.status, StatusCode::OK);
    assert!(export.body.contains("RRSIG"));
}

#[tokio::test]
async fn dnssec_ops_need_signing() {
    let fx = fx_with(None, false).await;
    for (uri, body) in [
        (
            "/api/v1/dnssec/keys/export",
            json!({"passphrase": BACKUP_PASSPHRASE}),
        ),
        (
            "/api/v1/dnssec/passphrase",
            json!({"new_passphrase": NEW_PASSPHRASE}),
        ),
        (
            "/api/v1/zones/example.com./dnssec/rollover/abort",
            json!({}),
        ),
    ] {
        let res = admin(&fx, Method::POST, uri, Some(body)).await;
        assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE, "{uri}");
    }
}

#[tokio::test]
async fn nta_expiry_through_the_api() {
    let fx = fx().await;
    let url = "/api/v1/settings/dnssec";
    let now = fx.clock.now();
    let res = admin(
        &fx,
        Method::PATCH,
        url,
        Some(json!({"negative_trust_anchors": [
            "forever.example",
            {"name": "Lab.Test", "expires_at": now + 100},
            {"name": "plain.test"},
        ]})),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let v = res.json();
    assert_eq!(
        v["negative_trust_anchors"],
        json!(["forever.example.", "lab.test.", "plain.test."])
    );
    assert_eq!(
        v["negative_trust_anchor_entries"],
        json!([
            {"name": "forever.example.", "expires_at": null},
            {"name": "lab.test.", "expires_at": now + 100},
            {"name": "plain.test.", "expires_at": null},
        ])
    );
    let anchors = fx.engine.dnssec_policy();
    assert_eq!(
        anchors.validator.anchors().negative_entries().len(),
        3,
        "the engine holds the expiry"
    );

    // Past the expiry the anchor is gone from the listing.
    fx.clock.advance(100);
    let v = admin(&fx, Method::GET, url, None).await.json();
    assert_eq!(
        v["negative_trust_anchors"],
        json!(["forever.example.", "plain.test."])
    );
    assert_eq!(
        v["negative_trust_anchor_entries"].as_array().unwrap().len(),
        2
    );

    // An expiry that is not in the future, or does not fit, is refused; nothing changes.
    for expires in [json!(now + 100), json!(0), json!(-5), json!(i64::MAX)] {
        let res = admin(
            &fx,
            Method::PATCH,
            url,
            Some(json!({"negative_trust_anchors": [{"name": "late.test", "expires_at": expires}]})),
        )
        .await;
        assert_eq!(
            res.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{expires}: {}",
            res.body
        );
    }
    let res = admin(
        &fx,
        Method::PATCH,
        url,
        Some(json!({"negative_trust_anchors": [{"name": "x.test", "bogus": 1}]})),
    )
    .await;
    assert!(res.status.is_client_error());
    let v = admin(&fx, Method::GET, url, None).await.json();
    assert_eq!(v["negative_trust_anchors"].as_array().unwrap().len(), 2);
}
