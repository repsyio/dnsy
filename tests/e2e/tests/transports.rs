//! DNS over TLS (with and without client certificates) and DNS over HTTPS.

use std::time::Duration;

use dnsy_e2e::clients::{Framed, query_edns, wire};
use dnsy_e2e::zones::example_zone;
use dnsy_e2e::{Harness, MtlsPolicy, Opts, Token, eventually, query};
use dnsy_proto::{Message, RData, Rcode, RecordType};
use reqwest::Method;
use serde_json::json;

fn opts() -> Opts {
    Opts::default().zone("example.test.", example_zone())
}

fn www() -> Message {
    query("www.example.test.", RecordType::A)
}

fn is_www(r: &Message) -> bool {
    r.header.rcode == Rcode::NoError
        && matches!(r.answers.first().map(|a| &a.data), Some(RData::A(ip)) if ip.to_string() == "192.0.2.7")
}

// ---- DoT ----

#[tokio::test]
async fn dot_query() {
    let h = Harness::start(Opts {
        dot: Some(MtlsPolicy::Off),
        ..opts()
    })
    .await;
    let mut c = Framed::connect_dot(h.dot.unwrap(), &h.pki, None)
        .await
        .unwrap();
    let r = c.ask(&www()).await.unwrap();
    assert!(is_www(&r));
    // The connection serves more than one query.
    assert!(is_www(&c.ask(&www()).await.unwrap()));
}

#[tokio::test]
async fn dot_pads_responses_when_asked() {
    let h = Harness::start(Opts {
        dot: Some(MtlsPolicy::Off),
        ..opts()
    })
    .await;
    let mut c = Framed::connect_dot(h.dot.unwrap(), &h.pki, None)
        .await
        .unwrap();
    let mut q = query_edns("www.example.test.", RecordType::A, 1232);
    q.edns
        .as_mut()
        .unwrap()
        .options
        .push(dnsy_proto::EdnsOption::Padding(0));
    c.send(&q).await.unwrap();
    let raw = c.recv_raw().await.unwrap();
    assert_eq!(
        raw.len() % 468,
        0,
        "padded to a multiple of 468, got {}",
        raw.len()
    );
    assert!(is_www(&Message::decode(&raw).unwrap()));
}

#[tokio::test]
async fn dot_plain_tcp_client_is_closed() {
    let h = Harness::start(Opts {
        dot: Some(MtlsPolicy::Off),
        ..opts()
    })
    .await;
    let mut c = Framed::connect_tcp(h.dot.unwrap()).await;
    c.send(&www()).await.unwrap_or(());
    assert!(c.closed_within(Duration::from_secs(10)).await);
}

#[tokio::test]
async fn dot_idle_timeout_closes_connection() {
    let h = Harness::start(Opts {
        dot: Some(MtlsPolicy::Off),
        tcp_idle_ms: 400,
        ..opts()
    })
    .await;
    let mut c = Framed::connect_dot(h.dot.unwrap(), &h.pki, None)
        .await
        .unwrap();
    assert!(is_www(&c.ask(&www()).await.unwrap()));
    assert!(c.closed_within(Duration::from_secs(10)).await);
}

// ---- mTLS ----

async fn dot_h(policy: MtlsPolicy) -> Harness {
    Harness::start(Opts {
        dot: Some(policy),
        ..opts()
    })
    .await
}

/// Connects and asks one query; with TLS 1.3 a rejected client certificate shows on the read.
async fn try_dot(h: &Harness, id: Option<&dnsy_e2e::ClientIdentity>) -> Result<Message, String> {
    let mut c = Framed::connect_dot(h.dot.unwrap(), &h.pki, id)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    c.ask(&www()).await.map_err(|e| format!("query: {e}"))
}

#[tokio::test]
async fn dot_mtls_required_no_cert_fails() {
    let h = dot_h(MtlsPolicy::Required).await;
    assert!(try_dot(&h, None).await.is_err());
}

#[tokio::test]
async fn dot_mtls_valid_cert_ok() {
    let h = dot_h(MtlsPolicy::Required).await;
    let r = try_dot(&h, Some(&h.pki.valid_client)).await.unwrap();
    assert!(is_www(&r));
}

#[tokio::test]
async fn mtls_rejects_untrusted_and_expired_certificates() {
    let h = dot_h(MtlsPolicy::Required).await;
    assert!(try_dot(&h, Some(&h.pki.untrusted_client)).await.is_err());
    assert!(try_dot(&h, Some(&h.pki.expired_client)).await.is_err());
    // Rejections do not hurt the next valid client.
    assert!(try_dot(&h, Some(&h.pki.valid_client)).await.is_ok());
}

#[tokio::test]
async fn mtls_optional_allows_anonymous_but_not_invalid_certs() {
    let h = dot_h(MtlsPolicy::Optional).await;
    assert!(try_dot(&h, None).await.is_ok());
    assert!(try_dot(&h, Some(&h.pki.valid_client)).await.is_ok());
    assert!(try_dot(&h, Some(&h.pki.untrusted_client)).await.is_err());
}

#[tokio::test]
async fn mtls_certificate_not_on_the_allowlist_is_rejected() {
    let h = Harness::start(Opts {
        dot: Some(MtlsPolicy::Required),
        allow_client_cert: false,
        ..opts()
    })
    .await;
    assert!(
        try_dot(&h, Some(&h.pki.valid_client)).await.is_err(),
        "a chain-valid certificate must also be allowlisted"
    );
    let (status, _) = h
        .api_send(
            Method::POST,
            "/client-certs",
            Some(json!({"sha256": h.pki.valid_client.fingerprint(), "label": "late"})),
        )
        .await;
    assert_eq!(status, 201);
    assert!(try_dot(&h, Some(&h.pki.valid_client)).await.is_ok());
}

#[tokio::test]
async fn mtls_removed_certificate_is_cut_off() {
    let h = dot_h(MtlsPolicy::Required).await;
    let id = h.client_cert_id.unwrap();
    let mut open = Framed::connect_dot(h.dot.unwrap(), &h.pki, Some(&h.pki.valid_client))
        .await
        .unwrap();
    assert!(is_www(&open.ask(&www()).await.unwrap()));

    let (status, _) = h
        .api_send(Method::DELETE, &format!("/client-certs/{id}"), None)
        .await;
    assert_eq!(status, 204);

    // The open connection is re-checked on its next query and closed.
    assert!(open.ask(&www()).await.is_err());
    // New handshakes fail too.
    assert!(try_dot(&h, Some(&h.pki.valid_client)).await.is_err());
}

#[tokio::test]
async fn mtls_disabled_certificate_is_rejected_then_reenabled() {
    let h = dot_h(MtlsPolicy::Required).await;
    let id = h.client_cert_id.unwrap();
    let path = format!("/client-certs/{id}");
    let (s, _) = h
        .api_send(Method::PATCH, &path, Some(json!({"enabled": false})))
        .await;
    assert_eq!(s, 200);
    assert!(try_dot(&h, Some(&h.pki.valid_client)).await.is_err());
    let (s, _) = h
        .api_send(Method::PATCH, &path, Some(json!({"enabled": true})))
        .await;
    assert_eq!(s, 200);
    assert!(try_dot(&h, Some(&h.pki.valid_client)).await.is_ok());
}

// ---- DoH ----

async fn doh_h() -> Harness {
    Harness::start(Opts {
        doh: true,
        ..opts()
    })
    .await
}

#[tokio::test]
async fn doh_get_post_with_token() {
    let h = doh_h().await;
    for http2 in [true, false] {
        let doh = h.doh_client(http2);
        for token in [
            Token::Bearer(h.doh_token.clone()),
            Token::Path(h.doh_token.clone()),
        ] {
            for post in [true, false] {
                let resp = if post {
                    doh.post(&www(), &token).await
                } else {
                    doh.get(&www(), &token).await
                };
                assert_eq!(resp.status, 200, "http2={http2} post={post} {token:?}");
                assert_eq!(resp.header("content-type"), Some("application/dns-message"));
                assert_eq!(resp.header("cache-control"), Some("max-age=300"));
                assert!(is_www(&resp.message()));
            }
        }
    }
}

#[tokio::test]
async fn doh_without_token_401() {
    let h = doh_h().await;
    let doh = h.doh_client(true);
    let r = doh.post(&www(), &Token::None).await;
    assert_eq!(r.status, 401);
    assert!(
        r.header("www-authenticate")
            .is_some_and(|v| v.starts_with("Bearer"))
    );
    let r = doh.get(&www(), &Token::None).await;
    assert_eq!(r.status, 401);
    // Wrong, malformed and tampered tokens all look the same.
    let mut tampered = h.doh_token.clone();
    tampered.push('x');
    for t in [
        Token::Bearer("nope".into()),
        Token::Bearer(tampered.clone()),
        Token::Path(tampered),
        Token::Path("dnsy_AAAAAAAAAAAAA_bm9wZQ".into()),
    ] {
        let r = doh.post(&www(), &t).await;
        assert_eq!(r.status, 401, "{t:?}");
        assert!(r.body.is_empty() || Message::decode(&r.body).is_err());
    }
}

#[tokio::test]
async fn doh_token_without_dns_scope_is_forbidden() {
    let h = doh_h().await;
    let read_only = h.new_token("reader", &["api:read"]).await;
    let r = h
        .doh_client(true)
        .post(&www(), &Token::Bearer(read_only))
        .await;
    assert_eq!(r.status, 403);
}

#[tokio::test]
async fn doh_tokens_are_optional_when_not_required() {
    let h = Harness::start(Opts {
        doh: true,
        doh_require_token: false,
        ..opts()
    })
    .await;
    let doh = h.doh_client(true);
    assert_eq!(doh.post(&www(), &Token::None).await.status, 200);
    // A presented token is still verified.
    assert_eq!(
        doh.post(&www(), &Token::Bearer("bogus".into()))
            .await
            .status,
        401
    );
    assert_eq!(
        doh.post(&www(), &Token::Bearer(h.doh_token.clone()))
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn doh_bad_requests() {
    let h = doh_h().await;
    let doh = h.doh_client(true);
    let auth = format!("Bearer {}", h.doh_token);
    let headers = [("authorization", auth.as_str())];
    let dns = [
        ("authorization", auth.as_str()),
        ("content-type", "application/dns-message"),
    ];

    let r = doh
        .raw(Method::GET, "/dns-query?dns=@@@", &headers, vec![])
        .await;
    assert_eq!(r.status, 400, "bad base64");
    let r = doh.raw(Method::GET, "/dns-query", &headers, vec![]).await;
    assert_eq!(r.status, 400, "missing dns parameter");
    let r = doh.raw(Method::POST, "/dns-query", &dns, vec![]).await;
    assert_eq!(r.status, 400, "empty body");
    let r = doh
        .raw(Method::POST, "/dns-query", &dns, vec![1, 2, 3])
        .await;
    assert_eq!(r.status, 400, "not a DNS message");
    let r = doh
        .raw(
            Method::POST,
            "/dns-query",
            &[
                ("authorization", auth.as_str()),
                ("content-type", "text/plain"),
            ],
            wire(&www()),
        )
        .await;
    assert_eq!(r.status, 415);
    let r = doh.raw(Method::PUT, "/dns-query", &dns, wire(&www())).await;
    assert_eq!(r.status, 405);
    let r = doh.raw(Method::GET, "/other", &headers, vec![]).await;
    assert_eq!(r.status, 404);
    // Still fine afterwards.
    assert_eq!(
        doh.post(&www(), &Token::Bearer(h.doh_token.clone()))
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn doh_rate_limits_repeated_auth_failures() {
    let h = doh_h().await;
    let doh = h.doh_client(true);
    let mut limited = false;
    for _ in 0..30 {
        let r = doh.post(&www(), &Token::Bearer("wrong".into())).await;
        if r.status == 429 {
            assert!(r.header("retry-after").is_some());
            limited = true;
            break;
        }
        assert_eq!(r.status, 401);
    }
    assert!(limited, "30 failed tokens from one address must hit 429");
    // Even a valid token is refused while limited, so a guess never reveals validity.
    let r = doh.post(&www(), &Token::Bearer(h.doh_token.clone())).await;
    assert_eq!(r.status, 429);
}

#[tokio::test]
async fn doh_tokens_never_reach_logs_or_the_query_log() {
    let h = Harness::start(Opts {
        doh: true,
        log_level: "debug",
        ..opts()
    })
    .await;
    let doh = h.doh_client(true);
    for token in [
        Token::Path(h.doh_token.clone()),
        Token::Bearer(h.doh_token.clone()),
    ] {
        assert_eq!(doh.get(&www(), &token).await.status, 200);
    }
    let bad = format!("{}zz", h.doh_token);
    assert_eq!(
        doh.post(&www(), &Token::Path(bad.clone())).await.status,
        401
    );
    assert_eq!(
        doh.post(&www(), &Token::Bearer(bad.clone())).await.status,
        401
    );

    // The query log is written asynchronously: wait until both good queries are in.
    let rows = eventually(Duration::from_secs(20), "query log rows", || async {
        let (s, body) = h
            .api_send(Method::GET, "/querylog?domain=www.example.test", None)
            .await;
        (s == 200 && body.to_string().matches("www.example.test").count() >= 2).then_some(body)
    })
    .await;
    let secret_part = h.doh_token.splitn(3, '_').nth(2).unwrap().to_owned();
    for (what, text) in [("logs", h.logs()), ("query log", rows.to_string())] {
        assert!(!text.contains(&h.doh_token), "token leaked into the {what}");
        assert!(
            !text.contains(&secret_part),
            "token secret leaked into the {what}"
        );
        assert!(
            !text.contains(&bad),
            "rejected token leaked into the {what}"
        );
    }
}
