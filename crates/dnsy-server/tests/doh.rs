//! `DoH` listener tests. All sockets bind port 0; certificates come from a throwaway test CA.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dnsy_auth::{TokenService, UserService};
use dnsy_core::{Principal, Role, Scope, Transport};
use dnsy_engine::{Handler, RequestContext};
use dnsy_proto::{Class, Message, Name, Question, RData, Rcode, Record, RecordType};
use dnsy_server::{DohConfig, Server, ServerConfig, TokenAuth};
use dnsy_store::Store;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, header};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing_subscriber::fmt::MakeWriter;

const MSG: &str = "application/dns-message";

/// Answers with A records of TTL 300 and 60, and remembers what it was told.
type Seen = Arc<Mutex<Vec<(Transport, Option<Principal>, String)>>>;

#[derive(Clone, Default)]
struct Recorder {
    seen: Seen,
}

impl Handler for Recorder {
    fn handle(&self, ctx: RequestContext, query: &Message) -> impl Future<Output = Message> + Send {
        self.seen.lock().unwrap().push((
            ctx.transport,
            ctx.principal.clone(),
            format!("{ctx:?} {query:?}"),
        ));
        let mut r = Message::response_to(query);
        r.header.rcode = Rcode::NoError;
        for ttl in [300, 60] {
            r.answers.push(Record {
                name: query.questions[0].name.clone(),
                rtype: RecordType::A,
                class: Class::In,
                ttl,
                data: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            });
        }
        std::future::ready(r)
    }
}

struct Fixture {
    server: Server,
    addr: SocketAddr,
    recorder: Recorder,
    ca: rustls_pki_types::CertificateDer<'static>,
    good: String,
    no_scope: String,
    _dir: tempfile::TempDir,
}

async fn fixture(require: bool, max_failures: u32) -> Fixture {
    fixture_tracking(require, max_failures, dnsy_auth::DEFAULT_MAX_TRACKED).await
}

async fn fixture_tracking(require: bool, max_failures: u32, max_tracked: usize) -> Fixture {
    fixture_with(require, max_failures, |doh| {
        doh.max_tracked_clients = max_tracked;
    })
    .await
}

async fn fixture_with(
    require: bool,
    max_failures: u32,
    tweak: impl FnOnce(&mut DohConfig),
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).unwrap().der().clone();
    let issuer = Issuer::new(params, ca_key);
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["dns.test".to_owned()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    std::fs::write(dir.path().join("cert.pem"), leaf.pem()).unwrap();
    std::fs::write(dir.path().join("key.pem"), key.serialize_pem()).unwrap();

    let store = Store::open(&dir.path().join("t.db")).unwrap();
    let user = UserService::new(store.clone())
        .create("alice", "pw", Role::Operator)
        .await
        .unwrap();
    let tokens = TokenService::new(store);
    let (good, _) = tokens
        .create(user.id, "dns", &[Scope::DnsQuery], None)
        .await
        .unwrap();
    let (no_scope, _) = tokens
        .create(user.id, "api", &[Scope::ApiRead], None)
        .await
        .unwrap();

    let recorder = Recorder::default();
    let lo: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut doh = DohConfig::new(
        vec![lo],
        dir.path().join("cert.pem"),
        dir.path().join("key.pem"),
        Arc::new(TokenAuth(tokens)),
    );
    doh.require_token = require;
    doh.max_auth_failures = max_failures;
    tweak(&mut doh);
    let mut config = ServerConfig::new(vec![], vec![]);
    config.doh = Some(doh);
    let server = Server::start(config, Arc::new(recorder.clone()))
        .await
        .unwrap();
    let addr = server.doh_addrs()[0];
    Fixture {
        server,
        addr,
        recorder,
        ca,
        good,
        no_scope,
        _dir: dir,
    }
}

enum Sender {
    H1(hyper::client::conn::http1::SendRequest<Full<Bytes>>),
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

struct Client {
    sender: Sender,
    alpn: Vec<u8>,
}

struct Reply {
    status: u16,
    headers: hyper::HeaderMap,
    body: Vec<u8>,
}

impl Client {
    async fn connect(f: &Fixture, h2: bool) -> Client {
        Client::connect_from(f, h2, None).await
    }

    /// Connects from the given loopback source address.
    async fn connect_from(f: &Fixture, h2: bool, from: Option<&str>) -> Client {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(f.ca.clone()).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![if h2 {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];
        let tcp = match from {
            Some(src) => {
                let socket = tokio::net::TcpSocket::new_v4().unwrap();
                socket
                    .bind((src.parse::<Ipv4Addr>().unwrap(), 0).into())
                    .unwrap();
                socket.connect(f.addr).await.unwrap()
            }
            None => TcpStream::connect(f.addr).await.unwrap(),
        };
        let tls = TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("dns.test").unwrap(), tcp)
            .await
            .unwrap();
        let alpn = tls.get_ref().1.alpn_protocol().unwrap().to_vec();
        let io = TokioIo::new(tls);
        let sender = if h2 {
            let (s, c) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                .await
                .unwrap();
            tokio::spawn(c);
            Sender::H2(s)
        } else {
            let (s, c) = hyper::client::conn::http1::handshake(io).await.unwrap();
            tokio::spawn(c);
            Sender::H1(s)
        };
        Client { sender, alpn }
    }

    async fn send(&mut self, req: Request<Full<Bytes>>) -> Reply {
        let response = match &mut self.sender {
            Sender::H1(s) => s.send_request(req).await.unwrap(),
            Sender::H2(s) => s.send_request(req).await.unwrap(),
        };
        let (parts, body) = response.into_parts();
        Reply {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body: body.collect().await.unwrap().to_bytes().to_vec(),
        }
    }
}

fn query(id: u16) -> Vec<u8> {
    let mut m = Message::response_to(&Message::decode(&[0; 12]).unwrap());
    m.header.qr = false;
    m.header.rd = true;
    m.header.id = id;
    m.questions.push(Question {
        name: Name::from_ascii("example.com.").unwrap(),
        qtype: RecordType::A,
        qclass: Class::In,
    });
    m.encode(512).unwrap()
}

fn get(path_and_query: &str, bearer: Option<&str>) -> Request<Full<Bytes>> {
    let mut b = Request::builder()
        .method(Method::GET)
        .uri(format!("https://dns.test{path_and_query}"))
        .header(header::HOST, "dns.test");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Full::default()).unwrap()
}

fn get_dns(path: &str, bearer: Option<&str>) -> Request<Full<Bytes>> {
    get(
        &format!("{path}?dns={}", URL_SAFE_NO_PAD.encode(query(7))),
        bearer,
    )
}

fn post(path: &str, bearer: Option<&str>, ct: &str, body: Vec<u8>) -> Request<Full<Bytes>> {
    let mut b = Request::builder()
        .method(Method::POST)
        .uri(format!("https://dns.test{path}"))
        .header(header::HOST, "dns.test")
        .header(header::CONTENT_TYPE, ct);
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Full::new(Bytes::from(body))).unwrap()
}

fn assert_answer(r: &Reply) {
    assert_eq!(r.status, 200);
    assert_eq!(r.headers[header::CONTENT_TYPE], MSG);
    let m = Message::decode(&r.body).unwrap();
    assert_eq!(m.header.id, 7);
    assert_eq!(m.answers.len(), 2);
}

#[tokio::test]
async fn doh_get_and_post() {
    let f = fixture(true, 10).await;
    for h2 in [false, true] {
        let mut c = Client::connect(&f, h2).await;
        assert_eq!(
            c.alpn,
            if h2 {
                b"h2".to_vec()
            } else {
                b"http/1.1".to_vec()
            }
        );
        let r = c.send(get_dns("/dns-query", Some(&f.good))).await;
        assert_answer(&r);
        let r = c
            .send(post("/dns-query", Some(&f.good), MSG, query(7)))
            .await;
        assert_answer(&r);
    }
    let seen = f.recorder.seen.lock().unwrap();
    assert_eq!(seen.len(), 4);
    assert!(
        seen.iter()
            .all(|(t, p, _)| *t == Transport::Doh && p.is_some())
    );
}

#[tokio::test]
async fn doh_requires_token() {
    let f = fixture(true, 10).await;
    let mut c = Client::connect(&f, false).await;
    let r = c.send(get_dns("/dns-query", None)).await;
    assert_eq!(r.status, 401);
    assert_eq!(r.headers[header::WWW_AUTHENTICATE], "Bearer");
    let r = c.send(get_dns("/dns-query", Some("dnsy_nope"))).await;
    assert_eq!(r.status, 401);
    assert!(f.recorder.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn doh_optional_token_when_not_required() {
    let f = fixture(false, 10).await;
    let mut c = Client::connect(&f, true).await;
    assert_answer(&c.send(get_dns("/dns-query", None)).await);
    // A presented token is still verified.
    assert_eq!(c.send(get_dns("/dns-query", Some("bad"))).await.status, 401);
    assert_answer(&c.send(get_dns("/dns-query", Some(&f.good))).await);
    let seen = f.recorder.seen.lock().unwrap();
    assert!(seen[0].1.is_none() && seen[1].1.is_some());
}

#[tokio::test]
async fn doh_wrong_scope_403() {
    let f = fixture(true, 10).await;
    let mut c = Client::connect(&f, false).await;
    let r = c.send(get_dns("/dns-query", Some(&f.no_scope))).await;
    assert_eq!(r.status, 403);
    assert!(f.recorder.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn doh_path_token_works() {
    let f = fixture(true, 10).await;
    let mut c = Client::connect(&f, true).await;
    let r = c
        .send(get_dns(&format!("/dns-query/{}", f.good), None))
        .await;
    assert_answer(&r);
    let r = c
        .send(post(&format!("/dns-query/{}", f.good), None, MSG, query(7)))
        .await;
    assert_answer(&r);
    let r = c
        .send(get_dns(&format!("/dns-query/{}x", f.good), None))
        .await;
    assert_eq!(r.status, 401);
}

#[tokio::test]
async fn doh_bad_content_type_415() {
    let f = fixture(true, 10).await;
    let mut c = Client::connect(&f, false).await;
    let r = c
        .send(post(
            "/dns-query",
            Some(&f.good),
            "application/json",
            query(7),
        ))
        .await;
    assert_eq!(r.status, 415);
}

#[tokio::test]
async fn doh_cache_control_min_ttl() {
    let f = fixture(false, 10).await;
    let mut c = Client::connect(&f, false).await;
    let r = c.send(get_dns("/dns-query", None)).await;
    assert_eq!(r.headers[header::CACHE_CONTROL], "max-age=60");
}

#[tokio::test]
async fn doh_response_with_token_is_private() {
    let f = fixture(false, 10).await;
    let mut c = Client::connect(&f, false).await;
    let r = c.send(get_dns("/dns-query", Some(&f.good))).await;
    assert_eq!(r.headers[header::CACHE_CONTROL], "private, max-age=60");
    let r = c
        .send(get_dns(&format!("/dns-query/{}", f.good), None))
        .await;
    assert_eq!(r.headers[header::CACHE_CONTROL], "private, max-age=60");
}

fn forwarded(mut req: Request<Full<Bytes>>, xff: &str) -> Request<Full<Bytes>> {
    req.headers_mut()
        .append("x-forwarded-for", xff.parse().unwrap());
    req
}

async fn proxied_fixture(max_failures: u32) -> Fixture {
    fixture_with(true, max_failures, |doh| {
        doh.trusted_proxies = vec!["127.0.0.2/32".parse().unwrap()];
    })
    .await
}

#[tokio::test]
async fn doh_throttle_keys_on_forwarded_client_from_trusted_proxy_only() {
    let f = proxied_fixture(2).await;
    let mut proxy = Client::connect_from(&f, false, Some("127.0.0.2")).await;
    for _ in 0..2 {
        let r = proxy
            .send(forwarded(
                get_dns("/dns-query", Some("garbage")),
                "203.0.113.1",
            ))
            .await;
        assert_eq!(r.status, 401);
    }
    let a = forwarded(get_dns("/dns-query", Some(&f.good)), "203.0.113.1");
    assert_eq!(proxy.send(a).await.status, 429);
    // Another client behind the same proxy is not locked out.
    let b = forwarded(get_dns("/dns-query", Some(&f.good)), "203.0.113.2");
    assert_eq!(proxy.send(b).await.status, 200);

    // An untrusted peer cannot dodge its own lockout by varying the header.
    let mut direct = Client::connect_from(&f, false, Some("127.0.0.3")).await;
    for n in 0..2 {
        let r = direct
            .send(forwarded(
                get_dns("/dns-query", Some("garbage")),
                &format!("198.51.100.{n}"),
            ))
            .await;
        assert_eq!(r.status, 401);
    }
    let r = direct
        .send(forwarded(
            get_dns("/dns-query", Some(&f.good)),
            "198.51.100.9",
        ))
        .await;
    assert_eq!(r.status, 429);
}

#[tokio::test]
async fn doh_response_from_a_proxied_listener_is_private() {
    let f = fixture_with(false, 10, |doh| {
        doh.trusted_proxies = vec!["127.0.0.2/32".parse().unwrap()];
    })
    .await;
    // Even without a token, and even for a peer that is not the proxy.
    for from in ["127.0.0.2", "127.0.0.3"] {
        let mut c = Client::connect_from(&f, false, Some(from)).await;
        let r = c
            .send(forwarded(get_dns("/dns-query", None), "203.0.113.9"))
            .await;
        assert_eq!(
            r.headers[header::CACHE_CONTROL],
            "private, max-age=60",
            "{from}"
        );
    }
}

#[tokio::test]
async fn doh_trusted_proxy_without_a_usable_header_is_not_the_proxy() {
    let f = proxied_fixture(10).await;
    let mut proxy = Client::connect_from(&f, false, Some("127.0.0.2")).await;
    assert_answer(&proxy.send(get_dns("/dns-query", Some(&f.good))).await);
    let r = proxy
        .send(forwarded(
            get_dns("/dns-query", Some(&f.good)),
            "203.0.113.9:80",
        ))
        .await;
    assert_answer(&r);
    let seen = f.recorder.seen.lock().unwrap();
    for (_, _, ctx) in seen.iter() {
        assert!(ctx.contains("client: 0.0.0.0:0"), "{ctx}");
        assert!(!ctx.contains("127.0.0.2"), "{ctx}");
    }
}

#[tokio::test]
async fn doh_request_context_carries_the_forwarded_client() {
    let f = proxied_fixture(10).await;
    let mut proxy = Client::connect_from(&f, true, Some("127.0.0.2")).await;
    let r = proxy
        .send(forwarded(
            get_dns("/dns-query", Some(&f.good)),
            "203.0.113.9, 127.0.0.2",
        ))
        .await;
    assert_answer(&r);
    let mut direct = Client::connect_from(&f, false, Some("127.0.0.3")).await;
    let r = direct
        .send(forwarded(
            get_dns("/dns-query", Some(&f.good)),
            "203.0.113.7",
        ))
        .await;
    assert_answer(&r);
    let seen = f.recorder.seen.lock().unwrap();
    assert!(seen[0].2.contains("client: 203.0.113.9:0"), "{}", seen[0].2);
    assert!(seen[1].2.contains("client: 127.0.0.3:"), "{}", seen[1].2);
    assert!(!seen[1].2.contains("203.0.113.7"));
}

#[tokio::test]
async fn doh_rejects_malformed_and_oversized_input() {
    let f = fixture(true, 10).await;
    let mut c = Client::connect(&f, false).await;
    let bad = [
        get("/dns-query?dns=!!!", Some(&f.good)),
        get("/dns-query", Some(&f.good)),
        get("/dns-query?dns=AQIDBA==", Some(&f.good)),
        get(
            &format!("/dns-query?dns={}", "A".repeat(60_000)),
            Some(&f.good),
        ),
        get("/dns-query?dns=AAAA", Some(&f.good)), // decodes, but is not a DNS message
        post("/dns-query", Some(&f.good), MSG, vec![]),
        post("/dns-query", Some(&f.good), MSG, vec![0; 65_536]),
    ];
    for req in bad {
        let r = c.send(req).await;
        assert_eq!(r.status, 400);
    }
    assert!(f.recorder.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn doh_method_and_path_mapping() {
    let f = fixture(true, 10).await;
    let mut c = Client::connect(&f, false).await;
    let put = Request::builder()
        .method(Method::PUT)
        .uri("https://dns.test/dns-query")
        .header(header::HOST, "dns.test")
        .body(Full::default())
        .unwrap();
    let r = c.send(put).await;
    assert_eq!(r.status, 405);
    assert_eq!(r.headers[header::ALLOW], "GET, POST");
    assert_eq!(c.send(get("/other", Some(&f.good))).await.status, 404);
}

#[tokio::test]
async fn doh_auth_failures_throttled_without_leaking_token_existence() {
    let f = fixture(true, 3).await;
    let mut c = Client::connect(&f, false).await;
    // Well-formed, but no such token id. Change a char in the low end of the id: the leading
    // chars are not random (ids are 53 bits), so overwriting them can be a no-op.
    let mut unknown = f.good.clone();
    let flipped = if &unknown[14..15] == "A" { "B" } else { "A" };
    unknown.replace_range(14..15, flipped);
    assert_ne!(unknown, f.good);
    let mut bodies = Vec::new();
    for t in [&unknown, "garbage", &format!("{}x", f.good)] {
        let r = c.send(get_dns("/dns-query", Some(t))).await;
        assert_eq!(r.status, 401);
        bodies.push(r.body);
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]));
    // Blocked now: even a valid token gets 429 and the decision never looks at the token.
    let r = c.send(get_dns("/dns-query", Some(&f.good))).await;
    assert_eq!(r.status, 429);
    assert!(r.headers.contains_key(header::RETRY_AFTER));
    assert!(f.recorder.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn doh_throttle_is_per_client_address() {
    let f = fixture(true, 2).await;
    let mut a = Client::connect_from(&f, false, Some("127.0.0.2")).await;
    for _ in 0..2 {
        assert_eq!(
            a.send(get_dns("/dns-query", Some("garbage"))).await.status,
            401
        );
    }
    assert_eq!(
        a.send(get_dns("/dns-query", Some(&f.good))).await.status,
        429
    );
    // Another address is not locked out by the first one's failures.
    let mut b = Client::connect_from(&f, false, Some("127.0.0.3")).await;
    assert_eq!(
        b.send(get_dns("/dns-query", Some(&f.good))).await.status,
        200
    );
}

#[tokio::test]
async fn doh_throttle_saturation_keeps_blocked_ip_blocked() {
    // Room for 16 keys; 120 other clients fail once each and fill every shard.
    let f = fixture_tracking(true, 2, 16).await;
    let mut attacker = Client::connect_from(&f, false, Some("127.0.0.2")).await;
    for _ in 0..2 {
        assert_eq!(
            attacker
                .send(get_dns("/dns-query", Some("garbage")))
                .await
                .status,
            401
        );
    }
    for host in 10..130 {
        let mut c = Client::connect_from(&f, false, Some(&format!("127.0.0.{host}"))).await;
        c.send(get_dns("/dns-query", Some("garbage"))).await;
    }
    assert_eq!(
        attacker
            .send(get_dns("/dns-query", Some(&f.good)))
            .await
            .status,
        429,
        "a full table must not forget a blocked client"
    );
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

#[tokio::test]
async fn doh_path_token_redacted_in_logs_and_querylog() {
    redaction_scenario().await;
}

/// Tokens are random, so a leak check that depends on the token's bytes must hold for all of
/// them: repeat with fresh tokens (both path and header forms run in every round).
#[tokio::test]
async fn doh_token_redaction_holds_for_many_tokens() {
    for _ in 0..50 {
        redaction_scenario().await;
    }
}

async fn redaction_scenario() {
    let capture = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish(),
    );
    let f = fixture(true, 10).await;
    let secret = f.good.clone();
    let wrong = format!("{}x", f.good);
    let mut replies = Vec::new();
    for h2 in [false, true] {
        let mut c = Client::connect(&f, h2).await;
        replies.push(c.send(get_dns(&format!("/dns-query/{secret}"), None)).await);
        replies.push(c.send(get_dns("/dns-query", Some(&secret))).await);
        replies.push(c.send(get_dns(&format!("/dns-query/{wrong}"), None)).await);
        replies.push(c.send(get_dns("/dns-query", Some(&wrong))).await);
        replies.push(
            c.send(get_dns(&format!("/dns-query/{}", f.no_scope), None))
                .await,
        );
        replies.push(c.send(get(&format!("/dns-query/{secret}"), None)).await);
    }
    f.server.shutdown().await;
    // The secret is `dnsy_<id>_<base64url secret>` and the base64url part may itself contain
    // `_`, so split at the second underscore only: a shorter fragment would match ordinary log
    // text by chance.
    let secret_part = secret.splitn(3, '_').nth(2).unwrap();
    assert!(
        secret_part.len() >= 40,
        "secret fragment too short to be meaningful"
    );
    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.contains(&secret) && !logs.contains(secret.split('_').nth(1).unwrap()));
    assert!(!logs.is_empty(), "the test must actually capture logs");
    assert!(!logs.contains(secret_part) && !logs.contains(&f.no_scope));
    for r in &replies {
        let text = format!("{:?}{}", r.headers, String::from_utf8_lossy(&r.body));
        assert!(!text.contains(secret_part), "token echoed in a response");
    }
    // Everything the engine (and so the query log) is given.
    let seen = f.recorder.seen.lock().unwrap();
    assert_eq!(seen.len(), 4);
    for (_, principal, text) in seen.iter() {
        assert!(principal.is_some());
        assert!(!text.contains(secret_part), "token reached the engine");
    }
}
