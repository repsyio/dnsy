use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use dnsy_proto::Name;
use dnsy_store::Store;

use crate::{
    BlockMode, Clock, FetchError, Fetcher, FilterError, FilterLimits, ListFormat, ListManager,
    NewSource, RefreshError, RefreshOutcome, RuleKind, SourceStore, Verdict, is_public,
};

#[derive(Clone)]
struct Fixture {
    body: Arc<Mutex<String>>,
    status: Arc<AtomicU16>,
    hits: Arc<AtomicUsize>,
    conditional_hits: Arc<AtomicUsize>,
}

async fn list(State(fx): State<Fixture>, headers: HeaderMap) -> Response {
    fx.hits.fetch_add(1, Ordering::SeqCst);
    let status = fx.status.load(Ordering::SeqCst);
    if status != 200 {
        return StatusCode::from_u16(status).unwrap().into_response();
    }
    let body = fx.body.lock().unwrap().clone();
    let etag = format!("\"{}\"", body.len());
    if headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v == etag.as_str())
    {
        fx.conditional_hits.fetch_add(1, Ordering::SeqCst);
        return StatusCode::NOT_MODIFIED.into_response();
    }
    (
        [
            (header::ETAG, etag),
            (
                header::LAST_MODIFIED,
                "Mon, 01 Jan 2024 00:00:00 GMT".to_owned(),
            ),
        ],
        body,
    )
        .into_response()
}

async fn slow() -> &'static str {
    tokio::time::sleep(Duration::from_secs(5)).await;
    "late.example\n"
}

async fn redirect_loop() -> Response {
    (StatusCode::FOUND, [(header::LOCATION, "/loop")]).into_response()
}

async fn redirect_to_list() -> Response {
    (StatusCode::FOUND, [(header::LOCATION, "/list")]).into_response()
}

async fn redirect_to_ftp() -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, "ftp://example.com/x")],
    )
        .into_response()
}

/// A raw HTTP/1.1 server answering every request with a chunked body (no Content-Length).
async fn chunked_server() -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                    .await;
                for _ in 0..50 {
                    let mut chunk = b"64\r\n".to_vec();
                    chunk.extend_from_slice(&[b'a'; 100]);
                    chunk.extend_from_slice(b"\r\n");
                    if sock.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
                let _ = sock.write_all(b"0\r\n\r\n").await;
            });
        }
    });
    addr
}

struct Server {
    fx: Fixture,
    addr: SocketAddr,
}

impl Server {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
    fn set_body(&self, b: &str) {
        *self.fx.body.lock().unwrap() = b.to_owned();
    }
}

async fn server() -> Server {
    let fx = Fixture {
        body: Arc::new(Mutex::new("0.0.0.0 ads.example\n".to_owned())),
        status: Arc::new(AtomicU16::new(200)),
        hits: Arc::new(AtomicUsize::new(0)),
        conditional_hits: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/list", get(list))
        .route("/slow", get(slow))
        .route("/loop", get(redirect_loop))
        .route("/hop", get(redirect_to_list))
        .route("/ftp", get(redirect_to_ftp))
        .with_state(fx.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server { fx, addr }
}

struct ManualClock(AtomicI64);

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
    fn sleep(&self, _: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(std::future::ready(()))
    }
}

struct Env {
    sources: SourceStore,
    manager: ListManager,
    clock: Arc<ManualClock>,
    dir: tempfile::TempDir,
}

fn env_with(fetcher: Fetcher) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let sources = SourceStore::new(Store::open(&dir.path().join("t.db")).unwrap());
    let clock = Arc::new(ManualClock(AtomicI64::new(1_000_000)));
    let manager = ListManager::new(
        sources.clone(),
        BlockMode::NullIp,
        FilterLimits::default(),
        fetcher,
        clock.clone(),
    );
    Env {
        sources,
        manager,
        clock,
        dir,
    }
}

fn env() -> Env {
    env_with(Fetcher::default())
}

fn new_source(location: &str, interval_secs: u64, allow_private: bool) -> NewSource {
    NewSource {
        name: format!("src-{location}"),
        location: location.to_owned(),
        format: ListFormat::Auto,
        enabled: true,
        interval_secs,
        allow_private,
    }
}

fn blocked(m: &ListManager, n: &str) -> bool {
    matches!(
        m.current().check(&Name::from_ascii(n).unwrap()),
        Verdict::Block { .. }
    )
}

#[tokio::test]
async fn conditional_fetch_304_keeps_list() {
    let srv = server().await;
    let e = env();
    let id = e
        .sources
        .add(new_source(&srv.url("/list"), 3600, true))
        .await
        .unwrap();
    assert_eq!(
        e.manager.refresh_source(id).await.unwrap(),
        RefreshOutcome::Updated { entries: 1 }
    );
    assert!(blocked(&e.manager, "ads.example"));
    assert_eq!(
        e.manager.refresh_source(id).await.unwrap(),
        RefreshOutcome::NotModified
    );
    assert_eq!(srv.fx.conditional_hits.load(Ordering::SeqCst), 1);
    assert!(blocked(&e.manager, "sub.ads.example"));
    let s = &e.sources.list().await.unwrap()[0];
    assert_eq!(s.last_status.as_deref(), Some("not modified"));
    assert_eq!(s.etag.as_deref(), Some("\"20\""));
    assert_eq!(
        s.last_modified.as_deref(),
        Some("Mon, 01 Jan 2024 00:00:00 GMT")
    );
    assert_eq!(s.entries, 1);
}

#[tokio::test]
async fn changed_list_replaces_previous() {
    let srv = server().await;
    let e = env();
    let id = e
        .sources
        .add(new_source(&srv.url("/list"), 3600, true))
        .await
        .unwrap();
    e.manager.refresh_source(id).await.unwrap();
    srv.set_body("0.0.0.0 other.example\n0.0.0.0 more.example\n");
    assert_eq!(
        e.manager.refresh_source(id).await.unwrap(),
        RefreshOutcome::Updated { entries: 2 }
    );
    assert!(!blocked(&e.manager, "ads.example"));
    assert!(blocked(&e.manager, "more.example"));
}

#[tokio::test]
async fn failed_fetch_keeps_previous() {
    let srv = server().await;
    let e = env();
    let id = e
        .sources
        .add(new_source(&srv.url("/list"), 3600, true))
        .await
        .unwrap();
    e.manager.refresh_source(id).await.unwrap();

    srv.fx.status.store(500, Ordering::SeqCst);
    let err = e.manager.refresh_source(id).await.unwrap_err();
    assert!(matches!(err, RefreshError::Fetch(FetchError::Status(500))));
    assert!(blocked(&e.manager, "ads.example"));
    let status = e.sources.list().await.unwrap()[0]
        .last_status
        .clone()
        .unwrap();
    assert!(status.starts_with("error:"), "{status}");

    srv.fx.status.store(200, Ordering::SeqCst);
    srv.set_body("<html>maintenance page, not a list!</html>\n");
    let err = e.manager.refresh_source(id).await.unwrap_err();
    assert!(matches!(err, RefreshError::Malformed));
    assert!(blocked(&e.manager, "ads.example"));
}

#[tokio::test]
async fn size_cap_enforced() {
    let srv = server().await;
    let e = env_with(Fetcher::new(100, Duration::from_secs(30)));
    let fetcher = Fetcher::new(100, Duration::from_secs(30));
    // Content-Length known up front.
    srv.set_body(&"a.example\n".repeat(20));
    let id = e
        .sources
        .add(new_source(&srv.url("/list"), 3600, true))
        .await
        .unwrap();
    let err = e.manager.refresh_source(id).await.unwrap_err();
    assert!(
        matches!(err, RefreshError::Fetch(FetchError::TooLarge)),
        "{err}"
    );
    assert!(e.manager.current().is_empty());
    // Chunked body without Content-Length.
    let err = fetcher
        .fetch(&format!("http://{}/", chunked_server().await), true, None)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::TooLarge), "{err}");
    // Files are capped too.
    let f = e.dir.path().join("big.txt");
    std::fs::write(&f, "a.example\n".repeat(20)).unwrap();
    let err = fetcher
        .fetch(f.to_str().unwrap(), false, None)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::TooLarge));
}

#[tokio::test]
async fn private_target_refused() {
    let srv = server().await;
    let fetcher = Fetcher::default();
    let url = srv.url("/list");
    let err = fetcher.fetch(&url, false, None).await.unwrap_err();
    assert!(matches!(err, FetchError::PrivateTarget), "{err}");
    let by_name = format!("http://localhost:{}/list", srv.addr.port());
    let err = fetcher.fetch(&by_name, false, None).await.unwrap_err();
    assert!(matches!(err, FetchError::PrivateTarget), "{err}");
    assert_eq!(srv.fx.hits.load(Ordering::SeqCst), 0);
    // Explicitly allowed, it works.
    assert!(matches!(
        fetcher.fetch(&url, true, None).await.unwrap(),
        crate::Fetched::Body { .. }
    ));
}

#[test]
fn public_address_policy() {
    let no = [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "100.64.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "240.0.0.1",
        "198.18.0.1",
        "192.0.2.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd12::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::1",
        "2001:db8::1",
        "::127.0.0.1",
    ];
    for ip in no {
        assert!(!is_public(ip.parse::<IpAddr>().unwrap()), "{ip}");
    }
    for ip in [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
        "::ffff:8.8.8.8",
    ] {
        assert!(is_public(ip.parse::<IpAddr>().unwrap()), "{ip}");
    }
}

#[tokio::test]
async fn schemes_and_locations() {
    let fetcher = Fetcher::default();
    for bad in [
        "ftp://example.com/x",
        "file:///etc/passwd",
        "gopher://x/",
        "https://u:p@example.com/",
    ] {
        let err = fetcher.fetch(bad, true, None).await.unwrap_err();
        assert!(
            matches!(
                err,
                FetchError::UnsupportedScheme | FetchError::InvalidLocation
            ),
            "{bad}: {err}"
        );
    }
    let e = env();
    let err = e
        .sources
        .add(new_source("ftp://example.com/x", 60, false))
        .await
        .unwrap_err();
    assert!(matches!(err, FilterError::Invalid(_)));
}

#[tokio::test]
async fn redirects_followed_and_limited() {
    let srv = server().await;
    let fetcher = Fetcher::default();
    let ok = fetcher.fetch(&srv.url("/hop"), true, None).await.unwrap();
    assert!(matches!(ok, crate::Fetched::Body { .. }));
    let err = fetcher
        .fetch(&srv.url("/loop"), true, None)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::TooManyRedirects), "{err}");
    let err = fetcher
        .fetch(&srv.url("/ftp"), true, None)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::BadRedirect), "{err}");
}

#[tokio::test]
async fn http_errors_and_timeout() {
    let srv = server().await;
    let fetcher = Fetcher::new(1024, Duration::from_millis(300));
    let err = fetcher
        .fetch(&srv.url("/slow"), true, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::Timeout | FetchError::Http),
        "{err}"
    );
    let err = fetcher
        .fetch(&srv.url("/missing"), true, None)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Status(404)), "{err}");
}

#[tokio::test]
async fn schedule_refreshes() {
    let srv = server().await;
    let e = env();
    e.sources
        .add(new_source(&srv.url("/list"), 100, true))
        .await
        .unwrap();

    // Never fetched: due immediately.
    let wait = e.manager.tick().await;
    assert_eq!(srv.fx.hits.load(Ordering::SeqCst), 1);
    assert!(blocked(&e.manager, "ads.example"));
    assert!((1..=60).contains(&wait.as_secs()), "{wait:?}");

    // Not due yet: no request.
    e.clock.0.fetch_add(50, Ordering::SeqCst);
    e.manager.tick().await;
    assert_eq!(srv.fx.hits.load(Ordering::SeqCst), 1);

    // Past interval plus the maximum jitter (10%): refreshed and picks up the new content.
    srv.set_body("0.0.0.0 new.example\n0.0.0.0 x.example\n");
    e.clock.0.fetch_add(61, Ordering::SeqCst);
    e.manager.tick().await;
    assert_eq!(srv.fx.hits.load(Ordering::SeqCst), 2);
    assert!(blocked(&e.manager, "new.example"));
    assert!(!blocked(&e.manager, "ads.example"));
}

#[tokio::test]
async fn failed_refresh_retries_sooner_than_interval() {
    let srv = server().await;
    srv.fx.status.store(500, Ordering::SeqCst);
    let e = env();
    e.sources
        .add(new_source(&srv.url("/list"), 86_400, true))
        .await
        .unwrap();
    e.manager.tick().await;
    assert_eq!(srv.fx.hits.load(Ordering::SeqCst), 1);
    srv.fx.status.store(200, Ordering::SeqCst);
    e.clock.0.fetch_add(331, Ordering::SeqCst);
    e.manager.tick().await;
    assert_eq!(srv.fx.hits.load(Ordering::SeqCst), 2);
    assert!(blocked(&e.manager, "ads.example"));
}

#[tokio::test]
async fn file_source_custom_rules_and_disable() {
    let e = env();
    let path = e.dir.path().join("list.txt");
    std::fs::write(&path, "||ads.example^\n||keep.example^\n").unwrap();
    let a = e
        .sources
        .add(new_source(path.to_str().unwrap(), 60, false))
        .await
        .unwrap();
    e.sources
        .add_custom_rule(RuleKind::Allow, "keep.example")
        .await
        .unwrap();
    e.sources
        .add_custom_rule(RuleKind::Block, "custom.example")
        .await
        .unwrap();
    e.sources
        .add_custom_rule(RuleKind::Block, "bad domain!")
        .await
        .unwrap();
    assert!(matches!(
        e.sources
            .add_custom_rule(RuleKind::Block, "custom.example")
            .await,
        Err(FilterError::Duplicate)
    ));
    e.manager.refresh_source(a).await.unwrap();
    assert!(blocked(&e.manager, "ads.example"));
    assert!(blocked(&e.manager, "custom.example"));
    assert!(!blocked(&e.manager, "keep.example"));
    assert_eq!(e.sources.custom_rules().await.unwrap().len(), 3);

    e.sources.set_enabled(a, false).await.unwrap();
    e.manager.tick().await;
    assert!(!blocked(&e.manager, "ads.example"));
    assert!(blocked(&e.manager, "custom.example"));

    e.sources.set_enabled(a, true).await.unwrap();
    e.manager.tick().await;
    assert!(blocked(&e.manager, "ads.example"));
    e.manager.reload().await.unwrap();
    assert!(blocked(&e.manager, "ads.example"));

    assert!(matches!(
        e.manager.refresh_source(999).await,
        Err(RefreshError::NotFound)
    ));
    e.sources.delete(a).await.unwrap();
    assert!(matches!(
        e.sources.delete(a).await,
        Err(FilterError::NotFound)
    ));
    e.manager.tick().await;
    assert!(!blocked(&e.manager, "ads.example"));
}

#[tokio::test]
async fn seed_only_on_first_start() {
    let e = env();
    let locs = vec![
        "https://example.com/a.txt".to_owned(),
        "/var/lib/dnsy/b.txt".to_owned(),
    ];
    e.sources.seed(&locs, 3600).await.unwrap();
    e.sources
        .seed(&["https://example.com/c.txt".to_owned()], 3600)
        .await
        .unwrap();
    let got = e.sources.list().await.unwrap();
    assert_eq!(got.len(), 2);
    assert!(
        got.iter()
            .all(|s| s.enabled && s.interval_secs == 3600 && !s.allow_private)
    );
    assert!(matches!(
        e.sources
            .add(new_source("https://example.com/a.txt", 60, false))
            .await,
        Err(FilterError::Duplicate)
    ));
    assert!(matches!(
        e.sources
            .add(NewSource {
                interval_secs: 0,
                ..new_source("x", 0, false)
            })
            .await,
        Err(FilterError::Invalid(_))
    ));
}
