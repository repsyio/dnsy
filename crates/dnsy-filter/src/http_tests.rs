//! Tests of the hand-written HTTP client: URL splitting, redirect resolution, dialling, TLS
//! verification and the SSRF re-check on redirects.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::{Method, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::http::{self, Scheme, Target};
use crate::{FetchError, Fetched, Fetcher, Location, MAX_LIST_BYTES};

/// A raw server answering every connection with `response`; counts connections and keeps the
/// last request head.
struct Raw {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
    last: Arc<Mutex<String>>,
}

async fn raw(response: String) -> Raw {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let last = Arc::new(Mutex::new(String::new()));
    let (count, seen) = (Arc::clone(&accepted), Arc::clone(&last));
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let response = response.clone();
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                *seen.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into_owned();
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Raw {
        addr,
        accepted,
        last,
    }
}

fn ok_body(body: &str, extra: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// An address on which nothing listens.
async fn closed_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

#[test]
fn target_parse_table() {
    let t = Target::parse("HTTPS://Lists.Example.COM/a/b.txt?x=1&y=%41#frag").unwrap();
    assert_eq!(t.scheme(), Scheme::Https);
    assert_eq!(t.host_str(), "lists.example.com");
    assert_eq!(t.port(), 443);
    assert_eq!(t.path_and_query(), "/a/b.txt?x=1&y=%41");
    assert_eq!(t.ip(), None);

    let t = Target::parse("http://example.com").unwrap();
    assert_eq!((t.port(), t.path_and_query()), (80, "/"));
    let t = Target::parse("http://example.com?q").unwrap();
    assert_eq!(t.path_and_query(), "/?q");
    let t = Target::parse("http://example.com:8080/x").unwrap();
    assert_eq!(t.port(), 8080);
    let t = Target::parse("http://example.com:/x").unwrap();
    assert_eq!(t.port(), 80);
    let t = Target::parse("http://example.com./x").unwrap();
    assert_eq!(t.host_str(), "example.com.");

    let t = Target::parse("http://[2001:DB8::1]:8443/x").unwrap();
    assert_eq!(t.host_str(), "[2001:db8::1]");
    assert_eq!(t.ip(), Some(IpAddr::V6("2001:db8::1".parse().unwrap())));
    assert_eq!(t.port(), 8443);
    let t = Target::parse("https://[::1]").unwrap();
    assert_eq!(
        (t.ip(), t.port()),
        (Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), 443)
    );
    let t = Target::parse("http://127.0.0.1:81/").unwrap();
    assert_eq!(t.ip(), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    for bad in [
        "https://u:p@example.com/",
        "https://user@example.com/",
        "https://bücher.example/",
        "https://example.com/ü",
        "http://exa mple.com/",
        "http://example.com/a\r\nX: y",
        "http:///x",
        "http://:80/x",
        "http://.example/",
        "http://exa%6dple.com/",
        "http://example.com:99999/",
        "http://example.com:8o/",
        "http://[::1/",
        "http://[::1]x/",
        "http://[nope]/",
        "http://0x7f.1/",
        "http://2130706433/",
        "http://127.1/",
        "http://010.0.0.1/",
        "http://1.2.3.256/",
        "example.com/x",
    ] {
        assert!(
            matches!(Target::parse(bad), Err(FetchError::InvalidLocation)),
            "{bad}"
        );
    }
    assert!(matches!(
        Target::parse("ftp://example.com/"),
        Err(FetchError::UnsupportedScheme)
    ));
    assert!(matches!(
        Location::parse("https://u:p@example.com/"),
        Err(FetchError::InvalidLocation)
    ));
    assert!(matches!(
        Location::parse("HTTP://example.com/l"),
        Ok(Location::Url(_))
    ));
}

#[test]
fn location_resolution_table() {
    let base = Target::parse("https://a.example:8443/dir/list?x").unwrap();
    let next = base.resolve_location("https://b.example/other").unwrap();
    assert_eq!(
        (next.host_str(), next.port(), next.path_and_query()),
        ("b.example", 443, "/other")
    );
    let next = base.resolve_location("/moved?y=1#f").unwrap();
    assert_eq!(
        (
            next.scheme(),
            next.host_str(),
            next.port(),
            next.path_and_query()
        ),
        (Scheme::Https, "a.example", 8443, "/moved?y=1")
    );
    let plain = Target::parse("http://a.example/").unwrap();
    assert_eq!(
        plain
            .resolve_location("HTTPS://b.example/")
            .unwrap()
            .scheme(),
        Scheme::Https
    );
    for bad in [
        "relative/path",
        "../up",
        "//b.example/x",
        "http://b.example/",
        "ftp://example.com/x",
        "https:///x",
        "https://u@b.example/",
        "/bad path",
        "",
    ] {
        assert!(
            matches!(base.resolve_location(bad), Err(FetchError::BadRedirect)),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn oversized_validator_headers_are_dropped() {
    let etag = format!("\"{}\"", "e".repeat(600));
    let srv = raw(ok_body(
        "ads.example\n",
        &format!("ETag: {etag}\r\nLast-Modified: Tue, 20 Oct 2026 10:00:00 GMT\r\n"),
    ))
    .await;
    let got = Fetcher::default()
        .fetch(&format!("http://{}/l", srv.addr), true, None)
        .await
        .unwrap();
    let Fetched::Body { bytes, validators } = got else {
        panic!("expected a body");
    };
    assert_eq!(bytes, b"ads.example\n");
    assert_eq!(validators.etag, None);
    assert_eq!(
        validators.last_modified.as_deref(),
        Some("Tue, 20 Oct 2026 10:00:00 GMT")
    );
    let head = srv.last.lock().unwrap().clone();
    assert!(head.starts_with("GET /l HTTP/1.1\r\n"), "{head}");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains(&format!("host: {}\r\n", srv.addr)), "{head}");
    assert!(lower.contains("user-agent: dnsy\r\n"), "{head}");
    assert!(lower.contains("connection: close\r\n"), "{head}");
    assert!(!lower.contains("accept-encoding"), "{head}");
}

#[tokio::test]
async fn connect_uses_only_the_checked_addresses() {
    let live = raw(ok_body("hello", "")).await;
    let decoy = raw(ok_body("decoy", "")).await;
    let target = Target::parse(&format!("http://{}/x", decoy.addr)).unwrap();
    let tls = http::tls_config(http::webpki_roots());
    let addrs = [closed_addr().await, live.addr];
    let mut ex = http::send(&tls, &addrs, Method::GET, &target, &[])
        .await
        .unwrap();
    let body = http::read_body(&mut ex.response, 1024).await.unwrap();
    assert_eq!(body, b"hello");
    assert_eq!(live.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(decoy.accepted.load(Ordering::SeqCst), 0);
    // The Host header still names the target, not the dialled address.
    let head = live.last.lock().unwrap().to_ascii_lowercase();
    assert!(
        head.contains(&format!("host: {}\r\n", decoy.addr)),
        "{head}"
    );

    let none = [closed_addr().await];
    assert!(matches!(
        http::send(&tls, &none, Method::GET, &target, &[]).await,
        Err(FetchError::Http)
    ));
    assert_eq!(decoy.accepted.load(Ordering::SeqCst), 0);
}

/// A TLS server for `names` answering one fixed response; returns its address and the CA.
async fn tls_server(names: Vec<String>) -> (SocketAddr, rustls::RootCertStore) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(names)
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let _ = tls
                    .write_all(ok_body("secure.example\n", "").as_bytes())
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (addr, roots)
}

#[tokio::test]
async fn https_fetch_verifies_the_certificate() {
    let (addr, roots) = tls_server(vec!["127.0.0.1".into(), "localhost".into()]).await;
    let trusting = Fetcher::with_roots(roots.clone(), MAX_LIST_BYTES, Duration::from_secs(5));
    for url in [
        format!("https://127.0.0.1:{}/l", addr.port()),
        format!("https://localhost:{}/l", addr.port()),
    ] {
        let got = trusting.fetch(&url, true, None).await.unwrap();
        assert!(
            matches!(&got, Fetched::Body { bytes, .. } if bytes == b"secure.example\n"),
            "{url}"
        );
    }

    // Same server, unknown CA: the webpki roots do not include it.
    let err = Fetcher::default()
        .fetch(&format!("https://127.0.0.1:{}/l", addr.port()), true, None)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::Http), "{err}");

    // Trusted CA, but the certificate does not name the host asked for.
    let (other, roots) = tls_server(vec!["lists.example".into()]).await;
    let fetcher = Fetcher::with_roots(roots, MAX_LIST_BYTES, Duration::from_secs(5));
    for url in [
        format!("https://127.0.0.1:{}/l", other.port()),
        format!("https://localhost:{}/l", other.port()),
    ] {
        let err = fetcher.fetch(&url, true, None).await.unwrap_err();
        assert!(matches!(err, FetchError::Http), "{url}: {err}");
    }
}

#[tokio::test]
async fn redirect_target_is_rechecked_against_the_ssrf_policy() {
    let local = raw(ok_body("internal.example\n", "")).await;
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://{}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        local.addr
    );
    let front = raw(redirect).await;
    // 192.0.2.0/24 is not public; 1.1.1.1 is. The first hop passes the policy and is dialled
    // to the local server standing in for it; the redirect to 127.0.0.1 must be refused.
    let fetcher = Fetcher::default().dial_instead(front.addr);
    let err = fetcher
        .fetch("http://1.1.1.1/list", false, None)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::PrivateTarget), "{err}");
    assert_eq!(front.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(local.accepted.load(Ordering::SeqCst), 0);
    // The first hop itself is checked before dialling.
    let err = fetcher
        .fetch("http://192.0.2.1/list", false, None)
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::PrivateTarget), "{err}");
    assert_eq!(front.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn request_returns_status_and_caps_the_body() {
    let srv = raw(
        "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 4\r\nConnection: close\r\n\r\nmove"
            .to_owned(),
    )
    .await;
    let url = format!("http://{}/api/v1/cache", srv.addr);
    let (status, body) = http::request(
        Method::DELETE,
        &url,
        &[(hyper::header::AUTHORIZATION, "Bearer t")],
        1024,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!((status, body.as_slice()), (StatusCode::FOUND, &b"move"[..]));
    let head = srv.last.lock().unwrap().clone();
    assert!(
        head.starts_with("DELETE /api/v1/cache HTTP/1.1\r\n"),
        "{head}"
    );
    assert!(
        head.to_ascii_lowercase()
            .contains("authorization: bearer t\r\n")
    );
    assert_eq!(srv.accepted.load(Ordering::SeqCst), 1);

    let err = http::request(Method::GET, &url, &[], 3, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(matches!(err, FetchError::TooLarge), "{err}");
    let err = http::request(
        Method::GET,
        "http://bad host/",
        &[],
        3,
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, FetchError::InvalidLocation), "{err}");
    let err = http::request(
        Method::GET,
        &format!("http://{}/", closed_addr().await),
        &[],
        3,
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, FetchError::Http), "{err}");
}
