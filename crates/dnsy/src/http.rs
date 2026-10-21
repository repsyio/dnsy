//! Serves the API router over plain HTTP or TLS with graceful shutdown.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::response::IntoResponse as _;
use hyper::StatusCode;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;

use crate::{Error, Result};

/// How long open API connections (for example a live-tail stream) get after shutdown starts.
const DRAIN: Duration = Duration::from_secs(2);

/// TLS acceptor for the API from PEM files (read once at start).
pub(crate) fn acceptor(cert: &Path, key: &Path) -> Result<TlsAcceptor> {
    let chain = CertificateDer::pem_file_iter(cert)
        .map_err(|e| Error::msg(format!("api.tls_cert {}: {e}", cert.display())))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::msg(format!("api.tls_cert {}: {e}", cert.display())))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| Error::msg(format!("api.tls_key {}: {e}", key.display())))?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Path of the live-tail stream; it is open-ended by design and exempt from the request timeout.
const STREAM_PATH: &str = "/api/v1/querylog/stream";

/// Admission limits of the API listener.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpLimits {
    /// Concurrent connections; further ones are closed at accept.
    pub max_conns: usize,
    /// Time for a client to send its first bytes (TLS handshake included) and each request head.
    pub header_read: Duration,
    /// Time for a handler to produce a response (headers), except on [`STREAM_PATH`].
    pub request: Duration,
}

impl HttpLimits {
    pub(crate) fn new(max_conns: usize) -> Self {
        Self {
            max_conns,
            header_read: Duration::from_secs(30),
            request: Duration::from_secs(30),
        }
    }
}

/// Reports whether the peer has sent any byte yet (hyper's protocol detection waits for the first
/// bytes without a timer of its own).
struct Watched<T> {
    inner: T,
    seen: Arc<AtomicBool>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Watched<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.seen.store(true, Ordering::Relaxed);
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Watched<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Accepts connections until `shutdown` flips, then lets open ones finish for [`DRAIN`].
pub(crate) async fn serve(
    listener: TcpListener,
    app: Router,
    tls: Option<TlsAcceptor>,
    mut shutdown: watch::Receiver<bool>,
    limits: HttpLimits,
) {
    let slots = Arc::new(Semaphore::new(limits.max_conns));
    let mut conns = JoinSet::new();
    loop {
        while conns.try_join_next().is_some() {}
        let (stream, peer) = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(error = %e, "api accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!(%peer, "api connection limit reached; closing");
            continue;
        };
        let app = app.clone();
        let tls = tls.clone();
        let mut stop = shutdown.clone();
        conns.spawn(async move {
            let io: Box<dyn Io> = match tls {
                Some(acceptor) => {
                    match timeout(limits.header_read, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => Box::new(tls),
                        Ok(Err(e)) => {
                            tracing::debug!(%peer, error = %e, "api tls handshake failed");
                            return;
                        }
                        Err(_) => {
                            tracing::debug!(%peer, "api tls handshake timed out");
                            return;
                        }
                    }
                }
                None => Box::new(stream),
            };
            let seen = Arc::new(AtomicBool::new(false));
            let io = Watched {
                inner: io,
                seen: Arc::clone(&seen),
            };
            // Handlers read the peer address from `ConnectInfo` (login throttling is keyed on it).
            let service = service_fn(move |req: hyper::Request<Incoming>| {
                let mut req = req.map(axum::body::Body::new);
                req.extensions_mut().insert(ConnectInfo(peer));
                let exempt = req.uri().path() == STREAM_PATH;
                let call = app.clone().oneshot(req);
                async move {
                    if exempt {
                        return call.await;
                    }
                    match timeout(limits.request, call).await {
                        Ok(response) => response,
                        Err(_) => Ok(StatusCode::REQUEST_TIMEOUT.into_response()),
                    }
                }
            });
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_read);
            builder
                .http2()
                .timer(TokioTimer::new())
                .max_concurrent_streams(100)
                .keep_alive_interval(limits.header_read)
                .keep_alive_timeout(limits.header_read);
            let conn = builder.serve_connection(TokioIo::new(io), service);
            tokio::pin!(conn);
            let first_bytes = tokio::time::sleep(limits.header_read);
            tokio::pin!(first_bytes);
            let mut waiting = true;
            let result = loop {
                tokio::select! {
                    r = conn.as_mut() => break r,
                    () = &mut first_bytes, if waiting => {
                        if !seen.load(Ordering::Relaxed) {
                            tracing::debug!(%peer, "api connection sent nothing; closing");
                            break Ok(());
                        }
                        waiting = false;
                    }
                    _ = stop.changed() => {
                        conn.as_mut().graceful_shutdown();
                        break conn.await;
                    }
                }
            };
            if let Err(e) = result {
                tracing::debug!(%peer, error = %e, "api connection ended");
            }
            drop(permit);
        });
    }
    let _ = tokio::time::timeout(DRAIN, async { while conns.join_next().await.is_some() {} }).await;
}

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use std::time::Duration;

    use dnsy_api::{ApiConfig, ApiState, router};
    use dnsy_core::Role;
    use serde_json::json;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    const PW: &str = "correct horse battery";

    struct Server {
        addr: SocketAddr,
        store: dnsy_store::Store,
        _stop: watch::Sender<bool>,
        _dir: tempfile::TempDir,
    }

    async fn server() -> Server {
        server_with(HttpLimits::new(256)).await
    }

    async fn server_with(limits: HttpLimits) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
        let state = ApiState::new(store.clone());
        state.users.create("admin", PW, Role::Admin).await.unwrap();
        let app = router(
            state.clone(),
            ApiConfig {
                tls: false,
                secure_cookies: None,
            },
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        tokio::spawn(serve(listener, app, None, rx, limits));
        Server {
            addr,
            store,
            _stop: stop,
            _dir: dir,
        }
    }

    /// Posts a login from the given loopback source address; returns status and headers text.
    async fn login(s: &Server, from: &str, password: &str) -> (u16, String) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket
            .bind(SocketAddr::new(from.parse().unwrap(), 0))
            .unwrap();
        let mut stream = socket.connect(s.addr).await.unwrap();
        let body = json!({"username": "admin", "password": password}).to_string();
        let request = format!(
            "POST /api/v1/auth/login HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\
             content-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.unwrap();
        let status = raw.split(' ').nth(1).unwrap().parse().unwrap();
        (status, raw.to_ascii_lowercase())
    }

    async fn recorded_ips(s: &Server) -> Vec<String> {
        s.store
            .read(|c| {
                let mut stmt = c.prepare("SELECT DISTINCT ip FROM login_attempts")?;
                Ok(stmt
                    .query_map([], |r| r.get(0))?
                    .collect::<std::result::Result<Vec<String>, _>>()?)
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn login_attempts_record_peer_ip_through_real_listener() {
        let s = server().await;
        assert_eq!(login(&s, "127.0.0.2", "wrong-password").await.0, 401);
        let ips = recorded_ips(&s).await;
        assert_eq!(ips, vec!["127.0.0.2".to_owned()]);
    }

    #[tokio::test]
    async fn locked_out_address_does_not_lock_out_another_address() {
        let s = server().await;
        for _ in 0..5 {
            assert_eq!(login(&s, "127.0.0.2", "wrong-password").await.0, 401);
        }
        let (status, raw) = login(&s, "127.0.0.2", PW).await;
        assert_eq!(status, 429);
        assert!(raw.contains("retry-after:"));
        // The attacker's address is locked; the administrator elsewhere is not.
        assert_eq!(login(&s, "127.0.0.3", PW).await.0, 200);
        assert!(!recorded_ips(&s).await.contains(&"0.0.0.0".to_owned()));
    }

    /// Opens a connection and sends `head` without ending the request.
    async fn open_with(addr: SocketAddr, head: &str) -> tokio::net::TcpStream {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        stream
    }

    async fn healthz(addr: SocketAddr) -> String {
        let mut stream = open_with(
            addr,
            "GET /healthz HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n",
        )
        .await;
        let mut raw = String::new();
        stream.read_to_string(&mut raw).await.unwrap();
        raw
    }

    fn short(max_conns: usize) -> HttpLimits {
        HttpLimits {
            max_conns,
            header_read: Duration::from_millis(300),
            request: Duration::from_millis(300),
        }
    }

    #[tokio::test]
    async fn api_half_request_is_closed_within_timeout() {
        let s = server_with(short(256)).await;
        let mut half = open_with(s.addr, "GET /healthz HTTP/1.1\r\nhost: t\r\n").await;
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), half.read_to_end(&mut rest))
            .await
            .expect("half request is closed")
            .ok();
    }

    #[tokio::test]
    async fn api_silent_connection_is_closed_within_timeout() {
        let s = server_with(short(256)).await;
        let mut silent = tokio::net::TcpStream::connect(s.addr).await.unwrap();
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), silent.read_to_end(&mut rest))
            .await
            .expect("silent connection is closed")
            .ok();
    }

    #[tokio::test]
    async fn api_idle_connections_do_not_block_healthz() {
        let s = server_with(HttpLimits::new(4096)).await;
        let mut idle = Vec::new();
        for _ in 0..2000 {
            idle.push(tokio::net::TcpStream::connect(s.addr).await.unwrap());
        }
        let started = std::time::Instant::now();
        assert!(healthz(s.addr).await.starts_with("HTTP/1.1 200"));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(idle);
    }

    #[tokio::test]
    async fn api_connection_cap_closes_the_excess() {
        let s = server_with(HttpLimits {
            max_conns: 1,
            ..HttpLimits::new(1)
        })
        .await;
        let _held = tokio::net::TcpStream::connect(s.addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut extra = tokio::net::TcpStream::connect(s.addr).await.unwrap();
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), extra.read_to_end(&mut rest))
            .await
            .expect("excess connection is closed")
            .ok();
        assert_eq!(rest, Vec::<u8>::new());
    }

    #[tokio::test]
    async fn api_stalled_request_body_gets_408() {
        let s = server_with(short(256)).await;
        let mut stalled = open_with(
            s.addr,
            "POST /api/v1/auth/login HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\
             content-type: application/json\r\ncontent-length: 100\r\n\r\n{",
        )
        .await;
        let mut raw = String::new();
        tokio::time::timeout(Duration::from_secs(3), stalled.read_to_string(&mut raw))
            .await
            .expect("stalled request is answered")
            .unwrap();
        assert!(raw.starts_with("HTTP/1.1 408"), "{raw}");
    }
}
