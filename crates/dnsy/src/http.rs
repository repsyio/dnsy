//! Serves the API router over plain HTTP or TLS with graceful shutdown.

use std::net::IpAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::ConnectInfo;
use axum::response::IntoResponse as _;
use dnsy_api::auth::ClientAddr;
use dnsy_core::net::{IpNet, forwarded_client, is_trusted};
use dnsy_server::SlotLimit;
use hyper::StatusCode;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::watch;
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

/// After answering 413 the listener keeps reading and discarding at most this many request bytes
/// (or the declared `Content-Length` when smaller) so that the client can still read the answer.
const DRAIN_BODY_BYTES: u64 = 4 << 20;

/// Longest the discard of a rejected body may take, counted from the end of the connection.
const DRAIN_BODY_TIME: Duration = Duration::from_secs(2);

/// Path of the live-tail stream; it is open-ended by design and exempt from the request timeout.
const STREAM_PATH: &str = "/api/v1/querylog/stream";

/// Admission limits of the API listener.
#[derive(Debug, Clone)]
pub(crate) struct HttpLimits {
    /// Concurrent connections; further ones are closed at accept.
    pub max_conns: usize,
    /// Concurrent connections per client (`client_key`); further ones are closed at accept.
    pub max_conns_per_client: usize,
    /// Time for a client to finish the TLS handshake and each request head, and the longest a
    /// connection may sit with no request in progress (HTTP/1.1 keep-alive and HTTP/2 alike).
    pub header_read: Duration,
    /// Time for a handler to produce a response (headers), except on [`STREAM_PATH`].
    pub request: Duration,
    /// Reverse proxies whose `X-Forwarded-For` names the client; their connections count against
    /// `max_conns` only.
    pub trusted_proxies: Arc<[IpNet]>,
}

impl HttpLimits {
    pub(crate) fn from_config(config: &dnsy_config::Config) -> Self {
        let count = |n: u32| usize::try_from(n).unwrap_or(usize::MAX);
        Self {
            trusted_proxies: config.api.trusted_proxies.clone().into(),
            ..Self::new(
                count(config.api.max_conns),
                count(config.api.max_conns_per_client),
            )
        }
    }

    pub(crate) fn new(max_conns: usize, max_conns_per_client: usize) -> Self {
        Self {
            max_conns,
            max_conns_per_client,
            header_read: Duration::from_secs(30),
            request: Duration::from_secs(30),
            trusted_proxies: Arc::from([]),
        }
    }
}

/// Requests in progress on one connection and when the connection last had one.
#[derive(Debug)]
struct Activity {
    /// Bytes of an oversized request body worth discarding once the connection is done; 0 when
    /// no request was rejected with 413.
    drain: AtomicU64,
    started: Instant,
    active: AtomicUsize,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            drain: AtomicU64::new(0),
            started: Instant::now(),
            active: AtomicUsize::new(0),
            last_ms: AtomicU64::new(0),
        })
    }

    fn touch(&self) {
        let ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    /// Remembers how much of a rejected body is worth discarding when the answer is a 413.
    fn note_status(&self, status: StatusCode, declared: Option<u64>) {
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            let bound = declared.map_or(DRAIN_BODY_BYTES, |n| n.min(DRAIN_BODY_BYTES));
            self.drain.store(bound, Ordering::Relaxed);
        }
    }

    /// Marks a request as started; it ends when the guard drops.
    fn begin(self: &Arc<Self>) -> RequestGuard {
        self.active.fetch_add(1, Ordering::Relaxed);
        self.touch();
        RequestGuard(Arc::clone(self))
    }

    /// Completes once the connection has had no request in progress for `limit`.
    async fn closed_when_idle(&self, limit: Duration) {
        let mut deadline = tokio::time::Instant::now() + limit;
        loop {
            tokio::time::sleep_until(deadline).await;
            let wait = match self.idle_for() {
                Some(idle) if idle >= limit => return,
                Some(idle) => limit.saturating_sub(idle),
                None => limit,
            };
            deadline = tokio::time::Instant::now() + wait;
        }
    }

    /// How long the connection has had no request in progress, `None` while one is.
    fn idle_for(&self) -> Option<Duration> {
        if self.active.load(Ordering::Relaxed) > 0 {
            return None;
        }
        let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        Some(self.started.elapsed().saturating_sub(last))
    }
}

struct RequestGuard(Arc<Activity>);

/// A response body that keeps its connection counted as busy until it is finished or dropped.
struct Tracked {
    body: axum::body::BodyDataStream,
    _guard: RequestGuard,
}

impl futures_util::Stream for Tracked {
    type Item = std::result::Result<axum::body::Bytes, axum::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.body).poll_next(cx)
    }
}

fn tracked(body: axum::body::Body, guard: RequestGuard) -> axum::body::Body {
    axum::body::Body::from_stream(Tracked {
        body: body.into_data_stream(),
        _guard: guard,
    })
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
        self.0.touch();
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
    let slots = SlotLimit::new(limits.max_conns, limits.max_conns_per_client);
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
        let Some(permit) = admit(&slots, peer.ip(), &limits.trusted_proxies) else {
            tracing::debug!(%peer, "api connection limit reached (shared or per client); closing");
            continue;
        };
        let app = app.clone();
        let tls = tls.clone();
        let mut stop = shutdown.clone();
        let (header_read, request) = (limits.header_read, limits.request);
        let trusted = Arc::clone(&limits.trusted_proxies);
        conns.spawn(async move {
            let io: Box<dyn Io> = match tls {
                Some(acceptor) => match timeout(header_read, acceptor.accept(stream)).await {
                    Ok(Ok(tls)) => Box::new(tls),
                    Ok(Err(e)) => {
                        tracing::debug!(%peer, error = %e, "api tls handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(%peer, "api tls handshake timed out");
                        return;
                    }
                },
                None => Box::new(stream),
            };
            let io = SharedIo(Arc::new(std::sync::Mutex::new(io)));
            let activity = Activity::new();
            let tracker = Arc::clone(&activity);
            // Handlers read the client address from `ClientAddr` (login throttling is keyed on
            // it): the peer, or the `X-Forwarded-For` client when the peer is a trusted proxy.
            let service = service_fn(move |req: hyper::Request<Incoming>| {
                let mut req = req.map(axum::body::Body::new);
                let client = request_client(&req, peer.ip(), &trusted);
                req.extensions_mut().insert(ConnectInfo(peer));
                req.extensions_mut().insert(ClientAddr(client));
                let exempt = req.uri().path() == STREAM_PATH;
                let declared = declared_length(&req);
                let call =
                    noting_rejection(app.clone().oneshot(req), Arc::clone(&tracker), declared);
                let guard = tracker.begin();
                async move {
                    if exempt {
                        // The live-tail stream is open-ended: it has no request timeout, and a
                        // successful response keeps the connection busy until its body ends or
                        // is dropped. A rejected request (401, 403, 429) does not.
                        let response = call.await?;
                        if response.status().is_success() {
                            return Ok(response.map(|body| tracked(body, guard)));
                        }
                        return Ok(response);
                    }
                    let _guard = guard;
                    match timeout(request, call).await {
                        Ok(response) => response,
                        Err(_) => Ok(StatusCode::REQUEST_TIMEOUT.into_response()),
                    }
                }
            });
            let mut builder = Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(header_read);
            builder
                .http2()
                .timer(TokioTimer::new())
                .max_concurrent_streams(100)
                .keep_alive_interval(header_read)
                .keep_alive_timeout(header_read);
            let conn = builder.serve_connection(TokioIo::new(io.clone()), service);
            tokio::pin!(conn);
            let result = tokio::select! {
                r = conn.as_mut() => r,
                () = activity.closed_when_idle(header_read) => {
                    tracing::debug!(%peer, "api connection idle; closing");
                    Ok(())
                }
                _ = stop.changed() => {
                    conn.as_mut().graceful_shutdown();
                    conn.await
                }
            };
            if let Err(e) = result {
                tracing::debug!(%peer, error = %e, "api connection ended");
            }
            // The 413 is out; let the client finish (a bounded part of) its upload so it can
            // read it. The slot is held until then.
            discard(io, activity.drain.load(Ordering::Relaxed)).await;
            drop(permit);
        });
    }
    let _ = tokio::time::timeout(DRAIN, async { while conns.join_next().await.is_some() {} }).await;
}

/// A connection slot for `peer`. A trusted proxy multiplexes many clients: it counts against
/// `max_conns` only.
fn admit(slots: &SlotLimit, peer: IpAddr, trusted: &[IpNet]) -> Option<dnsy_server::Slot> {
    if is_trusted(peer, trusted) {
        slots.try_acquire_shared()
    } else {
        slots.try_acquire(peer)
    }
}

/// The request's client address (see [`forwarded_client`]).
fn request_client<B>(req: &hyper::Request<B>, peer: IpAddr, trusted: &[IpNet]) -> IpAddr {
    let xff = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok());
    forwarded_client(peer, xff, trusted)
}

/// The connection's transport, shared so the listener keeps it after hyper is done with it and
/// can discard the unread rest of a rejected body (closing with unread data resets the peer).
#[derive(Clone)]
struct SharedIo(Arc<std::sync::Mutex<Box<dyn Io>>>);

impl SharedIo {
    fn with<R>(&self, f: impl FnOnce(Pin<&mut Box<dyn Io>>) -> R) -> R {
        let mut io = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(Pin::new(&mut *io))
    }
}

impl tokio::io::AsyncRead for SharedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.with(|io| io.poll_read(cx, buf))
    }
}

impl tokio::io::AsyncWrite for SharedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.with(|io| io.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.with(|io| io.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.with(|io| io.poll_shutdown(cx))
    }
}

/// Awaits the handler and records a 413 answer so the connection can discard the rest of the body.
async fn noting_rejection<F>(
    call: F,
    activity: Arc<Activity>,
    declared: Option<u64>,
) -> std::result::Result<axum::response::Response, std::convert::Infallible>
where
    F: Future<Output = std::result::Result<axum::response::Response, std::convert::Infallible>>,
{
    let response = call.await;
    if let Ok(r) = &response {
        activity.note_status(r.status(), declared);
    }
    response
}

fn declared_length<B>(req: &hyper::Request<B>) -> Option<u64> {
    let value = req.headers().get(hyper::header::CONTENT_LENGTH)?;
    value.to_str().ok()?.parse().ok()
}

/// Reads and discards up to `max` bytes (nothing when 0), for at most [`DRAIN_BODY_TIME`].
async fn discard(mut io: SharedIo, max: u64) {
    use tokio::io::AsyncReadExt as _;
    let mut left = max;
    let mut buf = vec![0_u8; 16 * 1024];
    let work = Box::pin(async {
        while left > 0 {
            match io.read(&mut buf).await {
                Ok(n) if n > 0 => left = left.saturating_sub(n as u64),
                _ => break,
            }
        }
    });
    if max > 0 {
        let _ = timeout(DRAIN_BODY_TIME, work).await;
    }
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
        token: String,
        _stop: watch::Sender<bool>,
        _dir: tempfile::TempDir,
    }

    async fn server() -> Server {
        server_with(HttpLimits::new(256, 256)).await
    }

    async fn server_with(limits: HttpLimits) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
        let state = ApiState::new(store.clone());
        let admin = state
            .auth
            .users
            .create("admin", PW, Role::Admin)
            .await
            .unwrap();
        let (token, _) = state
            .auth
            .tokens
            .create(admin.id, "t", &[dnsy_core::Scope::ApiWrite], None)
            .await
            .unwrap();
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
            token,
            _stop: stop,
            _dir: dir,
        }
    }

    /// Posts a login from the given loopback source address; returns status and headers text.
    async fn login(s: &Server, from: &str, password: &str) -> (u16, String) {
        login_with(s, from, password, "").await
    }

    /// [`login`] with extra header lines (each ending in `\r\n`).
    async fn login_with(s: &Server, from: &str, password: &str, extra: &str) -> (u16, String) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket
            .bind(SocketAddr::new(from.parse().unwrap(), 0))
            .unwrap();
        let mut stream = socket.connect(s.addr).await.unwrap();
        let body = json!({"username": "admin", "password": password}).to_string();
        let request = format!(
            "POST /api/v1/auth/login HTTP/1.1\r\nhost: t\r\nconnection: close\r\n{extra}\
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

    /// Limits trusting `127.0.0.2` as a reverse proxy.
    fn proxied(max_conns_per_client: usize) -> HttpLimits {
        HttpLimits {
            trusted_proxies: Arc::from(["127.0.0.2/32".parse::<IpNet>().unwrap()]),
            ..HttpLimits::new(256, max_conns_per_client)
        }
    }

    #[tokio::test]
    async fn forwarded_for_is_ignored_from_an_untrusted_peer() {
        let s = server_with(proxied(256)).await;
        let xff = "x-forwarded-for: 203.0.113.9\r\n";
        assert_eq!(
            login_with(&s, "127.0.0.3", "wrong-password", xff).await.0,
            401
        );
        assert_eq!(recorded_ips(&s).await, vec!["127.0.0.3".to_owned()]);
        // Without a trusted list the header is ignored even from 127.0.0.2.
        let plain = server().await;
        assert_eq!(
            login_with(&plain, "127.0.0.2", "wrong-password", xff)
                .await
                .0,
            401
        );
        assert_eq!(recorded_ips(&plain).await, vec!["127.0.0.2".to_owned()]);
    }

    #[tokio::test]
    async fn forwarded_for_is_used_from_a_trusted_proxy() {
        let s = server_with(proxied(256)).await;
        let xff = "x-forwarded-for: 198.51.100.1, 203.0.113.9\r\n";
        assert_eq!(
            login_with(&s, "127.0.0.2", "wrong-password", xff).await.0,
            401
        );
        assert_eq!(recorded_ips(&s).await, vec!["203.0.113.9".to_owned()]);
    }

    #[tokio::test]
    async fn trusted_proxy_without_a_usable_header_is_not_keyed_as_the_proxy() {
        let s = server_with(proxied(256)).await;
        assert_eq!(login(&s, "127.0.0.2", "wrong-password").await.0, 401);
        let bad = "x-forwarded-for: 203.0.113.9:443\r\n";
        assert_eq!(
            login_with(&s, "127.0.0.2", "wrong-password", bad).await.0,
            401
        );
        assert_eq!(recorded_ips(&s).await, vec!["0.0.0.0".to_owned()]);
    }

    #[tokio::test]
    async fn forwarded_lockout_is_per_forwarded_client() {
        let s = server_with(proxied(256)).await;
        let a = "x-forwarded-for: 203.0.113.1\r\n";
        let b = "x-forwarded-for: 203.0.113.2\r\n";
        for _ in 0..5 {
            assert_eq!(
                login_with(&s, "127.0.0.2", "wrong-password", a).await.0,
                401
            );
        }
        assert_eq!(login_with(&s, "127.0.0.2", PW, a).await.0, 429);
        assert_eq!(login_with(&s, "127.0.0.2", PW, b).await.0, 200);
    }

    #[tokio::test]
    async fn trusted_proxy_is_exempt_from_the_per_client_connection_cap() {
        let s = server_with(proxied(1)).await;
        let _held = connect_from("127.0.0.2", s.addr).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut proxy = connect_from("127.0.0.2", s.addr).await;
        proxy
            .write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut raw = String::new();
        proxy.read_to_string(&mut raw).await.unwrap();
        assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
        // An untrusted peer still gets one connection.
        let _first = connect_from("127.0.0.3", s.addr).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut second = connect_from("127.0.0.3", s.addr).await;
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), second.read_to_end(&mut rest))
            .await
            .expect("the second connection from an untrusted client is closed")
            .ok();
        assert_eq!(rest, Vec::<u8>::new());
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

    /// Sends a zone create whose declared body is far over the 1 MiB limit, then keeps writing
    /// `total` bytes of it (or until the server stops reading). Returns the response text and the
    /// bytes written.
    async fn upload_oversized(s: &Server, declared: usize, total: usize) -> (String, usize) {
        let mut stream = tokio::net::TcpStream::connect(s.addr).await.unwrap();
        let head = format!(
            "POST /api/v1/zones HTTP/1.1\r\nhost: t\r\nauthorization: Bearer {}\r\n\
             content-type: application/json\r\ncontent-length: {declared}\r\n\r\n",
            s.token
        );
        stream.write_all(head.as_bytes()).await.unwrap();
        let chunk = vec![b'x'; 64 * 1024];
        let mut written = 0;
        while written < total {
            let n = chunk.len().min(total - written);
            if stream.write_all(&chunk[..n]).await.is_err() {
                break;
            }
            written += n;
            // A real client takes time to produce its body; the server answers meanwhile.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let mut raw = String::new();
        // A reset after the answer may cut the read short; whatever arrived is kept.
        let _ = stream.read_to_string(&mut raw).await;
        (raw, written)
    }

    #[tokio::test]
    async fn client_sending_four_times_the_limit_reads_the_413() {
        let s = server().await;
        let four = 4 << 20;
        let (raw, written) = upload_oversized(&s, four, four).await;
        // The whole body went out (no broken pipe) and the answer was readable.
        assert_eq!(written, four);
        assert!(raw.starts_with("HTTP/1.1 413"), "got {raw:?}");
    }

    #[tokio::test]
    async fn endless_oversized_upload_is_cut_off_within_the_bound() {
        let s = server().await;
        // Declares far more than it sends: the server drains at most its bound (4 MiB), then closes.
        let started = Instant::now();
        let (_, written) = tokio::time::timeout(
            Duration::from_secs(20),
            upload_oversized(&s, usize::MAX >> 1, usize::MAX >> 1),
        )
        .await
        .expect("the server stops reading and closes");
        assert!(started.elapsed() < Duration::from_secs(10));
        // Drain bound (4 MiB) plus what the request layers read and the socket buffers hold.
        assert!(written < 64 << 20, "wrote {written} bytes");
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
            max_conns_per_client: max_conns,
            header_read: Duration::from_millis(300),
            request: Duration::from_millis(300),
            trusted_proxies: Arc::from([]),
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
        let s = server_with(HttpLimits::new(4096, 4096)).await;
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
        let s = server_with(HttpLimits::new(1, 1)).await;
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

    /// Opens a connection from the loopback address `from`.
    async fn connect_from(from: &str, to: SocketAddr) -> tokio::net::TcpStream {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket
            .bind(SocketAddr::new(from.parse().unwrap(), 0))
            .unwrap();
        socket.connect(to).await.unwrap()
    }

    #[tokio::test]
    async fn api_per_client_cap_leaves_room_for_other_clients() {
        let s = server_with(HttpLimits::new(256, 2)).await;
        let _a = connect_from("127.0.0.2", s.addr).await;
        let _b = connect_from("127.0.0.2", s.addr).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut third = connect_from("127.0.0.2", s.addr).await;
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), third.read_to_end(&mut rest))
            .await
            .expect("the third connection from one client is closed")
            .ok();
        assert_eq!(rest, Vec::<u8>::new());
        let mut other = connect_from("127.0.0.3", s.addr).await;
        other
            .write_all(b"GET /healthz HTTP/1.1\r\nhost: t\r\nconnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut raw = String::new();
        other.read_to_string(&mut raw).await.unwrap();
        assert!(raw.starts_with("HTTP/1.1 200"), "{raw}");
    }

    /// True when the server closes an HTTP/2 connection that sent `request` (a HEADERS frame, or
    /// nothing) within 5 s. The client answers PING frames, as a live peer would, so keep-alive
    /// pings alone never close it.
    async fn h2_is_closed(addr: SocketAddr, request: &[u8]) -> bool {
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            .await
            .unwrap();
        c.write_all(request).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut head = [0_u8; 9];
                if c.read_exact(&mut head).await.is_err() {
                    return;
                }
                let len =
                    usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
                let mut payload = vec![0_u8; len];
                if c.read_exact(&mut payload).await.is_err() {
                    return;
                }
                if head[3] == 6 && head[4] & 1 == 0 {
                    let mut ack = vec![0, 0, 8, 6, 1, 0, 0, 0, 0];
                    ack.extend_from_slice(&payload);
                    if c.write_all(&ack).await.is_err() {
                        return;
                    }
                }
            }
        })
        .await
        .is_ok()
    }

    /// A HEADERS frame (stream 1, `END_STREAM`) for `GET path`.
    fn h2_get(path: &str) -> Vec<u8> {
        let mut block = vec![0x82, 0x86, 0x44, u8::try_from(path.len()).unwrap()];
        block.extend_from_slice(path.as_bytes());
        block.extend_from_slice(&[0x41, 0x01, b't']);
        let mut frame = vec![0, 0, u8::try_from(block.len()).unwrap(), 1, 0x5, 0, 0, 0, 1];
        frame.extend(block);
        frame
    }

    #[tokio::test]
    async fn api_h2_connection_without_streams_is_closed() {
        let s = server_with(short(256)).await;
        assert!(
            h2_is_closed(s.addr, &[]).await,
            "idle h2 connection stayed open"
        );
    }

    #[tokio::test]
    async fn api_connection_is_idle_closed_after_stream_ends_or_request_rejected() {
        let s = server_with(short(256)).await;
        // The stream path is rejected without a session; the connection must then count as idle
        // and be closed, not stay busy forever.
        assert!(
            h2_is_closed(s.addr, &h2_get(STREAM_PATH)).await,
            "rejected stream request left the connection busy"
        );
    }

    #[tokio::test]
    async fn tracked_body_releases_the_connection_when_finished_or_dropped() {
        use http_body_util::BodyExt as _;
        let activity = Activity::new();
        let finished = tracked(axum::body::Body::from("x"), activity.begin());
        assert!(activity.idle_for().is_none());
        finished.collect().await.unwrap();
        assert!(activity.idle_for().is_some());
        let dropped = tracked(axum::body::Body::from("y"), activity.begin());
        assert!(activity.idle_for().is_none());
        drop(dropped);
        assert!(activity.idle_for().is_some());
    }
}
