//! `DoH` listener (RFC 8484): hyper over rustls, HTTP/1.1 and HTTP/2 (ALPN `h2`, `http/1.1`).
//!
//! `GET /dns-query?dns=<base64url>` and `POST /dns-query` (`application/dns-message`). Tokens are
//! accepted as `Authorization: Bearer` or as `/dns-query/{token}` for clients that cannot set
//! headers. Status mapping: 404 other paths, 405 other methods, 401 missing or rejected token,
//! 403 token without `dns:query`, 429 throttled, 415 wrong content type, 400 malformed or
//! oversized input (over 65535 octets).
//!
//! Secrets: the request URI and `Authorization` header are never logged, copied into error
//! bodies or handed to the engine; the only thing that travels on is the [`Principal`].

mod throttle;
mod wire;

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dnsy_auth::{AuthError, TokenVerifier};
use dnsy_core::{Principal, Scope, Transport};
use dnsy_engine::{Handler, RequestContext};
use dnsy_proto::Edns;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, RETRY_AFTER,
    WWW_AUTHENTICATE,
};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

use crate::query::{Incoming as Parsed, encode_response, pad_response, parse};
use crate::tcp::Limits;
use throttle::Throttle;
use wire::{MAX_MESSAGE, MAX_TOKEN, MEDIA_TYPE};

/// ALPN protocols, in preference order.
pub(crate) const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Why a token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohDenied {
    /// Malformed, unknown, revoked or expired token: 401.
    Invalid,
    /// A valid token without the `dns:query` scope: 403.
    MissingScope,
    /// The verifier itself failed: 500.
    Internal,
}

/// Object-safe token check for `DoH`; [`TokenAuth`] adapts a [`TokenVerifier`].
pub trait DohAuthenticator: Send + Sync + 'static {
    /// Verifies `token` for the `dns:query` scope.
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Principal, DohDenied>> + Send + 'a>>;
}

/// [`DohAuthenticator`] backed by a [`TokenVerifier`] (comparison is constant time there).
#[derive(Debug, Clone)]
pub struct TokenAuth<V>(pub V);

impl<V: TokenVerifier + 'static> DohAuthenticator for TokenAuth<V> {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Principal, DohDenied>> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .verify(token, Scope::DnsQuery)
                .await
                .map_err(|e| match e {
                    AuthError::InvalidToken => DohDenied::Invalid,
                    AuthError::MissingScope => DohDenied::MissingScope,
                    _ => DohDenied::Internal,
                })
        })
    }
}

/// `DoH` listener settings.
#[derive(Clone)]
pub struct DohConfig {
    pub listen: Vec<SocketAddr>,
    /// Certificate chain (PEM), hot-reloaded.
    pub cert: PathBuf,
    /// Private key (PEM).
    pub key: PathBuf,
    pub auth: Arc<dyn DohAuthenticator>,
    /// Request path (default `/dns-query`); `{path}/{token}` carries a token in the path.
    pub path: String,
    /// Reject requests without a token (default `true`). A presented token is always verified.
    pub require_token: bool,
    /// Rejected tokens per client IP and window before it gets 429 (default 10).
    pub max_auth_failures: u32,
    /// Throttle window (default 60 s).
    pub auth_window: Duration,
}

impl std::fmt::Debug for DohConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohConfig")
            .field("listen", &self.listen)
            .field("cert", &self.cert)
            .field("key", &self.key)
            .field("require_token", &self.require_token)
            .finish_non_exhaustive()
    }
}

impl DohConfig {
    /// Token required by default.
    #[must_use]
    pub fn new(
        listen: Vec<SocketAddr>,
        cert: PathBuf,
        key: PathBuf,
        auth: Arc<dyn DohAuthenticator>,
    ) -> Self {
        Self {
            listen,
            cert,
            key,
            auth,
            path: wire::BASE_PATH.to_owned(),
            require_token: true,
            max_auth_failures: 10,
            auth_window: Duration::from_secs(60),
        }
    }
}

pub(crate) struct State<H> {
    handler: Arc<H>,
    path: String,
    auth: Arc<dyn DohAuthenticator>,
    require_token: bool,
    throttle: Throttle,
    body_timeout: Duration,
}

impl<H> State<H> {
    pub(crate) fn new(config: &DohConfig, handler: Arc<H>, body_timeout: Duration) -> Arc<Self> {
        Arc::new(State {
            handler,
            path: config.path.clone(),
            auth: Arc::clone(&config.auth),
            require_token: config.require_token,
            throttle: Throttle::new(config.max_auth_failures, config.auth_window),
            body_timeout,
        })
    }
}

pub(crate) async fn serve<H: Handler>(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<State<H>>,
    mut shutdown: watch::Receiver<bool>,
    limits: Limits,
) {
    let slots = Arc::new(Semaphore::new(limits.max_conns));
    let mut conns = JoinSet::new();
    loop {
        while conns.try_join_next().is_some() {}
        let (stream, client) = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(error = %e, "doh accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::debug!(%client, "doh connection limit reached; closing");
            continue;
        };
        let acceptor = acceptor.clone();
        let state = Arc::clone(&state);
        let shutdown = shutdown.clone();
        conns.spawn(async move {
            match timeout(limits.idle, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => connection(tls, client, state, shutdown, limits).await,
                Ok(Err(e)) => tracing::debug!(error = %e, "doh handshake failed"),
                Err(_) => tracing::debug!("doh handshake timed out"),
            }
            drop(permit);
        });
    }
    let _ = timeout(limits.drain, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
}

async fn connection<H: Handler, S>(
    stream: S,
    client: SocketAddr,
    state: Arc<State<H>>,
    mut shutdown: watch::Receiver<bool>,
    limits: Limits,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.idle);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(100)
        .keep_alive_interval(limits.idle)
        .keep_alive_timeout(limits.idle);
    let service = service_fn(move |req| {
        let state = Arc::clone(&state);
        async move { Ok::<_, Infallible>(respond(&state, client, req).await) }
    });
    let conn = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(conn);
    tokio::select! {
        result = conn.as_mut() => {
            if let Err(e) = result {
                tracing::debug!(%client, error = %e, "doh connection ended");
            }
        }
        _ = shutdown.changed() => {
            conn.as_mut().graceful_shutdown();
            let _ = timeout(limits.drain, conn.as_mut()).await;
        }
    }
}

/// An early-exit response (boxed: it is large for an `Err` variant).
type Rejection = Box<Response<Full<Bytes>>>;

fn reply(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(
        status.canonical_reason().unwrap_or("error"),
    )));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    response
}

fn unauthorized() -> Response<Full<Bytes>> {
    let mut response = reply(StatusCode::UNAUTHORIZED);
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// Handles one request. Nothing in here may log or echo the URI or `Authorization`.
async fn respond<H: Handler>(
    state: &State<H>,
    client: SocketAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let response = route(state, client, req).await;
    tracing::debug!(%client, status = response.status().as_u16(), "doh request");
    response
}

async fn route<H: Handler>(
    state: &State<H>,
    client: SocketAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let Ok(path_token) = wire::path_token(&state.path, req.uri().path()) else {
        return reply(StatusCode::NOT_FOUND);
    };
    if req.method() != Method::GET && req.method() != Method::POST {
        let mut response = reply(StatusCode::METHOD_NOT_ALLOWED);
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET, POST"));
        return response;
    }
    let principal = match authenticate(state, client, &req, path_token).await {
        Ok(p) => p,
        Err(rejection) => return *rejection,
    };
    let bytes = if req.method() == Method::GET {
        match wire::decode_get(req.uri().query()) {
            Ok(b) => b,
            Err(()) => return reply(StatusCode::BAD_REQUEST),
        }
    } else {
        match read_post(state, req).await {
            Ok(b) => b,
            Err(rejection) => return *rejection,
        }
    };
    let Parsed::Query(query) = parse(&bytes) else {
        return reply(StatusCode::BAD_REQUEST);
    };
    let ctx = RequestContext {
        client,
        transport: Transport::Doh,
        principal,
        received_at: Instant::now(),
    };
    let Some(mut response) = state.handler.respond(ctx, query.clone()).await else {
        // HTTP cannot stay silent: a dropped query becomes a bare 403.
        return reply(StatusCode::FORBIDDEN);
    };
    if query.edns.as_ref().is_some_and(Edns::has_padding) {
        pad_response(&mut response);
    }
    let Some(body) = encode_response(&query, &response, MAX_MESSAGE) else {
        return reply(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut http = Response::new(Full::new(Bytes::from(body)));
    let headers = http.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&format!("max-age={}", wire::min_ttl(&response)))
            .unwrap_or_else(|_| HeaderValue::from_static("max-age=0")),
    );
    http
}

/// Resolves the request's principal. `Err` carries the response to send.
async fn authenticate<H>(
    state: &State<H>,
    client: SocketAddr,
    req: &Request<Incoming>,
    path_token: Option<&str>,
) -> Result<Option<Principal>, Rejection> {
    let ip = client.ip();
    if let Some(secs) = state.throttle.blocked(ip, Instant::now()) {
        let mut response = reply(StatusCode::TOO_MANY_REQUESTS);
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from(secs));
        return Err(Box::new(response));
    }
    let header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(wire::bearer);
    let Some(token) = path_token.or(header) else {
        return if state.require_token {
            Err(Box::new(unauthorized()))
        } else {
            Ok(None)
        };
    };
    if token.len() > MAX_TOKEN {
        state.throttle.failure(ip, Instant::now());
        return Err(Box::new(unauthorized()));
    }
    match state.auth.authenticate(token).await {
        Ok(principal) => Ok(Some(principal)),
        Err(DohDenied::Invalid) => {
            state.throttle.failure(ip, Instant::now());
            Err(Box::new(unauthorized()))
        }
        Err(DohDenied::MissingScope) => Err(Box::new(reply(StatusCode::FORBIDDEN))),
        Err(DohDenied::Internal) => Err(Box::new(reply(StatusCode::INTERNAL_SERVER_ERROR))),
    }
}

async fn read_post<H>(state: &State<H>, req: Request<Incoming>) -> Result<Vec<u8>, Rejection> {
    let content_type = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    if !content_type.is_some_and(wire::is_dns_message) {
        return Err(Box::new(reply(StatusCode::UNSUPPORTED_MEDIA_TYPE)));
    }
    let declared = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_MESSAGE) {
        return Err(Box::new(reply(StatusCode::BAD_REQUEST)));
    }
    let body = Limited::new(req.into_body(), MAX_MESSAGE).collect();
    match timeout(state.body_timeout, body).await {
        Ok(Ok(collected)) => {
            let bytes = collected.to_bytes();
            if bytes.is_empty() {
                Err(Box::new(reply(StatusCode::BAD_REQUEST)))
            } else {
                Ok(bytes.to_vec())
            }
        }
        Ok(Err(_)) => Err(Box::new(reply(StatusCode::BAD_REQUEST))),
        Err(_) => Err(Box::new(reply(StatusCode::REQUEST_TIMEOUT))),
    }
}
