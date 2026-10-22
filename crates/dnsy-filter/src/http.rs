//! A small HTTP/1.1 client: one request per connection over a TCP stream dialled to addresses
//! the caller supplies, with TLS verified against the webpki roots.
//!
//! URLs are split by hand ([`Target`]): ASCII only (internationalised host names are not
//! supported; use the punycode `xn--` form), no user info, IPv6 literals in brackets. A host
//! ending in a numeric label is an IPv4 address read as browsers and the WHATWG URL standard
//! read it (`127.1`, `0x7f.0.0.1` and `2130706433` are all `127.0.0.1`), so the address policy
//! sees the address that is actually dialled; a malformed one is refused.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONNECTION, HOST, HeaderName, HeaderValue, USER_AGENT};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::location::FetchError;
pub use crate::location::{Scheme, Target};

/// The client configuration used by every caller: webpki roots, ring provider.
///
/// # Panics
/// Never in practice: the ring provider supports the default protocol versions.
pub(crate) fn tls_config(roots: rustls::RootCertStore) -> Arc<rustls::ClientConfig> {
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

pub(crate) fn webpki_roots() -> rustls::RootCertStore {
    rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// Aborts the connection task when dropped.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A response whose connection task lives as long as the response, so dropping it (or the
/// future reading it) closes the connection.
pub(crate) struct Exchange {
    pub(crate) response: Response<Incoming>,
    _conn: AbortOnDrop,
}

/// Sends one request to `target` over a connection to the first of `addrs` that accepts it.
/// Only `addrs` are dialled; the target's host is used for SNI, certificate verification and
/// the `Host` header. `headers` are added after `Host`, `User-Agent` and `Connection: close`.
pub(crate) async fn send(
    tls: &Arc<rustls::ClientConfig>,
    addrs: &[SocketAddr],
    method: Method,
    target: &Target,
    headers: &[(HeaderName, &str)],
) -> Result<Exchange, FetchError> {
    let mut stream = None;
    for addr in addrs {
        if let Ok(s) = TcpStream::connect(addr).await {
            stream = Some(s);
            break;
        }
    }
    let stream = stream.ok_or(FetchError::Http)?;
    let mut builder = Request::builder()
        .method(method)
        .uri(target.path_and_query())
        .header(HOST, target.host_header())
        .header(USER_AGENT, "dnsy")
        .header(CONNECTION, "close");
    for (name, value) in headers {
        let value = HeaderValue::from_str(value).map_err(|_| FetchError::Http)?;
        builder = builder.header(name, value);
    }
    let request = builder
        .body(Empty::<Bytes>::new())
        .map_err(|_| FetchError::Http)?;
    match target.scheme() {
        Scheme::Http => exchange(stream, request).await,
        Scheme::Https => {
            let name = match target.ip() {
                Some(ip) => ServerName::IpAddress(ip.into()),
                None => ServerName::try_from(target.host_str().to_owned())
                    .map_err(|_| FetchError::Http)?,
            };
            let tls = tokio_rustls::TlsConnector::from(Arc::clone(tls))
                .connect(name, stream)
                .await
                .map_err(|_| FetchError::Http)?;
            exchange(tls, request).await
        }
    }
}

async fn exchange<S>(io: S, request: Request<Empty<Bytes>>) -> Result<Exchange, FetchError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| FetchError::Http)?;
    let conn = AbortOnDrop(tokio::spawn(async move {
        let _ = conn.await;
    }));
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| FetchError::Http)?;
    Ok(Exchange {
        response,
        _conn: conn,
    })
}

/// Reads the body, refusing more than `max_bytes`: a larger `Content-Length` fails before the
/// first byte, a body without one fails as soon as it grows past the limit.
pub(crate) async fn read_body(
    response: &mut Response<Incoming>,
    max_bytes: u64,
) -> Result<Vec<u8>, FetchError> {
    let declared = response
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > max_bytes) {
        return Err(FetchError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(|_| FetchError::Http)?;
        if let Ok(chunk) = frame.into_data() {
            if (bytes.len() + chunk.len()) as u64 > max_bytes {
                return Err(FetchError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
    }
    Ok(bytes)
}

/// Sends one request to `url` and reads at most `max_bytes` of the answer, all within
/// `timeout`. No redirects are followed (a 3xx is returned as is) and no address policy is
/// applied: this is for operator-chosen endpoints such as the local API (`dnsy cache flush`),
/// not for list sources.
///
/// # Errors
/// [`FetchError::Resolve`], [`FetchError::Timeout`], [`FetchError::TooLarge`],
/// [`FetchError::Http`] and the URL errors of [`Target::parse`].
pub async fn request(
    method: Method,
    url: &str,
    headers: &[(HeaderName, &str)],
    max_bytes: u64,
    timeout: Duration,
) -> Result<(StatusCode, Vec<u8>), FetchError> {
    let target = Target::parse(url)?;
    let tls = tls_config(webpki_roots());
    tokio::time::timeout(timeout, async {
        let addrs = resolve(&target).await?;
        let mut exchange = send(&tls, &addrs, method, &target, headers).await?;
        let body = read_body(&mut exchange.response, max_bytes).await?;
        Ok((exchange.response.status(), body))
    })
    .await
    .map_err(|_| FetchError::Timeout)?
}

/// The addresses of the target's host: the literal itself or every address it resolves to.
pub(crate) async fn resolve(target: &Target) -> Result<Vec<SocketAddr>, FetchError> {
    let addrs: Vec<SocketAddr> = match target.ip() {
        Some(ip) => vec![SocketAddr::new(ip, target.port())],
        None => tokio::net::lookup_host((target.host_str(), target.port()))
            .await
            .map_err(|_| FetchError::Resolve)?
            .collect(),
    };
    if addrs.is_empty() {
        return Err(FetchError::Resolve);
    }
    Ok(addrs)
}
