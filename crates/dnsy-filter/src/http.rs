//! A small HTTP/1.1 client: one request per connection over a TCP stream dialled to addresses
//! the caller supplies, with TLS verified against the webpki roots.
//!
//! URLs are split by hand ([`Target`]): ASCII only (internationalised host names are not
//! supported; use the punycode `xn--` form), no user info, IPv6 literals in brackets. Hosts
//! ending in a numeric label must be a plain dotted-quad IPv4 address, so shorthand forms such
//! as `0x7f.1` or `2130706433` are refused instead of being interpreted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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

use crate::fetch::FetchError;

/// URL scheme of a [`Target`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// An `http(s)` URL split into the parts a request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    scheme: Scheme,
    /// Lowercase host; IPv6 literals keep their brackets.
    host: String,
    ip: Option<IpAddr>,
    port: u16,
    path_and_query: String,
}

impl Target {
    /// Parses an absolute `http://` or `https://` URL. The fragment is dropped; an empty path
    /// becomes `/`; percent-encoding is passed through untouched.
    ///
    /// # Errors
    /// [`FetchError::UnsupportedScheme`] for another scheme, [`FetchError::InvalidLocation`]
    /// for anything else this parser does not accept.
    pub fn parse(s: &str) -> Result<Target, FetchError> {
        if !s.bytes().all(is_url_byte) {
            return Err(FetchError::InvalidLocation);
        }
        let (scheme, rest) = s.split_once("://").ok_or(FetchError::InvalidLocation)?;
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => return Err(FetchError::UnsupportedScheme),
        };
        let rest = rest.split_once('#').map_or(rest, |(r, _)| r);
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(split);
        if authority.contains('@') {
            return Err(FetchError::InvalidLocation);
        }
        let (host, ip, port) = split_authority(authority)?;
        Ok(Target {
            scheme,
            host,
            ip,
            port: port.unwrap_or_else(|| scheme.default_port()),
            path_and_query: path_and_query(tail),
        })
    }

    /// The target of a redirect answered by this target: an absolute `http(s)` URL or an
    /// absolute path on the same origin. Relative paths, scheme-relative and other schemes, a
    /// missing host and an https to http downgrade are refused.
    ///
    /// # Errors
    /// [`FetchError::BadRedirect`].
    pub fn resolve_location(&self, header: &str) -> Result<Target, FetchError> {
        let lower = header.to_ascii_lowercase();
        let next = if lower.starts_with("http://") || lower.starts_with("https://") {
            Target::parse(header).map_err(|_| FetchError::BadRedirect)?
        } else if header.starts_with('/') && !header.starts_with("//") {
            if !header.bytes().all(is_url_byte) {
                return Err(FetchError::BadRedirect);
            }
            let path = header.split_once('#').map_or(header, |(p, _)| p);
            Target {
                path_and_query: path.to_owned(),
                ..self.clone()
            }
        } else {
            return Err(FetchError::BadRedirect);
        };
        if self.scheme == Scheme::Https && next.scheme != Scheme::Https {
            return Err(FetchError::BadRedirect);
        }
        Ok(next)
    }

    /// The scheme.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host as written (lowercase, IPv6 literals in brackets).
    #[must_use]
    pub fn host_str(&self) -> &str {
        &self.host
    }

    /// The host when it is an IP literal.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    /// The explicit or default port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The path and query sent in the request line.
    #[must_use]
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    fn host_header(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Printable ASCII without space: everything else (controls, space, non-ASCII) is refused.
fn is_url_byte(b: u8) -> bool {
    b.is_ascii_graphic()
}

fn path_and_query(tail: &str) -> String {
    if tail.is_empty() {
        "/".to_owned()
    } else if tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    }
}

fn split_authority(authority: &str) -> Result<(String, Option<IpAddr>, Option<u16>), FetchError> {
    let (host, ip, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (addr, after) = v6.split_once(']').ok_or(FetchError::InvalidLocation)?;
        let addr: Ipv6Addr = addr.parse().map_err(|_| FetchError::InvalidLocation)?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(FetchError::InvalidLocation)?),
        };
        (format!("[{addr}]"), Some(IpAddr::V6(addr)), port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        let host = host.to_ascii_lowercase();
        let (host, ip) = check_host(host)?;
        (host, ip, port)
    };
    let port = match port {
        None | Some("") => None,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => {
            Some(p.parse().map_err(|_| FetchError::InvalidLocation)?)
        }
        Some(_) => return Err(FetchError::InvalidLocation),
    };
    Ok((host, ip, port))
}

/// A host name of letters, digits, `-`, `_` and `.`; a numeric last label makes it an IPv4
/// literal, which must then be a plain dotted quad.
fn check_host(host: String) -> Result<(String, Option<IpAddr>), FetchError> {
    let valid = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.');
    let bare = host.strip_suffix('.').unwrap_or(&host);
    if bare.is_empty() || bare.starts_with('.') || !host.bytes().all(valid) {
        return Err(FetchError::InvalidLocation);
    }
    let last = bare.rsplit('.').next().unwrap_or(bare);
    let numeric = last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
    if !numeric {
        return Ok((host, None));
    }
    let ip: Ipv4Addr = bare.parse().map_err(|_| FetchError::InvalidLocation)?;
    Ok((ip.to_string(), Some(IpAddr::V4(ip))))
}

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
    match target.scheme {
        Scheme::Http => exchange(stream, request).await,
        Scheme::Https => {
            let name = match target.ip {
                Some(ip) => ServerName::IpAddress(ip.into()),
                None => ServerName::try_from(target.host.clone()).map_err(|_| FetchError::Http)?,
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
    let addrs: Vec<SocketAddr> = match target.ip {
        Some(ip) => vec![SocketAddr::new(ip, target.port)],
        None => tokio::net::lookup_host((target.host.as_str(), target.port))
            .await
            .map_err(|_| FetchError::Resolve)?
            .collect(),
    };
    if addrs.is_empty() {
        return Err(FetchError::Resolve);
    }
    Ok(addrs)
}
