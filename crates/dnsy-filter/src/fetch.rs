//! Fetching one list source: a local file or an http(s) URL, with SSRF protection.
//!
//! URL fetches resolve the host once, refuse non-public addresses (unless the source allows
//! them), and pin the connection to exactly the checked addresses so a second lookup cannot be
//! answered differently (DNS rebinding). Redirects are followed by hand so every hop is checked.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::header::{ETAG, HeaderName, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION};
use hyper::{Method, Response, StatusCode};
use tokio::io::AsyncReadExt;

use crate::http::{self, Target};

/// Largest list body accepted from one source.
pub const MAX_LIST_BYTES: u64 = 50 * 1024 * 1024;

/// Total time allowed for one fetch (resolution, redirects and body).
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Redirects followed before giving up.
pub const MAX_REDIRECTS: usize = 5;

const MAX_VALIDATOR_LEN: usize = 512;

/// Why a fetch failed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("unsupported location scheme (only http, https and file paths are allowed)")]
    UnsupportedScheme,
    #[error("invalid location")]
    InvalidLocation,
    #[error("target address is not public")]
    PrivateTarget,
    #[error("could not resolve host")]
    Resolve,
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("redirect refused")]
    BadRedirect,
    #[error("list exceeds the size limit")]
    TooLarge,
    #[error("timed out")]
    Timeout,
    #[error("server answered {0}")]
    Status(u16),
    #[error("request failed")]
    Http,
    #[error("reading file: {0}")]
    Io(#[from] std::io::Error),
}

/// Where a list comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    File(PathBuf),
    Url(Target),
}

impl Location {
    /// Classifies `s`: `http://` and `https://` are URLs, any other `scheme://` is refused and
    /// everything else is a file path. URLs are split by [`Target::parse`] (ASCII only, no
    /// user info).
    ///
    /// # Errors
    /// [`FetchError::UnsupportedScheme`] or [`FetchError::InvalidLocation`].
    pub fn parse(s: &str) -> Result<Location, FetchError> {
        let lower = s.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            Ok(Location::Url(Target::parse(s)?))
        } else if s.contains("://") {
            Err(FetchError::UnsupportedScheme)
        } else if s.is_empty() {
            Err(FetchError::InvalidLocation)
        } else {
            Ok(Location::File(PathBuf::from(s)))
        }
    }
}

/// Cache validators remembered from a previous successful fetch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Validators {
    fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

/// Result of a fetch.
#[derive(Debug)]
pub enum Fetched {
    /// The server confirmed the previous copy is current.
    NotModified,
    Body {
        bytes: Vec<u8>,
        validators: Validators,
    },
}

/// Fetches list sources. Cheap to clone.
#[derive(Clone)]
pub struct Fetcher {
    tls: Arc<rustls::ClientConfig>,
    max_bytes: u64,
    timeout: Duration,
    #[cfg(test)]
    dial: Option<SocketAddr>,
}

impl Default for Fetcher {
    fn default() -> Self {
        Self::new(MAX_LIST_BYTES, FETCH_TIMEOUT)
    }
}

impl Fetcher {
    /// A fetcher verifying server certificates against the webpki roots.
    ///
    /// # Panics
    /// Never in practice: the ring provider supports the default protocol versions.
    #[must_use]
    pub fn new(max_bytes: u64, timeout: Duration) -> Fetcher {
        Fetcher {
            tls: http::tls_config(http::webpki_roots()),
            max_bytes,
            timeout,
            #[cfg(test)]
            dial: None,
        }
    }

    /// A fetcher trusting only `roots`.
    #[cfg(test)]
    pub(crate) fn with_roots(
        roots: rustls::RootCertStore,
        max_bytes: u64,
        timeout: Duration,
    ) -> Fetcher {
        Fetcher {
            tls: http::tls_config(roots),
            ..Fetcher::new(max_bytes, timeout)
        }
    }

    /// Dials `addr` instead of the checked addresses (after the policy check passed), so a
    /// test can stand a local server in for a public host.
    #[cfg(test)]
    pub(crate) fn dial_instead(mut self, addr: SocketAddr) -> Fetcher {
        self.dial = Some(addr);
        self
    }

    /// Fetches `location`. `prior` are validators of a copy the caller still holds; pass `None`
    /// when it holds no copy, so a 304 can never be answered with nothing to keep.
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch(
        &self,
        location: &str,
        allow_private: bool,
        prior: Option<&Validators>,
    ) -> Result<Fetched, FetchError> {
        match Location::parse(location)? {
            Location::File(path) => self.read_file(path).await,
            Location::Url(url) => {
                tokio::time::timeout(self.timeout, self.fetch_url(url, allow_private, prior))
                    .await
                    .map_err(|_| FetchError::Timeout)?
            }
        }
    }

    async fn read_file(&self, path: PathBuf) -> Result<Fetched, FetchError> {
        let file = tokio::fs::File::open(path).await?;
        let meta = file.metadata().await?;
        if !meta.is_file() {
            return Err(FetchError::InvalidLocation);
        }
        if meta.len() > self.max_bytes {
            return Err(FetchError::TooLarge);
        }
        let mut bytes = Vec::new();
        file.take(self.max_bytes + 1)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(FetchError::TooLarge);
        }
        Ok(Fetched::Body {
            bytes,
            validators: Validators::default(),
        })
    }

    async fn fetch_url(
        &self,
        mut url: Target,
        allow_private: bool,
        prior: Option<&Validators>,
    ) -> Result<Fetched, FetchError> {
        let prior = prior.filter(|v| !v.is_empty());
        for _ in 0..=MAX_REDIRECTS {
            let addrs = resolve_checked(&url, allow_private).await?;
            #[cfg(test)]
            let addrs = self.dial.map_or(addrs, |a| vec![a]);
            let mut headers: Vec<(HeaderName, &str)> = Vec::new();
            if let Some(v) = prior {
                if let Some(e) = &v.etag {
                    headers.push((IF_NONE_MATCH, e));
                }
                if let Some(m) = &v.last_modified {
                    headers.push((IF_MODIFIED_SINCE, m));
                }
            }
            let mut exchange = http::send(&self.tls, &addrs, Method::GET, &url, &headers).await?;
            let resp = &mut exchange.response;
            let status = resp.status();
            if status.is_redirection() && status != StatusCode::NOT_MODIFIED {
                let next = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or(FetchError::BadRedirect)?;
                url = url.resolve_location(next)?;
                continue;
            }
            if status == StatusCode::NOT_MODIFIED && prior.is_some() {
                return Ok(Fetched::NotModified);
            }
            if status != StatusCode::OK {
                return Err(FetchError::Status(status.as_u16()));
            }
            let validators = Validators {
                etag: header_value(resp, &ETAG),
                last_modified: header_value(resp, &LAST_MODIFIED),
            };
            let bytes = http::read_body(resp, self.max_bytes).await?;
            return Ok(Fetched::Body { bytes, validators });
        }
        Err(FetchError::TooManyRedirects)
    }
}

pub(crate) fn header_value(resp: &Response<Incoming>, name: &HeaderName) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= MAX_VALIDATOR_LEN)
        .map(str::to_owned)
}

/// Resolves the URL's host and applies the SSRF policy to every address. The connection is
/// then dialled to exactly these addresses.
async fn resolve_checked(url: &Target, allow_private: bool) -> Result<Vec<SocketAddr>, FetchError> {
    let addrs = http::resolve(url).await?;
    if !allow_private && addrs.iter().any(|a| !is_public(a.ip())) {
        return Err(FetchError::PrivateTarget);
    }
    Ok(addrs)
}

/// True for globally routable unicast addresses; false for loopback, private, link-local,
/// unique-local, carrier-grade NAT, multicast, reserved and documentation ranges, and for IPv6
/// forms embedding such an IPv4 address (mapped, compatible, NAT64, 6to4).
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => public_v4(a),
        IpAddr::V6(a) => public_v6(a),
    }
}

fn public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18))
}

fn public_v6(addr: Ipv6Addr) -> bool {
    let seg = addr.segments();
    let embedded = |hi: u16, lo: u16| {
        let [b0, b1] = hi.to_be_bytes();
        let [b2, b3] = lo.to_be_bytes();
        public_v4(Ipv4Addr::new(b0, b1, b2, b3))
    };
    if addr.is_unspecified() || addr.is_loopback() || addr.is_multicast() {
        return false;
    }
    if (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80 || (seg[0] & 0xffc0) == 0xfec0 {
        return false;
    }
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return false;
    }
    if seg[..5] == [0; 5] && (seg[5] == 0 || seg[5] == 0xffff) {
        return embedded(seg[6], seg[7]);
    }
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0; 4] {
        return embedded(seg[6], seg[7]);
    }
    if seg[0] == 0x2002 {
        return embedded(seg[1], seg[2]);
    }
    true
}
