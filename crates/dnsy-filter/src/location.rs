//! Where a list comes from: a local file or an `http(s)` URL split into the parts a request
//! needs. Parsing only; dialling lives in the `fetch` feature.
//!
//! URLs are split by hand ([`Target`]): ASCII only (internationalised host names are not
//! supported; use the punycode `xn--` form), no user info, IPv6 literals in brackets. A host
//! ending in a numeric label is an IPv4 address read as browsers and the WHATWG URL standard
//! read it (`127.1`, `0x7f.0.0.1` and `2130706433` are all `127.0.0.1`), so the address policy
//! sees the address that is actually dialled; a malformed one is refused.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

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

    #[cfg(feature = "fetch")]
    pub(crate) fn host_header(&self) -> String {
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
/// literal in the WHATWG forms.
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
    let ip = whatwg_ipv4(bare).ok_or(FetchError::InvalidLocation)?;
    Ok((ip.to_string(), Some(IpAddr::V4(ip))))
}

/// The WHATWG IPv4 parser: one to four parts, each decimal, octal (leading `0`) or hex (`0x`);
/// all but the last part are one byte, the last fills the remaining bytes.
fn whatwg_ipv4(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let mut numbers = Vec::with_capacity(parts.len());
    for part in &parts {
        if part.is_empty() {
            return None;
        }
        let (digits, radix) = if let Some(hex) = part.strip_prefix("0x") {
            (hex, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (&part[1..], 8)
        } else {
            (*part, 10)
        };
        let n = if digits.is_empty() {
            0
        } else {
            u64::from_str_radix(digits, radix).ok()?
        };
        numbers.push(n);
    }
    let (last, init) = numbers.split_last()?;
    if init.iter().any(|&n| n > 255) {
        return None;
    }
    let free_bits = 8 * (5 - numbers.len());
    if *last >= 1 << free_bits {
        return None;
    }
    let mut value = *last;
    for (i, &n) in init.iter().enumerate() {
        value += n << (8 * (3 - i));
    }
    u32::try_from(value).ok().map(Ipv4Addr::from)
}
