//! Upstream addressing: `udp://host[:port]`, `tcp://host[:port]`, `tls://host[:port][#sni]`.

use std::fmt;
use std::str::FromStr;

use crate::upstream::UpstreamError;

/// Transport used to reach an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamTransport {
    Udp,
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
}

/// A single upstream resolver.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Upstream {
    pub transport: UpstreamTransport,
    /// IP literal or host name (resolved at connect time).
    pub host: String,
    pub port: u16,
    /// TLS server name to verify; defaults to `host`.
    pub sni: Option<String>,
}

impl Upstream {
    /// The name the server certificate must be valid for.
    #[must_use]
    pub fn server_name(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.host)
    }
}

impl FromStr for Upstream {
    type Err = UpstreamError;

    fn from_str(s: &str) -> Result<Self, UpstreamError> {
        let bad = || UpstreamError::InvalidUpstream(s.to_owned());
        let (scheme, rest) = s.split_once("://").ok_or_else(bad)?;
        let (transport, default_port) = match scheme {
            "udp" => (UpstreamTransport::Udp, 53),
            "tcp" => (UpstreamTransport::Tcp, 53),
            "tls" => (UpstreamTransport::Tls, 853),
            _ => return Err(bad()),
        };
        let (authority, sni) = match rest.split_once('#') {
            Some((a, f)) if transport == UpstreamTransport::Tls && !f.is_empty() => {
                (a, Some(f.to_owned()))
            }
            Some(_) => return Err(bad()),
            None => (rest, None),
        };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (host, tail) = v6.split_once(']').ok_or_else(bad)?;
            match tail {
                "" => (host, default_port),
                _ => (
                    host,
                    tail.strip_prefix(':')
                        .and_then(|p| p.parse().ok())
                        .ok_or_else(bad)?,
                ),
            }
        } else if let Some((host, port)) = authority.split_once(':') {
            (host, port.parse().map_err(|_| bad())?)
        } else {
            (authority, default_port)
        };
        if host.is_empty() || port == 0 || host.contains(['/', '#', ' ']) {
            return Err(bad());
        }
        Ok(Self {
            transport,
            host: host.to_owned(),
            port,
            sni,
        })
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.transport {
            UpstreamTransport::Udp => "udp",
            UpstreamTransport::Tcp => "tcp",
            UpstreamTransport::Tls => "tls",
        };
        if self.host.contains(':') {
            write!(f, "{scheme}://[{}]:{}", self.host, self.port)?;
        } else {
            write!(f, "{scheme}://{}:{}", self.host, self.port)?;
        }
        if let Some(sni) = &self.sni {
            write!(f, "#{sni}")?;
        }
        Ok(())
    }
}
