use std::net::{IpAddr, SocketAddr};

use dnsy_core::{DnssecStatus, Transport};
use dnsy_proto::{Name, Rcode, RecordType};

/// Where an answer came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerSource {
    Authoritative,
    Cache,
    CacheStale,
    Upstream(SocketAddr),
    Blocked { list: String },
    Refused,
    Error,
}

/// The coarse answer source, as stored and filtered on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Authoritative,
    Cache,
    CacheStale,
    Upstream,
    Blocked,
    Refused,
    Error,
}

impl SourceKind {
    /// Stable storage/API name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authoritative => "authoritative",
            Self::Cache => "cache",
            Self::CacheStale => "cache_stale",
            Self::Upstream => "upstream",
            Self::Blocked => "blocked",
            Self::Refused => "refused",
            Self::Error => "error",
        }
    }
}

impl AnswerSource {
    #[must_use]
    pub fn kind(&self) -> SourceKind {
        match self {
            Self::Authoritative => SourceKind::Authoritative,
            Self::Cache => SourceKind::Cache,
            Self::CacheStale => SourceKind::CacheStale,
            Self::Upstream(_) => SourceKind::Upstream,
            Self::Blocked { .. } => SourceKind::Blocked,
            Self::Refused => SourceKind::Refused,
            Self::Error => SourceKind::Error,
        }
    }

    /// Upstream address or blocklist name.
    pub(crate) fn detail(&self) -> Option<String> {
        match self {
            Self::Upstream(a) => Some(a.to_string()),
            Self::Blocked { list } => Some(list.clone()),
            _ => None,
        }
    }
}

/// One answered query.
#[derive(Debug, Clone)]
pub struct QueryEvent {
    pub ts_unix_ms: i64,
    pub client: IpAddr,
    pub transport: Transport,
    pub principal: Option<String>,
    pub qname: Name,
    pub qtype: RecordType,
    pub rcode: Rcode,
    pub source: AnswerSource,
    pub dnssec: DnssecStatus,
    pub latency_us: u32,
}

/// Receiver of query events. Must never block the caller; implementations drop
/// and count when they cannot keep up.
pub trait QueryEventSink: Send + Sync {
    fn record(&self, ev: QueryEvent);
}

/// Truncate a client address to its /24 (IPv4) or /48 (IPv6) network address.
#[must_use]
pub fn redact_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            IpAddr::from([a, b, c, 0])
        }
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[6..].fill(0);
            IpAddr::from(o)
        }
    }
}

pub(crate) fn transport_str(t: Transport) -> &'static str {
    match t {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
        Transport::Dot => "dot",
        Transport::Doh => "doh",
    }
}

pub(crate) fn dnssec_str(d: DnssecStatus) -> &'static str {
    match d {
        DnssecStatus::Unchecked => "unchecked",
        DnssecStatus::Secure => "secure",
        DnssecStatus::Insecure => "insecure",
        DnssecStatus::Bogus => "bogus",
        DnssecStatus::Indeterminate => "indeterminate",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_redaction() {
        let v4: IpAddr = "192.0.2.77".parse().unwrap();
        assert_eq!(redact_client_ip(v4), "192.0.2.0".parse::<IpAddr>().unwrap());
        let v6: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        assert_eq!(
            redact_client_ip(v6),
            "2001:db8:1::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn source_kind_and_detail() {
        let up = AnswerSource::Upstream("192.0.2.1:53".parse().unwrap());
        assert_eq!(up.kind().as_str(), "upstream");
        assert_eq!(up.detail().as_deref(), Some("192.0.2.1:53"));
        let b = AnswerSource::Blocked { list: "ads".into() };
        assert_eq!(b.kind().as_str(), "blocked");
        assert_eq!(b.detail().as_deref(), Some("ads"));
        for (s, k) in [
            (AnswerSource::Authoritative, "authoritative"),
            (AnswerSource::Cache, "cache"),
            (AnswerSource::CacheStale, "cache_stale"),
            (AnswerSource::Refused, "refused"),
            (AnswerSource::Error, "error"),
        ] {
            assert_eq!(s.kind().as_str(), k);
            assert_eq!(s.detail(), None);
        }
    }
}
