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

/// Integer codes stored in `query_log` (migration 0015). Fixed forever: changing one needs a
/// migration. The text names are the API and stats vocabulary.
pub(crate) const TRANSPORTS: [&str; 4] = ["udp", "tcp", "dot", "doh"];
pub(crate) const SOURCES: [&str; 7] = [
    "authoritative",
    "cache",
    "cache_stale",
    "upstream",
    "blocked",
    "refused",
    "error",
];
pub(crate) const DNSSEC: [&str; 5] = ["unchecked", "secure", "insecure", "bogus", "indeterminate"];

pub(crate) fn transport_code(t: Transport) -> u8 {
    match t {
        Transport::Udp => 0,
        Transport::Tcp => 1,
        Transport::Dot => 2,
        Transport::Doh => 3,
    }
}

/// Stats vocabulary name of a DNSSEC status.
pub(crate) fn dnssec_str(d: DnssecStatus) -> &'static str {
    DNSSEC[usize::from(dnssec_code(d))]
}

pub(crate) fn dnssec_code(d: DnssecStatus) -> u8 {
    match d {
        DnssecStatus::Unchecked => 0,
        DnssecStatus::Secure => 1,
        DnssecStatus::Insecure => 2,
        DnssecStatus::Bogus => 3,
        DnssecStatus::Indeterminate => 4,
    }
}

impl SourceKind {
    /// Stored integer code.
    pub(crate) fn code(self) -> u8 {
        match self {
            Self::Authoritative => 0,
            Self::Cache => 1,
            Self::CacheStale => 2,
            Self::Upstream => 3,
            Self::Blocked => 4,
            Self::Refused => 5,
            Self::Error => 6,
        }
    }
}

/// The stored bytes of a client address: 4 (IPv4) or 16 (IPv6), network order.
pub(crate) fn client_bytes(ip: &IpAddr, buf: &mut [u8; 16]) -> usize {
    match ip {
        IpAddr::V4(a) => {
            buf[..4].copy_from_slice(&a.octets());
            4
        }
        IpAddr::V6(a) => {
            *buf = a.octets();
            16
        }
    }
}

/// Inverse of [`client_bytes`]; `None` for any other length.
pub(crate) fn client_from_bytes(b: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(b) {
        Some(IpAddr::from(v4))
    } else {
        <[u8; 16]>::try_from(b).ok().map(IpAddr::from)
    }
}

/// The text name of a stored code, `None` when out of range.
pub(crate) fn name_of(table: &'static [&'static str], code: i64) -> Option<&'static str> {
    usize::try_from(code)
        .ok()
        .and_then(|i| table.get(i).copied())
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
    fn codes_map_to_the_stored_names() {
        for (i, name) in TRANSPORTS.iter().enumerate() {
            let t = [
                Transport::Udp,
                Transport::Tcp,
                Transport::Dot,
                Transport::Doh,
            ][i];
            assert_eq!(usize::from(transport_code(t)), i);
            assert_eq!(name_of(&TRANSPORTS, i64::try_from(i).unwrap()), Some(*name));
        }
        let kinds = [
            SourceKind::Authoritative,
            SourceKind::Cache,
            SourceKind::CacheStale,
            SourceKind::Upstream,
            SourceKind::Blocked,
            SourceKind::Refused,
            SourceKind::Error,
        ];
        for (i, k) in kinds.iter().enumerate() {
            assert_eq!(usize::from(k.code()), i);
            assert_eq!(SOURCES[i], k.as_str());
        }
        let st = [
            DnssecStatus::Unchecked,
            DnssecStatus::Secure,
            DnssecStatus::Insecure,
            DnssecStatus::Bogus,
            DnssecStatus::Indeterminate,
        ];
        for (i, d) in st.iter().enumerate() {
            assert_eq!(usize::from(dnssec_code(*d)), i);
        }
        assert_eq!(name_of(&SOURCES, 7), None);
        assert_eq!(name_of(&SOURCES, -1), None);
    }

    #[test]
    fn client_bytes_round_trip() {
        let mut buf = [0; 16];
        for s in ["192.0.2.77", "2001:db8:1::", "::ffff:192.0.2.1", "::"] {
            let ip: IpAddr = s.parse().unwrap();
            let n = client_bytes(&ip, &mut buf);
            assert_eq!(n, if ip.is_ipv4() { 4 } else { 16 });
            assert_eq!(client_from_bytes(&buf[..n]), Some(ip));
        }
        assert_eq!(client_from_bytes(&[1, 2, 3]), None);
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
