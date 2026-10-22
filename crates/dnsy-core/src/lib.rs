//! Shared vocabulary types for DNSY. No logic beyond small, total helpers.

mod clock;

#[cfg(feature = "test-util")]
pub use clock::ManualClock;
pub use clock::{Clock, SystemClock};

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

mod key;

pub use key::{KeyRole, KeyState};

/// Transport a DNS request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
    Dot,
    Doh,
}

/// Database id of a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub i64);

/// Database id of an API token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenId(pub i64);

/// Who made a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    Token { token: TokenId, user: UserId },
    ClientCert { sha256: [u8; 32], subject: String },
}

/// User role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

/// Permission scope carried by a token or granted by a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    #[serde(rename = "dns:query")]
    DnsQuery,
    #[serde(rename = "api:read")]
    ApiRead,
    #[serde(rename = "api:write")]
    ApiWrite,
    #[serde(rename = "admin")]
    Admin,
}

impl Role {
    /// Whether this role is allowed to exercise `scope`.
    #[must_use]
    pub fn allows(self, scope: Scope) -> bool {
        match self {
            Role::Admin => true,
            Role::Operator => matches!(scope, Scope::ApiRead | Scope::ApiWrite | Scope::DnsQuery),
            Role::Viewer => matches!(scope, Scope::ApiRead),
        }
    }
}

/// DNSSEC validation outcome (RFC 4035 section 4.3) plus `Unchecked`
/// (validation off, CD=1, or locally generated answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnssecStatus {
    Unchecked,
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

/// Network vocabulary shared by every per-client limit.
pub mod net {
    use std::net::{IpAddr, Ipv6Addr};

    pub use ipnet::IpNet;

    /// Key under which per-client state is held: an IPv4 address as `/32`, an IPv6 address as its
    /// `/64` (one subscriber owns a whole `/64`, so per-address keys would be trivially bypassed).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct ClientKey(IpAddr);

    impl ClientKey {
        /// The canonical address (IPv6 with the low 64 bits zeroed).
        #[must_use]
        pub fn ip(self) -> IpAddr {
            self.0
        }
    }

    impl std::fmt::Display for ClientKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }

    /// Client key of `ip`. IPv4-mapped IPv6 addresses count as IPv4.
    #[must_use]
    pub fn client_key(ip: IpAddr) -> ClientKey {
        ClientKey(match ip.to_canonical() {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
        })
    }

    /// Most trusted hops [`forwarded_client`] skips before giving up.
    pub const MAX_TRUSTED_HOPS: usize = 16;

    /// The key of a request from a trusted proxy that names no usable client: no
    /// `X-Forwarded-For`, every entry a trusted proxy, more than [`MAX_TRUSTED_HOPS`] trusted
    /// entries, or a malformed entry reached on the walk. The unspecified address `0.0.0.0` is
    /// never a real peer, so it carries no ACL `allow`, no private-network trust and no
    /// per-client allowance of the proxy itself; all such requests share one bucket.
    pub const UNKNOWN_FORWARDED: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

    /// Whether `ip` (IPv4-mapped IPv6 counted as IPv4) lies inside one of `trusted`.
    #[must_use]
    pub fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
        let ip = ip.to_canonical();
        trusted.iter().any(|net| net.contains(&ip))
    }

    /// The client address of a request that arrived from `peer` carrying the `X-Forwarded-For`
    /// header instances `xff` (in order), given the proxies listed in `trusted`.
    ///
    /// - `peer` not trusted: `peer`; the header is ignored entirely.
    /// - Otherwise the instances are walked right to left (last instance first, each split on
    ///   `,`); entries inside `trusted` are skipped and the first entry outside it is the client.
    ///   Entries left of the client are never looked at, so a client-supplied prefix cannot
    ///   affect the result.
    /// - A reached entry that is not a bare IPv4/IPv6 address or a `[v6]` literal (a port suffix,
    ///   a hostname, an empty entry), more than [`MAX_TRUSTED_HOPS`] trusted entries, no header,
    ///   or every entry trusted: [`UNKNOWN_FORWARDED`]. A trusted peer never gets its own address
    ///   back, so nothing a request does can borrow the proxy's identity.
    #[must_use]
    pub fn forwarded_client<'a>(
        peer: IpAddr,
        xff: impl DoubleEndedIterator<Item = &'a str>,
        trusted: &[IpNet],
    ) -> IpAddr {
        if !is_trusted(peer, trusted) {
            return peer;
        }
        let mut hops = 0usize;
        for entry in xff.rev().flat_map(|value| value.rsplit(',')) {
            let Some(ip) = parse_forwarded_entry(entry.trim()) else {
                return UNKNOWN_FORWARDED;
            };
            if !is_trusted(ip, trusted) {
                return ip.to_canonical();
            }
            hops += 1;
            if hops >= MAX_TRUSTED_HOPS {
                return UNKNOWN_FORWARDED;
            }
        }
        UNKNOWN_FORWARDED
    }

    fn parse_forwarded_entry(entry: &str) -> Option<IpAddr> {
        if let Some(inner) = entry.strip_prefix('[').and_then(|e| e.strip_suffix(']')) {
            return inner.parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6);
        }
        entry.parse().ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        #[test]
        fn forwarded_client_rules() {
            let trusted: Vec<IpNet> =
                vec!["10.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()];
            let proxy = ip("10.0.0.1");
            let unknown = "0.0.0.0";
            let cases: &[(&str, IpAddr, &[&str], &str)] = &[
                (
                    "untrusted peer ignores header",
                    ip("198.51.100.7"),
                    &["203.0.113.9"],
                    "198.51.100.7",
                ),
                (
                    "rightmost untrusted",
                    proxy,
                    &["1.1.1.1, 203.0.113.9"],
                    "203.0.113.9",
                ),
                (
                    "two trusted hops skipped",
                    proxy,
                    &["203.0.113.9, 10.1.1.1, 10.2.2.2"],
                    "203.0.113.9",
                ),
                ("all trusted", proxy, &["10.1.1.1, 10.2.2.2"], unknown),
                ("no header", proxy, &[], unknown),
                (
                    "garbage reached",
                    proxy,
                    &["203.0.113.9, evil.example"],
                    unknown,
                ),
                (
                    "garbage left of the client ignored",
                    proxy,
                    &["evil.example, 203.0.113.9"],
                    "203.0.113.9",
                ),
                ("empty entry reached", proxy, &["203.0.113.9, "], unknown),
                ("bracketed v6", proxy, &["[2001:db8::5]"], "2001:db8::5"),
                ("bare v6", proxy, &["2001:db8::5"], "2001:db8::5"),
                ("port suffix", proxy, &["1.2.3.4:80"], unknown),
                ("v6 with port", proxy, &["[2001:db8::5]:443"], unknown),
                (
                    "two instances joined",
                    proxy,
                    &["203.0.113.1", "203.0.113.9"],
                    "203.0.113.9",
                ),
                (
                    "second instance trusted",
                    proxy,
                    &["203.0.113.1", "10.3.3.3"],
                    "203.0.113.1",
                ),
                (
                    "mapped peer is trusted",
                    ip("::ffff:10.0.0.1"),
                    &["203.0.113.9"],
                    "203.0.113.9",
                ),
                (
                    "mapped entry unmapped",
                    proxy,
                    &["::ffff:203.0.113.9"],
                    "203.0.113.9",
                ),
                ("v6 proxy", ip("::1"), &["203.0.113.9"], "203.0.113.9"),
                ("proxy names itself", proxy, &["10.0.0.1"], unknown),
            ];
            for (name, peer, xff, want) in cases {
                let got = forwarded_client(*peer, xff.iter().copied(), &trusted);
                assert_eq!(got, ip(want), "{name}");
            }
            // A long client-supplied prefix does not matter: only the reached entries count.
            let padded = format!("{}, 203.0.113.9", vec!["evil"; 5000].join(","));
            assert_eq!(
                forwarded_client(proxy, [padded.as_str()].into_iter(), &trusted),
                ip("203.0.113.9")
            );
            // Trusted hops are capped.
            let hops = |n: usize| format!("203.0.113.9, {}", vec!["10.9.9.9"; n].join(", "));
            let fifteen = hops(15);
            assert_eq!(
                forwarded_client(proxy, [fifteen.as_str()].into_iter(), &trusted),
                ip("203.0.113.9")
            );
            let sixteen = hops(16);
            assert_eq!(
                forwarded_client(proxy, [sixteen.as_str()].into_iter(), &trusted),
                UNKNOWN_FORWARDED
            );
            assert_eq!(
                forwarded_client(proxy, ["203.0.113.9"].into_iter(), &[]),
                proxy
            );
        }

        #[test]
        fn client_key_groups_ipv6_by_64() {
            assert_eq!(
                client_key(ip("2001:db8:0:1:ffff::3")).ip(),
                ip("2001:db8:0:1::")
            );
            assert_eq!(
                client_key(ip("2001:db8:0:1::1")),
                client_key(ip("2001:db8:0:1:aaaa::2"))
            );
            assert_ne!(
                client_key(ip("2001:db8:0:1::1")),
                client_key(ip("2001:db8:0:2::1"))
            );
        }

        #[test]
        fn client_key_keeps_ipv4_and_unmaps_mapped() {
            assert_eq!(client_key(ip("192.0.2.9")).ip(), ip("192.0.2.9"));
            assert_eq!(client_key(ip("::ffff:192.0.2.9")).ip(), ip("192.0.2.9"));
            assert_eq!(client_key(ip("192.0.2.9")).to_string(), "192.0.2.9");
        }
    }
}

/// DNSSEC validation mode. The serde strings are the `[dnssec] validation` config values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Validation {
    /// No validation.
    Off,
    /// Validate; Bogus answers are returned without AD.
    Permissive,
    /// Validate; Bogus answers become SERVFAIL.
    #[default]
    Strict,
}

/// How a blocked query is answered. The serde strings are the `[filter] block_mode` config values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// NXDOMAIN.
    #[serde(rename = "nxdomain")]
    NxDomain,
    /// `0.0.0.0` for A and `::` for AAAA.
    #[default]
    NullIp,
    /// REFUSED.
    Refused,
    /// Operator chosen sinkhole addresses; a family without an address answers NODATA. Set by
    /// code, not by configuration.
    #[serde(skip_deserializing)]
    CustomIp {
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCOPES: [(Scope, &str); 4] = [
        (Scope::DnsQuery, "\"dns:query\""),
        (Scope::ApiRead, "\"api:read\""),
        (Scope::ApiWrite, "\"api:write\""),
        (Scope::Admin, "\"admin\""),
    ];

    #[test]
    fn scope_serde_roundtrip() {
        for (scope, json) in SCOPES {
            assert_eq!(serde_json::to_string(&scope).unwrap(), json);
            assert_eq!(serde_json::from_str::<Scope>(json).unwrap(), scope);
        }
        assert!(serde_json::from_str::<Scope>("\"root\"").is_err());
    }

    #[test]
    fn role_allows_scope() {
        for (scope, _) in SCOPES {
            assert!(Role::Admin.allows(scope));
            assert_eq!(Role::Viewer.allows(scope), scope == Scope::ApiRead);
            assert_eq!(Role::Operator.allows(scope), scope != Scope::Admin);
        }
    }

    #[test]
    fn dnssec_status_serde() {
        let all = [
            (DnssecStatus::Secure, "\"secure\""),
            (DnssecStatus::Insecure, "\"insecure\""),
            (DnssecStatus::Bogus, "\"bogus\""),
            (DnssecStatus::Indeterminate, "\"indeterminate\""),
            (DnssecStatus::Unchecked, "\"unchecked\""),
        ];
        for (status, json) in all {
            assert_eq!(serde_json::to_string(&status).unwrap(), json);
            assert_eq!(serde_json::from_str::<DnssecStatus>(json).unwrap(), status);
        }
    }

    #[test]
    fn ids_and_enums_serde() {
        assert_eq!(serde_json::to_string(&UserId(7)).unwrap(), "7");
        assert_eq!(serde_json::to_string(&TokenId(9)).unwrap(), "9");
        assert_eq!(serde_json::to_string(&Transport::Doh).unwrap(), "\"doh\"");
        assert_eq!(serde_json::to_string(&Role::Viewer).unwrap(), "\"viewer\"");
        let p = Principal::ClientCert {
            sha256: [0; 32],
            subject: "CN=a".into(),
        };
        assert_eq!(p.clone(), p);
    }

    #[test]
    fn validation_and_block_mode_serde_strings_are_pinned() {
        for (v, text) in [
            (Validation::Off, "\"off\""),
            (Validation::Permissive, "\"permissive\""),
            (Validation::Strict, "\"strict\""),
        ] {
            assert_eq!(serde_json::to_string(&v).unwrap(), text);
            assert_eq!(serde_json::from_str::<Validation>(text).unwrap(), v);
        }
        for (m, text) in [
            (BlockMode::NullIp, "\"null_ip\""),
            (BlockMode::NxDomain, "\"nxdomain\""),
            (BlockMode::Refused, "\"refused\""),
        ] {
            assert_eq!(serde_json::to_string(&m).unwrap(), text);
            assert_eq!(serde_json::from_str::<BlockMode>(text).unwrap(), m);
        }
        assert_eq!(Validation::default(), Validation::Strict);
        assert_eq!(BlockMode::default(), BlockMode::NullIp);
    }
}
