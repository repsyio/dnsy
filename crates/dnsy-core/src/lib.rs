//! Shared vocabulary types for DNSY. No logic beyond small, total helpers.

use serde::{Deserialize, Serialize};

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

    #[cfg(test)]
    mod tests {
        use super::*;

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
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
}
