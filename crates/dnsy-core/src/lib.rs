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
