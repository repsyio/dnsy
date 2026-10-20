//! The optional `dnssec` block of a zone file.

use serde::{Deserialize, Serialize};

use crate::model::ZoneError;

/// Highest NSEC3 iteration count accepted even with the override (RFC 9276 advises 0).
const MAX_NSEC3_ITERATIONS: u16 = 500;

/// Whether one key signs everything or keys are split into KSK and ZSK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyLayout {
    Csk,
    KskZsk,
}

/// Authenticated denial of existence mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Denial {
    Nsec,
    Nsec3,
}

/// NSEC3 parameters (RFC 5155, RFC 9276).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nsec3Params {
    #[serde(default)]
    pub iterations: u16,
    /// Salt in hexadecimal; empty for no salt.
    #[serde(default)]
    pub salt: String,
    #[serde(default)]
    pub opt_out: bool,
    /// Explicitly allow a non-zero iteration count (accepted with a warning).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_nonzero_iterations: bool,
}

/// Signing policy of a zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnssecPolicy {
    #[serde(default)]
    pub enabled: bool,
    /// 13 (ECDSAP256SHA256) or 15 (Ed25519).
    #[serde(default = "default_algorithm")]
    pub algorithm: u8,
    #[serde(default = "default_layout")]
    pub key_layout: KeyLayout,
    #[serde(default = "default_denial")]
    pub denial: Denial,
    #[serde(default)]
    pub nsec3: Nsec3Params,
    #[serde(default = "default_validity")]
    pub signature_validity_days: u32,
    #[serde(default = "default_refresh")]
    pub refresh_days: u32,
    #[serde(default = "default_dnskey_ttl")]
    pub dnskey_ttl: u32,
}

fn default_algorithm() -> u8 {
    13
}
fn default_layout() -> KeyLayout {
    KeyLayout::Csk
}
fn default_denial() -> Denial {
    Denial::Nsec3
}
fn default_validity() -> u32 {
    14
}
fn default_refresh() -> u32 {
    5
}
fn default_dnskey_ttl() -> u32 {
    3600
}

impl DnssecPolicy {
    /// Validates the policy; returns warnings for accepted but discouraged settings.
    pub(crate) fn validate(&self) -> Result<Vec<String>, ZoneError> {
        let mut warnings = Vec::new();
        if !matches!(self.algorithm, 13 | 15) {
            return Err(invalid(format!(
                "dnssec.algorithm {} unsupported (use 13 or 15)",
                self.algorithm
            )));
        }
        if self.signature_validity_days == 0 {
            return Err(invalid("dnssec.signature_validity_days must be > 0".into()));
        }
        if self.refresh_days == 0 || self.refresh_days >= self.signature_validity_days {
            return Err(invalid(
                "dnssec.refresh_days must be > 0 and below signature_validity_days".into(),
            ));
        }
        if self.dnskey_ttl == 0 {
            return Err(invalid("dnssec.dnskey_ttl must be > 0".into()));
        }
        let n = &self.nsec3;
        if n.salt.len() > 510
            || !n.salt.len().is_multiple_of(2)
            || !n.salt.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(invalid(
                "dnssec.nsec3.salt must be hex of at most 255 bytes".into(),
            ));
        }
        if n.iterations > 0 {
            if !n.allow_nonzero_iterations {
                return Err(invalid(
                    "dnssec.nsec3.iterations must be 0 (RFC 9276) unless allow_nonzero_iterations is set"
                        .into(),
                ));
            }
            if n.iterations > MAX_NSEC3_ITERATIONS {
                return Err(invalid(format!(
                    "dnssec.nsec3.iterations above {MAX_NSEC3_ITERATIONS}"
                )));
            }
            warnings.push(format!(
                "dnssec.nsec3.iterations {} is non-zero; RFC 9276 recommends 0",
                n.iterations
            ));
        }
        Ok(warnings)
    }
}

fn invalid(msg: String) -> ZoneError {
    ZoneError::Invalid(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> DnssecPolicy {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn dnssec_block_validated() {
        assert_eq!(policy("{}").validate().unwrap().len(), 0);
        let bad = [
            r#"{"algorithm":8}"#,
            r#"{"signature_validity_days":0}"#,
            r#"{"refresh_days":14}"#,
            r#"{"refresh_days":0}"#,
            r#"{"dnskey_ttl":0}"#,
            r#"{"nsec3":{"salt":"zz"}}"#,
            r#"{"nsec3":{"salt":"abc"}}"#,
            r#"{"nsec3":{"iterations":5}}"#,
            r#"{"nsec3":{"iterations":501,"allow_nonzero_iterations":true}}"#,
        ];
        for b in bad {
            assert!(policy(b).validate().is_err(), "{b}");
        }
        let ok = policy(
            r#"{"algorithm":15,"nsec3":{"iterations":5,"salt":"aabb","allow_nonzero_iterations":true}}"#,
        );
        let w = ok.validate().unwrap();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("non-zero"));
    }

    #[test]
    fn unknown_fields_rejected() {
        assert!(serde_json::from_str::<DnssecPolicy>(r#"{"bogus":1}"#).is_err());
    }
}
