//! The optional `dnssec` block of a zone file.

use dnsy_dnssec::{MAX_NSEC3_ITERATIONS, RolloverTimings, SigningPolicy};
use serde::{Deserialize, Serialize};

use crate::model::ZoneError;

/// Longest propagation delay accepted (seven days).
const MAX_PROPAGATION_DELAY: u32 = 7 * 86_400;

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
    /// Seconds added to the DNSKEY TTL before a published key may sign: the time the new
    /// DNSKEY needs to reach every secondary and resolver.
    #[serde(default = "default_propagation_delay")]
    pub propagation_delay: u32,
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
fn default_propagation_delay() -> u32 {
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
        if self.propagation_delay > MAX_PROPAGATION_DELAY {
            return Err(invalid(format!(
                "dnssec.propagation_delay above {MAX_PROPAGATION_DELAY} seconds"
            )));
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

impl DnssecPolicy {
    /// The timing parameters of this zone's key rollovers.
    #[must_use]
    pub fn rollover_timings(&self) -> RolloverTimings {
        RolloverTimings {
            dnskey_ttl: self.dnskey_ttl,
            propagation: self.propagation_delay,
            max_signature_validity: self.signature_validity_days.saturating_mul(86_400),
        }
    }

    /// The policy as [`dnsy_dnssec::ZoneSigner`] takes it.
    ///
    /// # Errors
    /// The NSEC3 salt is not valid hex (cannot happen for a validated policy).
    pub fn signing_policy(&self) -> Result<SigningPolicy, ZoneError> {
        let denial = match self.denial {
            Denial::Nsec => dnsy_dnssec::Denial::Nsec,
            Denial::Nsec3 => dnsy_dnssec::Denial::Nsec3 {
                iterations: self.nsec3.iterations,
                salt: hex_decode(&self.nsec3.salt)
                    .ok_or_else(|| invalid("dnssec.nsec3.salt is not hex".into()))?,
                opt_out: self.nsec3.opt_out,
            },
        };
        Ok(SigningPolicy {
            denial,
            signature_validity_days: self.signature_validity_days,
            refresh_days: self.refresh_days,
            dnskey_ttl: self.dnskey_ttl,
        })
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
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
            r#"{"propagation_delay":604801}"#,
            r#"{"nsec3":{"salt":"zz"}}"#,
            r#"{"nsec3":{"salt":"abc"}}"#,
            r#"{"nsec3":{"iterations":5}}"#,
            r#"{"nsec3":{"iterations":101,"allow_nonzero_iterations":true}}"#,
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
    fn nsec3_iteration_cap_is_the_validator_cap() {
        let at = |n: u16| {
            policy(&format!(
                r#"{{"nsec3":{{"iterations":{n},"allow_nonzero_iterations":true}}}}"#
            ))
            .validate()
        };
        assert_eq!(MAX_NSEC3_ITERATIONS, 100);
        assert_eq!(
            dnsy_dnssec::ValidationLimits::default().max_nsec3_iterations,
            MAX_NSEC3_ITERATIONS
        );
        assert!(at(MAX_NSEC3_ITERATIONS).is_ok());
        assert!(at(MAX_NSEC3_ITERATIONS + 1).is_err());
        let src = include_str!("policy.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(!prod.contains("const MAX_NSEC3_ITERATIONS"));
    }

    #[test]
    fn converts_to_signing_policy() {
        let p = policy(r#"{"nsec3":{"salt":"aBff","opt_out":true},"dnskey_ttl":60}"#)
            .signing_policy()
            .unwrap();
        assert_eq!(
            p,
            SigningPolicy {
                denial: dnsy_dnssec::Denial::Nsec3 {
                    iterations: 0,
                    salt: vec![0xab, 0xff],
                    opt_out: true
                },
                signature_validity_days: 14,
                refresh_days: 5,
                dnskey_ttl: 60,
            }
        );
        let nsec = policy(r#"{"denial":"nsec"}"#).signing_policy().unwrap();
        assert_eq!(nsec.denial, dnsy_dnssec::Denial::Nsec);
        for bad in ["abc", "zz", "é1"] {
            let mut p = policy("{}");
            p.nsec3.salt = bad.into();
            assert!(p.signing_policy().is_err(), "{bad}");
        }
    }

    #[test]
    fn propagation_delay_defaults_and_feeds_the_rollover_timings() {
        let default = policy("{}");
        assert_eq!(default.propagation_delay, 3600);
        assert_eq!(default.rollover_timings().propagation, 3600);
        let custom = policy(
            r#"{"propagation_delay":120,"dnskey_ttl":60,"signature_validity_days":2,"refresh_days":1}"#,
        );
        assert!(custom.validate().is_ok());
        assert_eq!(
            custom.rollover_timings(),
            RolloverTimings {
                dnskey_ttl: 60,
                propagation: 120,
                max_signature_validity: 2 * 86_400,
            }
        );
        assert!(policy(r#"{"propagation_delay":0}"#).validate().is_ok());
        assert!(policy(r#"{"propagation_delay":604800}"#).validate().is_ok());
    }

    #[test]
    fn unknown_fields_rejected() {
        assert!(serde_json::from_str::<DnssecPolicy>(r#"{"bogus":1}"#).is_err());
    }
}
