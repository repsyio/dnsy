//! Cross-field validation.

use crate::ConfigError;
use crate::model::Config;

/// A parsed trust anchor DS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    /// Key tag.
    pub key_tag: u16,
    /// DNSSEC algorithm number.
    pub algorithm: u8,
    /// Digest type (1 SHA-1, 2 SHA-256, 4 SHA-384).
    pub digest_type: u8,
    /// Digest bytes.
    pub digest: Vec<u8>,
}

impl TrustAnchor {
    /// Parse `keytag algorithm digest-type digest-hex`.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] on a malformed record.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let bad = |why: &str| ConfigError::Invalid(format!("trust anchor `{text}`: {why}"));
        let mut parts = text.split_whitespace();
        let mut next = |what: &str| parts.next().ok_or_else(|| bad(&format!("missing {what}")));
        let key_tag = next("key tag")?
            .parse()
            .map_err(|_| bad("invalid key tag"))?;
        let algorithm = next("algorithm")?
            .parse()
            .map_err(|_| bad("invalid algorithm"))?;
        let digest_type: u8 = next("digest type")?
            .parse()
            .map_err(|_| bad("invalid digest type"))?;
        let hex = next("digest")?;
        if parts.next().is_some() {
            return Err(bad("trailing data"));
        }
        let digest = decode_hex(hex).ok_or_else(|| bad("digest is not hex"))?;
        let expected = match digest_type {
            1 => 20,
            2 => 32,
            4 => 48,
            _ => return Err(bad("unsupported digest type")),
        };
        if digest.len() != expected {
            return Err(bad("digest length does not match digest type"));
        }
        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn invalid(msg: &str) -> ConfigError {
    ConfigError::Invalid(msg.to_owned())
}

/// Non-fatal configuration problems.
pub(crate) fn warnings(c: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let public = c
        .dns
        .udp
        .iter()
        .chain(&c.dns.tcp)
        .chain(&c.dot.listen)
        .chain(&c.doh.listen)
        .find(|a| !a.ip().is_loopback());
    if let Some(addr) = public
        && c.limits.open_resolver
        && c.limits.per_client_qps == 0
    {
        out.push(format!(
            "listener {addr} is not loopback while limits.open_resolver = true and \
             limits.per_client_qps = 0: this is an open, unlimited resolver; set per_client_qps \
             or restrict clients with ACL rules"
        ));
    }
    out
}

pub(crate) fn validate(c: &Config) -> Result<(), ConfigError> {
    if !c.dot.listen.is_empty() {
        if c.dot.cert.is_none() || c.dot.key.is_none() {
            return Err(invalid(
                "dot.cert and dot.key are required when dot.listen is set",
            ));
        }
        if c.dot.mtls != crate::Mtls::Off && c.dot.client_ca.is_none() {
            return Err(invalid(
                "dot.client_ca is required when dot.mtls is optional or required",
            ));
        }
    }
    if !c.doh.listen.is_empty() && (c.doh.cert.is_none() || c.doh.key.is_none()) {
        return Err(invalid(
            "doh.cert and doh.key are required when doh.listen is set",
        ));
    }
    if !c.doh.path.starts_with('/') {
        return Err(invalid("doh.path must start with `/`"));
    }
    if c.api.tls_cert.is_some() != c.api.tls_key.is_some() {
        return Err(invalid("api.tls_cert and api.tls_key must be set together"));
    }
    if c.resolver.timeout_ms == 0 || c.resolver.attempts == 0 {
        return Err(invalid(
            "resolver.timeout_ms and resolver.attempts must be at least 1",
        ));
    }
    let cache = &c.cache;
    if cache.min_ttl > cache.max_ttl {
        return Err(invalid("cache.min_ttl must not exceed cache.max_ttl"));
    }
    if cache.max_entries == 0 {
        return Err(invalid("cache.max_entries must be at least 1"));
    }
    if !(1..=100).contains(&cache.prefetch.remaining_ttl_pct) {
        return Err(invalid(
            "cache.prefetch.remaining_ttl_pct must be between 1 and 100",
        ));
    }
    for anchor in &c.dnssec.trust_anchors {
        TrustAnchor::parse(anchor)?;
    }
    if c.dnssec.validation != crate::Validation::Off
        && c.dnssec.trust_anchors.is_empty()
        && c.dnssec.trust_anchor_file.is_none()
    {
        return Err(invalid(
            "dnssec validation needs trust_anchors or trust_anchor_file",
        ));
    }
    if c.filter.refresh_interval == 0 {
        return Err(invalid("filter.refresh_interval must be at least 1"));
    }
    Ok(())
}
