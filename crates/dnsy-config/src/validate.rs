//! Cross-field validation.

use crate::ConfigError;
use crate::model::Config;

/// Shape check of a trust anchor DS record: `keytag algorithm digest-type digest-hex`. The
/// fields themselves are parsed and checked by `dnsy_dnssec::TrustAnchor::parse` when the
/// policy is built and by `dnsy config check`.
fn check_anchor_shape(text: &str) -> Result<(), ConfigError> {
    if text.split_whitespace().count() == 4 {
        Ok(())
    } else {
        Err(invalid(&format!(
            "trust anchor `{text}`: expected `keytag algorithm digest-type digest-hex`"
        )))
    }
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
    if c.dot.client_crl.is_some() && (c.dot.mtls == crate::Mtls::Off || c.dot.listen.is_empty()) {
        return Err(invalid(
            "dot.client_crl needs dot.listen and dot.mtls set to optional or required",
        ));
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
    let l = &c.limits;
    if c.server.udp_sockets_per_address == 0
        || c.api.max_conns == 0
        || c.api.max_conns_per_client == 0
        || l.max_tcp_conns == 0
        || l.max_conns_per_client == 0
        || l.udp_in_flight == 0
        || l.udp_in_flight_per_client == 0
    {
        return Err(invalid(
            "server.udp_sockets_per_address, api.max_conns, api.max_conns_per_client, limits.max_tcp_conns, \
             limits.max_conns_per_client, limits.udp_in_flight and \
             limits.udp_in_flight_per_client must be at least 1",
        ));
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
        check_anchor_shape(anchor)?;
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
    for net in &c.filter.response_ip_blocklist {
        if net.parse::<ipnet::IpNet>().is_err() && net.parse::<std::net::IpAddr>().is_err() {
            return Err(invalid(&format!(
                "filter.response_ip_blocklist entry `{net}` is not an address or network"
            )));
        }
    }
    Ok(())
}
