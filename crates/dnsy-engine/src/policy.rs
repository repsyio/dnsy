//! [`LivePolicy`]: the policy a running engine lets the API change, as one trait.

use dnsy_config::BlockMode;
use dnsy_core::Validation;
use dnsy_filter::{AclAction, AclMatcher};
use dnsy_proto::Name;
use dnsy_resolver::groups::{Exchange, GroupError, GroupSet, GroupSpec};

use crate::engine::Engine;
use crate::response::ResponseIpPolicy;

/// A configured trust anchor, as shown (read-only) by `GET /settings/dnssec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchorInfo {
    /// Zone the anchor belongs to (`.` for the root).
    pub owner: String,
    pub key_tag: u16,
    pub algorithm: u8,
    /// Digest type for a DS anchor; `None` for a DNSKEY anchor.
    pub digest_type: Option<u8>,
    /// Upper-case hex digest of a DS anchor.
    pub digest: Option<String>,
}

/// What can change while the server runs: ACL, rate limit, block mode, response-IP policy,
/// upstream groups, DNSSEC mode and negative trust anchors. Changing the DNSSEC mode or the
/// negative trust anchors flushes the resolver cache, whose entries carry statuses computed
/// under the old settings.
pub trait LivePolicy: Send + Sync {
    /// Rebuilds the ACL from `rules` on top of the base ACL and swaps it in.
    fn apply_acl_rules(&self, rules: Vec<(AclMatcher, AclAction)>);
    /// Replaces the rate limiter (`qps == 0` disables limiting).
    fn set_rate_limit(&self, qps: u32);
    fn set_block_mode(&self, mode: BlockMode);
    fn set_response_ip_policy(&self, policy: ResponseIpPolicy);
    /// Validates `specs` and swaps them in as the upstream groups; an empty list leaves the
    /// server without upstreams.
    ///
    /// # Errors
    /// Invalid group definitions; nothing changes.
    fn replace_groups(&self, specs: Vec<GroupSpec>) -> Result<(), GroupError>;
    fn dnssec_mode(&self) -> Validation;
    fn set_dnssec_mode(&self, mode: Validation);
    /// The negative trust anchors with their expiry (Unix seconds), expired ones included.
    fn negative_trust_anchors(&self) -> Vec<(Name, Option<u32>)>;
    fn set_negative_trust_anchors(&self, entries: Vec<(Name, Option<u32>)>);
    fn trust_anchors(&self) -> Vec<TrustAnchorInfo>;
    /// True while the system clock is before the build time (validation suspended).
    fn dnssec_clock_untrusted(&self) -> bool;
}

/// Upper-case hexadecimal.
#[must_use]
pub fn hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

impl<E: Exchange + 'static> LivePolicy for Engine<E> {
    fn apply_acl_rules(&self, rules: Vec<(AclMatcher, AclAction)>) {
        let acl = Engine::acl(self).with_rules(rules);
        Engine::set_acl(self, acl);
    }

    fn set_rate_limit(&self, qps: u32) {
        Engine::set_rate_limit(self, qps);
    }

    fn set_block_mode(&self, mode: BlockMode) {
        Engine::set_block_mode(self, mode);
    }

    fn set_response_ip_policy(&self, policy: ResponseIpPolicy) {
        Engine::set_response_ip_policy(self, policy);
    }

    fn replace_groups(&self, specs: Vec<GroupSpec>) -> Result<(), GroupError> {
        let set = if specs.is_empty() {
            None
        } else {
            Some(GroupSet::from_specs(specs)?)
        };
        Engine::set_groups(self, set);
        Ok(())
    }

    fn dnssec_mode(&self) -> Validation {
        Engine::dnssec_mode(self)
    }

    fn set_dnssec_mode(&self, mode: Validation) {
        Engine::set_dnssec_mode(self, mode);
    }

    fn negative_trust_anchors(&self) -> Vec<(Name, Option<u32>)> {
        self.dnssec_policy()
            .validator
            .anchors()
            .negative_entries()
            .to_vec()
    }

    fn set_negative_trust_anchors(&self, entries: Vec<(Name, Option<u32>)>) {
        self.set_negative_trust_anchor_entries(entries);
    }

    fn trust_anchors(&self) -> Vec<TrustAnchorInfo> {
        let policy = self.dnssec_policy();
        let anchors = policy.validator.anchors();
        let ds = anchors
            .ds_anchors()
            .iter()
            .map(|(owner, ds)| TrustAnchorInfo {
                owner: owner.to_string(),
                key_tag: ds.key_tag,
                algorithm: ds.algorithm,
                digest_type: Some(ds.digest_type),
                digest: Some(hex_upper(&ds.digest)),
            });
        let keys = anchors
            .key_anchors()
            .iter()
            .map(|(owner, key)| TrustAnchorInfo {
                owner: owner.to_string(),
                key_tag: key.key_tag(),
                algorithm: key.algorithm,
                digest_type: None,
                digest: None,
            });
        ds.chain(keys).collect()
    }

    fn dnssec_clock_untrusted(&self) -> bool {
        Engine::dnssec_clock_untrusted(self)
    }
}
