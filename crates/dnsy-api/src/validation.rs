//! Run-time control of DNSSEC validation, implemented by the engine.

use std::fmt::Write as _;

use dnsy_config::Validation;
use dnsy_engine::Engine;
use dnsy_proto::Name;
use dnsy_resolver::groups::Exchange;

/// Upper-case hexadecimal.
pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

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

/// What the API may change while the server runs. Changing the mode or the negative trust
/// anchors flushes the resolver cache, whose entries carry statuses computed under the old
/// settings.
pub trait ValidationControl: Send + Sync {
    fn mode(&self) -> Validation;
    fn set_mode(&self, mode: Validation);
    fn negative_trust_anchors(&self) -> Vec<Name>;
    fn set_negative_trust_anchors(&self, names: Vec<Name>);
    fn trust_anchors(&self) -> Vec<TrustAnchorInfo>;
}

impl<E: Exchange + 'static> ValidationControl for Engine<E> {
    fn mode(&self) -> Validation {
        self.dnssec_mode()
    }

    fn set_mode(&self, mode: Validation) {
        self.set_dnssec_mode(mode);
    }

    fn negative_trust_anchors(&self) -> Vec<Name> {
        self.dnssec_policy()
            .validator
            .anchors()
            .negative_anchors()
            .to_vec()
    }

    fn set_negative_trust_anchors(&self, names: Vec<Name>) {
        self.set_negative_trust_anchors(names);
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
}
