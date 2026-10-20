//! Trust anchors (RFC 4033 3, RFC 5011 terminology) and negative trust anchors (RFC 7646).

use dnsy_proto::{Dnskey, Ds, Name};

/// The points validation starts from: DS and/or DNSKEY anchors, plus negative trust anchors
/// below which validation is skipped and answers are reported `Insecure`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAnchors {
    ds: Vec<(Name, Ds)>,
    keys: Vec<(Name, Dnskey)>,
    negative: Vec<Name>,
}

impl TrustAnchors {
    /// An empty set: nothing can validate as `Secure`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a DS anchor for the zone `owner` (for the root, the IANA KSK DS records).
    pub fn add_ds(&mut self, owner: Name, ds: Ds) {
        self.ds.push((owner, ds));
    }

    /// Adds a DNSKEY anchor for the zone `owner`.
    pub fn add_dnskey(&mut self, owner: Name, key: Dnskey) {
        self.keys.push((owner, key));
    }

    /// Adds a negative trust anchor: names at or below `name` validate as `Insecure`.
    pub fn add_negative(&mut self, name: Name) {
        self.negative.push(name);
    }

    /// Replaces every negative trust anchor with `names`.
    pub fn set_negative(&mut self, names: impl IntoIterator<Item = Name>) {
        self.negative = names.into_iter().collect();
    }

    /// The DS anchors with the zone each belongs to.
    pub fn ds_anchors(&self) -> &[(Name, Ds)] {
        &self.ds
    }

    /// The DNSKEY anchors with the zone each belongs to.
    pub fn key_anchors(&self) -> &[(Name, Dnskey)] {
        &self.keys
    }

    /// The negative trust anchors.
    pub fn negative_anchors(&self) -> &[Name] {
        &self.negative
    }

    /// True when there is no positive (DS or DNSKEY) anchor.
    pub fn is_empty(&self) -> bool {
        self.ds.is_empty() && self.keys.is_empty()
    }

    /// True when `name` is at or below a negative trust anchor.
    pub fn is_negative(&self, name: &Name) -> bool {
        self.negative.iter().any(|n| name.is_subdomain_of(n))
    }

    /// The deepest positive anchor at or above `name`.
    pub fn closest(&self, name: &Name) -> Option<&Name> {
        self.ds
            .iter()
            .map(|(o, _)| o)
            .chain(self.keys.iter().map(|(o, _)| o))
            .filter(|o| name.is_subdomain_of(o))
            .max_by_key(|o| o.label_count())
    }

    pub(super) fn ds_at<'a>(&'a self, owner: &'a Name) -> impl Iterator<Item = &'a Ds> + 'a {
        self.ds
            .iter()
            .filter(move |(o, _)| o == owner)
            .map(|(_, d)| d)
    }

    pub(super) fn keys_at<'a>(&'a self, owner: &'a Name) -> impl Iterator<Item = &'a Dnskey> + 'a {
        self.keys
            .iter()
            .filter(move |(o, _)| o == owner)
            .map(|(_, k)| k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn ds() -> Ds {
        Ds {
            key_tag: 1,
            algorithm: 13,
            digest_type: 2,
            digest: vec![0; 32],
        }
    }

    #[test]
    fn closest_prefers_deepest_anchor() {
        let mut ta = TrustAnchors::new();
        assert!(ta.is_empty());
        assert_eq!(ta.closest(&n("example.")), None);
        ta.add_ds(Name::root(), ds());
        ta.add_dnskey(
            n("example."),
            Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 13,
                public_key: vec![1; 64],
            },
        );
        assert!(!ta.is_empty());
        assert_eq!(ta.closest(&n("www.example.")), Some(&n("example.")));
        assert_eq!(ta.closest(&n("www.other.")), Some(&Name::root()));
        assert_eq!(ta.ds_at(&Name::root()).count(), 1);
        assert_eq!(ta.keys_at(&n("example.")).count(), 1);
        assert_eq!(ta.keys_at(&Name::root()).count(), 0);
        assert_eq!(ta.ds_anchors().len(), 1);
        assert_eq!(ta.key_anchors().len(), 1);
        assert_eq!(ta.negative_anchors(), []);
    }

    #[test]
    fn negative_anchor_covers_subtree() {
        let mut ta = TrustAnchors::new();
        ta.add_negative(n("broken.example."));
        assert!(ta.is_negative(&n("broken.example.")));
        assert!(ta.is_negative(&n("a.BROKEN.example.")));
        assert!(!ta.is_negative(&n("example.")));
        assert!(ta.is_empty());
        ta.set_negative([n("other.test.")]);
        assert!(!ta.is_negative(&n("broken.example.")));
        assert!(ta.is_negative(&n("x.other.test.")));
        assert_eq!(ta.negative_anchors(), [n("other.test.")]);
    }
}
