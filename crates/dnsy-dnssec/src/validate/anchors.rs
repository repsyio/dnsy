//! Trust anchors (RFC 4033 3, RFC 5011 terminology) and negative trust anchors (RFC 7646).

use dnsy_proto::{Dnskey, Ds, Name};

/// The points validation starts from: DS and/or DNSKEY anchors, plus negative trust anchors
/// below which validation is skipped and answers are reported `Insecure`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAnchors {
    ds: Vec<(Name, Ds)>,
    keys: Vec<(Name, Dnskey)>,
    /// Negative trust anchors with their optional expiry (Unix seconds).
    negative: Vec<(Name, Option<u32>)>,
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
        self.negative.push((name, None));
    }

    /// Adds a negative trust anchor that stops applying at `expires_at` (Unix seconds).
    pub fn add_negative_until(&mut self, name: Name, expires_at: u32) {
        self.negative.push((name, Some(expires_at)));
    }

    /// Replaces every negative trust anchor with `names`, none of which expires.
    pub fn set_negative(&mut self, names: impl IntoIterator<Item = Name>) {
        self.negative = names.into_iter().map(|n| (n, None)).collect();
    }

    /// Replaces every negative trust anchor with `entries` (name and optional expiry).
    pub fn set_negative_entries(&mut self, entries: impl IntoIterator<Item = (Name, Option<u32>)>) {
        self.negative = entries.into_iter().collect();
    }

    /// The DS anchors with the zone each belongs to.
    pub fn ds_anchors(&self) -> &[(Name, Ds)] {
        &self.ds
    }

    /// The DNSKEY anchors with the zone each belongs to.
    pub fn key_anchors(&self) -> &[(Name, Dnskey)] {
        &self.keys
    }

    /// The names of the negative trust anchors, expired ones included.
    pub fn negative_anchors(&self) -> Vec<Name> {
        self.negative.iter().map(|(n, _)| n.clone()).collect()
    }

    /// The negative trust anchors with their expiry (Unix seconds), expired ones included.
    pub fn negative_entries(&self) -> &[(Name, Option<u32>)] {
        &self.negative
    }

    /// True when there is no positive (DS or DNSKEY) anchor.
    pub fn is_empty(&self) -> bool {
        self.ds.is_empty() && self.keys.is_empty()
    }

    /// True when `name` is at or below a negative trust anchor that has not expired at `now`
    /// (Unix seconds).
    pub fn is_negative(&self, name: &Name, now: u32) -> bool {
        self.negative_ttl(name, now).is_some()
    }

    /// For a `name` at or below an unexpired negative trust anchor: `Some(cap)`, where `cap`
    /// is how many seconds an answer treated as insecure because of it may be cached (the
    /// time left of the longest-lived matching anchor), or `None` when an anchor without
    /// expiry applies. `None` overall means no anchor applies.
    pub fn negative_ttl(&self, name: &Name, now: u32) -> Option<Option<u32>> {
        let mut longest: Option<u32> = None;
        for (n, expires) in &self.negative {
            if !name.is_subdomain_of(n) {
                continue;
            }
            match expires {
                None => return Some(None),
                Some(e) if now < *e => {
                    longest = Some(longest.map_or(*e - now, |l| l.max(*e - now)));
                }
                Some(_) => {}
            }
        }
        longest.map(Some)
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
        assert!(ta.is_negative(&n("broken.example."), 0));
        assert!(ta.is_negative(&n("a.BROKEN.example."), u32::MAX));
        assert!(!ta.is_negative(&n("example."), 0));
        assert!(ta.is_empty());
        ta.set_negative([n("other.test.")]);
        assert!(!ta.is_negative(&n("broken.example."), 0));
        assert!(ta.is_negative(&n("x.other.test."), 0));
        assert_eq!(ta.negative_anchors(), [n("other.test.")]);
    }

    #[test]
    fn negative_anchor_stops_applying_at_its_expiry() {
        let mut ta = TrustAnchors::new();
        ta.add_negative_until(n("lab.example."), 1000);
        ta.add_negative(n("forever.example."));
        assert!(ta.is_negative(&n("www.lab.example."), 0));
        assert!(ta.is_negative(&n("www.lab.example."), 999));
        assert!(!ta.is_negative(&n("www.lab.example."), 1000), "expired");
        assert!(!ta.is_negative(&n("lab.example."), 5000));
        assert!(ta.is_negative(&n("forever.example."), u32::MAX));
        assert_eq!(
            ta.negative_entries(),
            [
                (n("lab.example."), Some(1000)),
                (n("forever.example."), None)
            ]
        );
        assert_eq!(
            ta.negative_ttl(&n("www.lab.example."), 400),
            Some(Some(600))
        );
        assert_eq!(ta.negative_ttl(&n("forever.example."), 400), Some(None));
        assert_eq!(ta.negative_ttl(&n("www.lab.example."), 1000), None);
        ta.add_negative_until(n("example."), 5000);
        assert_eq!(
            ta.negative_ttl(&n("www.lab.example."), 400),
            Some(Some(4600)),
            "the longest-lived matching anchor decides"
        );
        ta.set_negative_entries([(n("x.test."), Some(7))]);
        assert_eq!(ta.negative_anchors(), [n("x.test.")]);
        assert!(!ta.is_negative(&n("x.test."), 7));
    }
}
