use std::collections::HashMap;
use std::net::IpAddr;

use dnsy_core::Principal;
use ipnet::IpNet;

/// What to do with a request from a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AclAction {
    Allow,
    /// Answer REFUSED.
    Refuse,
    /// Send nothing.
    Drop,
}

impl AclAction {
    /// Higher is stricter; used to break ties between equally specific rules.
    fn strictness(self) -> u8 {
        match self {
            AclAction::Allow => 0,
            AclAction::Refuse => 1,
            AclAction::Drop => 2,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AclAction::Allow => "allow",
            AclAction::Refuse => "refuse",
            AclAction::Drop => "drop",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<AclAction> {
        match s {
            "allow" => Some(AclAction::Allow),
            "refuse" => Some(AclAction::Refuse),
            "drop" => Some(AclAction::Drop),
            _ => None,
        }
    }
}

/// What a rule matches on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclMatcher {
    /// Client address inside the network (host bits are ignored).
    Cidr(IpNet),
    /// mTLS client certificate by SHA-256 fingerprint.
    ClientCert([u8; 32]),
}

/// Immutable ACL snapshot. Build with [`Acl::new`] and swap atomically.
///
/// A client-certificate rule matching the principal wins over any CIDR rule
/// (identity is more specific than an address). Otherwise the longest matching
/// prefix wins; equal prefixes resolve to the stricter action. With no match
/// the default action applies.
#[derive(Debug, Clone)]
pub struct Acl {
    default: AclAction,
    certs: HashMap<[u8; 32], AclAction>,
    /// Sorted by prefix length descending, then strictness descending.
    cidrs: Vec<(IpNet, AclAction)>,
}

impl Acl {
    #[must_use]
    pub fn new(
        default: AclAction,
        rules: impl IntoIterator<Item = (AclMatcher, AclAction)>,
    ) -> Acl {
        let mut certs: HashMap<[u8; 32], AclAction> = HashMap::new();
        let mut cidrs: Vec<(IpNet, AclAction)> = Vec::new();
        for (matcher, action) in rules {
            match matcher {
                AclMatcher::Cidr(net) => cidrs.push((net.trunc(), action)),
                AclMatcher::ClientCert(fp) => {
                    let slot = certs.entry(fp).or_insert(action);
                    if action.strictness() > slot.strictness() {
                        *slot = action;
                    }
                }
            }
        }
        cidrs.sort_by_key(|(net, action)| {
            (
                std::cmp::Reverse(net.prefix_len()),
                std::cmp::Reverse(action.strictness()),
            )
        });
        Acl {
            default,
            certs,
            cidrs,
        }
    }

    #[must_use]
    pub fn check(&self, ip: IpAddr, principal: Option<&Principal>) -> AclAction {
        if let Some(Principal::ClientCert { sha256, .. }) = principal
            && let Some(action) = self.certs.get(sha256)
        {
            return *action;
        }
        let ip = ip.to_canonical();
        self.cidrs
            .iter()
            .find(|(net, _)| net.contains(&ip))
            .map_or(self.default, |(_, action)| *action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> AclMatcher {
        AclMatcher::Cidr(s.parse().unwrap())
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn longest_prefix_wins() {
        let acl = Acl::new(
            AclAction::Allow,
            [
                (net("10.0.0.0/8"), AclAction::Refuse),
                (net("10.1.0.0/16"), AclAction::Allow),
                (net("10.1.2.0/24"), AclAction::Drop),
            ],
        );
        assert_eq!(acl.check(ip("10.9.9.9"), None), AclAction::Refuse);
        assert_eq!(acl.check(ip("10.1.9.9"), None), AclAction::Allow);
        assert_eq!(acl.check(ip("10.1.2.3"), None), AclAction::Drop);
        assert_eq!(acl.check(ip("192.0.2.1"), None), AclAction::Allow);
    }

    #[test]
    fn ipv6_cidr_match() {
        let acl = Acl::new(
            AclAction::Refuse,
            [
                (net("2001:db8::/32"), AclAction::Allow),
                (net("2001:db8:bad::/48"), AclAction::Drop),
            ],
        );
        assert_eq!(acl.check(ip("2001:db8:1::1"), None), AclAction::Allow);
        assert_eq!(acl.check(ip("2001:db8:bad::1"), None), AclAction::Drop);
        assert_eq!(acl.check(ip("2001:db9::1"), None), AclAction::Refuse);
    }

    #[test]
    fn ipv4_mapped_ipv6_matches_ipv4_rules() {
        let acl = Acl::new(AclAction::Allow, [(net("10.0.0.0/8"), AclAction::Drop)]);
        assert_eq!(acl.check(ip("::ffff:10.1.1.1"), None), AclAction::Drop);
    }

    #[test]
    fn host_bits_in_rule_are_ignored_and_ties_pick_stricter() {
        let acl = Acl::new(
            AclAction::Allow,
            [
                (net("10.1.2.3/24"), AclAction::Allow),
                (net("10.1.2.0/24"), AclAction::Refuse),
            ],
        );
        assert_eq!(acl.check(ip("10.1.2.200"), None), AclAction::Refuse);
    }

    #[test]
    fn principal_rule_matches_client_cert() {
        let fp = [7u8; 32];
        let acl = Acl::new(
            AclAction::Allow,
            [
                (net("0.0.0.0/0"), AclAction::Refuse),
                (AclMatcher::ClientCert(fp), AclAction::Allow),
            ],
        );
        let cert = Principal::ClientCert {
            sha256: fp,
            subject: "CN=a".into(),
        };
        let other = Principal::ClientCert {
            sha256: [8; 32],
            subject: "CN=b".into(),
        };
        assert_eq!(acl.check(ip("203.0.113.9"), Some(&cert)), AclAction::Allow);
        assert_eq!(
            acl.check(ip("203.0.113.9"), Some(&other)),
            AclAction::Refuse
        );
        assert_eq!(acl.check(ip("203.0.113.9"), None), AclAction::Refuse);
    }

    #[test]
    fn duplicate_cert_rules_pick_stricter() {
        let fp = [1u8; 32];
        let acl = Acl::new(
            AclAction::Allow,
            [
                (AclMatcher::ClientCert(fp), AclAction::Drop),
                (AclMatcher::ClientCert(fp), AclAction::Allow),
            ],
        );
        let p = Principal::ClientCert {
            sha256: fp,
            subject: String::new(),
        };
        assert_eq!(acl.check(ip("192.0.2.1"), Some(&p)), AclAction::Drop);
    }

    #[test]
    fn action_names_round_trip() {
        for a in [AclAction::Allow, AclAction::Refuse, AclAction::Drop] {
            assert_eq!(AclAction::parse(a.as_str()), Some(a));
        }
        assert_eq!(AclAction::parse("x"), None);
    }
}
