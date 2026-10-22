//! Client admission: the CIDR and client-certificate ACL snapshot.

use std::collections::HashMap;
use std::net::IpAddr;

use dnsy_core::Principal;
use dnsy_filter::{AclAction, AclMatcher};
use ipnet::IpNet;

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
    /// Built by [`Acl::private_only`]; [`Acl::with_rules`] keeps the same base.
    private_only: bool,
}

/// Networks a private-only ACL allows: loopback, RFC 1918, 100.64/10, IPv4 and IPv6 link-local
/// and ULA.
const PRIVATE_NETS: [&str; 8] = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "fe80::/10",
];

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
            private_only: false,
        }
    }

    /// The safe default: private networks (loopback, RFC 1918, 100.64/10, ULA, link-local) are
    /// allowed and everything else is refused. `rules` still win by longest prefix (equal
    /// prefixes resolve to the stricter action).
    #[must_use]
    pub fn private_only(rules: impl IntoIterator<Item = (AclMatcher, AclAction)>) -> Acl {
        let base = PRIVATE_NETS
            .iter()
            .chain(&["fc00::/7"])
            .filter_map(|n| n.parse().ok())
            .map(|n| (AclMatcher::Cidr(n), AclAction::Allow));
        let mut acl = Acl::new(AclAction::Refuse, base.chain(rules));
        acl.private_only = true;
        acl
    }

    /// A new ACL over `rules` with the same base (allow-all or private-only) as `self`.
    #[must_use]
    pub fn with_rules(&self, rules: impl IntoIterator<Item = (AclMatcher, AclAction)>) -> Acl {
        if self.private_only {
            Acl::private_only(rules)
        } else {
            Acl::new(AclAction::Allow, rules)
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
    fn private_only_base_and_rules() {
        let acl = Acl::private_only([(net("203.0.113.0/24"), AclAction::Allow)]);
        for ok in [
            "127.0.0.1",
            "::1",
            "10.1.1.1",
            "172.31.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.1.1",
            "fe80::1",
            "fd00::1",
            "::ffff:10.0.0.1",
            "203.0.113.5",
        ] {
            assert_eq!(acl.check(ip(ok), None), AclAction::Allow, "{ok}");
        }
        for no in ["203.0.114.5", "8.8.8.8", "172.32.0.1", "2001:db8::1"] {
            assert_eq!(acl.check(ip(no), None), AclAction::Refuse, "{no}");
        }
        let acl = Acl::private_only([(net("10.0.0.0/8"), AclAction::Refuse)]);
        assert_eq!(acl.check(ip("10.1.1.1"), None), AclAction::Refuse);
        let rebuilt = acl.with_rules([]);
        assert_eq!(rebuilt.check(ip("8.8.8.8"), None), AclAction::Refuse);
        let open = Acl::new(AclAction::Allow, []).with_rules([]);
        assert_eq!(open.check(ip("8.8.8.8"), None), AclAction::Allow);
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
}
