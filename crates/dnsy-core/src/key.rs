//! Key roles and key lifecycle states, shared by the signer (`dnsy-dnssec`) and the key store
//! (`dnsy-keys`).

use std::fmt;

/// What a key signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRole {
    /// Combined signing key: signs the DNSKEY `RRset` and the zone, carries the SEP flag.
    Csk,
    /// Key signing key: signs the DNSKEY `RRset`, carries the SEP flag.
    Ksk,
    /// Zone signing key: signs everything else.
    Zsk,
}

impl KeyRole {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            KeyRole::Csk => "csk",
            KeyRole::Ksk => "ksk",
            KeyRole::Zsk => "zsk",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<KeyRole> {
        match s {
            "csk" => Some(KeyRole::Csk),
            "ksk" => Some(KeyRole::Ksk),
            "zsk" => Some(KeyRole::Zsk),
            _ => None,
        }
    }

    /// True when the DNSKEY carries the SEP flag and a DS is published at the parent.
    #[must_use]
    pub fn is_sep(self) -> bool {
        !matches!(self, KeyRole::Zsk)
    }
}

impl fmt::Display for KeyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyState {
    /// Created, not yet in the DNSKEY `RRset`.
    Generated,
    /// In the DNSKEY `RRset` but not signing.
    Published,
    /// Signing.
    Active,
    /// No longer signing, still in the DNSKEY `RRset` for validators holding old signatures.
    Retired,
    /// Withdrawn; the private key is destroyed.
    Removed,
}

impl KeyState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            KeyState::Generated => "generated",
            KeyState::Published => "published",
            KeyState::Active => "active",
            KeyState::Retired => "retired",
            KeyState::Removed => "removed",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<KeyState> {
        match s {
            "generated" => Some(KeyState::Generated),
            "published" => Some(KeyState::Published),
            "active" => Some(KeyState::Active),
            "retired" => Some(KeyState::Retired),
            "removed" => Some(KeyState::Removed),
            _ => None,
        }
    }

    /// True when the DNSKEY belongs in the zone's DNSKEY `RRset`.
    #[must_use]
    pub fn is_published(self) -> bool {
        matches!(
            self,
            KeyState::Published | KeyState::Active | KeyState::Retired
        )
    }
}

impl fmt::Display for KeyState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for r in [KeyRole::Csk, KeyRole::Ksk, KeyRole::Zsk] {
            assert_eq!(KeyRole::parse(r.as_str()), Some(r));
            assert_eq!(r.to_string(), r.as_str());
        }
        for s in [
            KeyState::Generated,
            KeyState::Published,
            KeyState::Active,
            KeyState::Retired,
            KeyState::Removed,
        ] {
            assert_eq!(KeyState::parse(s.as_str()), Some(s));
            assert_eq!(s.to_string(), s.as_str());
        }
        assert_eq!(KeyRole::parse("x"), None);
        assert_eq!(KeyState::parse("x"), None);
        assert!(KeyRole::Ksk.is_sep() && KeyRole::Csk.is_sep() && !KeyRole::Zsk.is_sep());
        assert!(KeyState::Retired.is_published() && !KeyState::Generated.is_published());
        assert!(!KeyState::Removed.is_published());
    }
}
