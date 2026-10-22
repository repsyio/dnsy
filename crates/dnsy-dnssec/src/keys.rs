//! Key roles, key lifecycle states and the rollover planner (RFC 6781, RFC 7583).
//!
//! The planner is a pure function of the key set, the timing parameters and the current
//! time, so rollovers are driven by an injectable [`dnsy_core::Clock`] and tested without sleeping.
//!
//! * ZSK **pre-publish**: the new key is published (DNSKEY only), and after the DNSKEY TTL
//!   plus propagation delay it becomes active while the old key is retired.
//! * KSK and CSK **double-DS**: the new key is published and its DS is handed to the parent;
//!   it stays published until the operator confirms the DS, then it becomes active and the
//!   old key is retired.
//! * A generated key is inert: only an explicit rollover step publishes it.
//! * A retired key stays in the DNSKEY `RRset` until every signature it made has expired and
//!   caches have dropped the old DNSKEY, then it is removed.

use crate::Algorithm;
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
    pub fn as_str(self) -> &'static str {
        match self {
            KeyRole::Csk => "csk",
            KeyRole::Ksk => "ksk",
            KeyRole::Zsk => "zsk",
        }
    }

    pub fn parse(s: &str) -> Option<KeyRole> {
        match s {
            "csk" => Some(KeyRole::Csk),
            "ksk" => Some(KeyRole::Ksk),
            "zsk" => Some(KeyRole::Zsk),
            _ => None,
        }
    }

    /// True when the DNSKEY carries the SEP flag and a DS is published at the parent.
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
    pub fn as_str(self) -> &'static str {
        match self {
            KeyState::Generated => "generated",
            KeyState::Published => "published",
            KeyState::Active => "active",
            KeyState::Retired => "retired",
            KeyState::Removed => "removed",
        }
    }

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

/// Public metadata of a stored key (never the private key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub id: i64,
    pub zone: String,
    pub role: KeyRole,
    pub algorithm: Algorithm,
    pub key_tag: u16,
    pub state: KeyState,
    pub created_at: i64,
    pub published_at: Option<i64>,
    pub active_at: Option<i64>,
    pub retired_at: Option<i64>,
    pub removed_at: Option<i64>,
    /// When the operator confirmed the DS at the parent (KSK and CSK only).
    pub ds_confirmed_at: Option<i64>,
}

/// Timing parameters of a zone's rollovers, in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolloverTimings {
    pub dnskey_ttl: u32,
    /// Extra time for the DNSKEY `RRset` to reach every secondary and resolver.
    pub propagation: u32,
    /// Longest validity of any signature made by the key.
    pub max_signature_validity: u32,
}

impl RolloverTimings {
    /// Time a published key waits before it may sign.
    pub fn publish_wait(&self) -> i64 {
        i64::from(self.dnskey_ttl) + i64::from(self.propagation)
    }

    /// Time a retired key stays published: its last signature must have expired.
    pub fn retire_wait(&self) -> i64 {
        self.publish_wait() + i64::from(self.max_signature_validity)
    }
}

/// One state change decided by [`plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    pub key_id: i64,
    pub to: KeyState,
}

/// Decides which keys of one zone change state at `now`.
///
/// A key moves at most one step per call, a `generated` key never moves (publishing it is an
/// explicit step), and a KSK or CSK that replaces an active key
/// waits for the operator's DS confirmation however long that takes.
pub fn plan(keys: &[KeyRecord], timings: &RolloverTimings, now: i64) -> Vec<Transition> {
    let mut out = Vec::new();
    for role in [KeyRole::Csk, KeyRole::Ksk, KeyRole::Zsk] {
        let group: Vec<&KeyRecord> = keys.iter().filter(|k| k.role == role).collect();
        let has_active = group.iter().any(|k| k.state == KeyState::Active);
        let mut activated = false;
        for k in &group {
            let to = match k.state {
                KeyState::Published => {
                    let waited = k
                        .published_at
                        .is_some_and(|t| now >= t.saturating_add(timings.publish_wait()));
                    let confirmed = !role.is_sep() || !has_active || k.ds_confirmed_at.is_some();
                    (waited && confirmed).then_some(KeyState::Active)
                }
                KeyState::Retired => k
                    .retired_at
                    .is_some_and(|t| now >= t.saturating_add(timings.retire_wait()))
                    .then_some(KeyState::Removed),
                KeyState::Generated | KeyState::Active | KeyState::Removed => None,
            };
            if let Some(to) = to {
                activated |= to == KeyState::Active;
                out.push(Transition { key_id: k.id, to });
            }
        }
        if activated {
            out.extend(
                group
                    .iter()
                    .filter(|k| k.state == KeyState::Active)
                    .map(|k| Transition {
                        key_id: k.id,
                        to: KeyState::Retired,
                    }),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: RolloverTimings = RolloverTimings {
        dnskey_ttl: 3600,
        propagation: 400,
        max_signature_validity: 10_000,
    };

    fn key(id: i64, role: KeyRole, state: KeyState) -> KeyRecord {
        KeyRecord {
            id,
            zone: "example.".into(),
            role,
            algorithm: Algorithm::EcdsaP256Sha256,
            key_tag: 1,
            state,
            created_at: 0,
            published_at: Some(1000),
            active_at: None,
            retired_at: Some(1000),
            removed_at: None,
            ds_confirmed_at: None,
        }
    }

    const NONE: [Transition; 0] = [];

    fn to(id: i64, to: KeyState) -> Transition {
        Transition { key_id: id, to }
    }

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

    #[test]
    fn zsk_rollover_states_advance_on_schedule() {
        let old = key(1, KeyRole::Zsk, KeyState::Active);
        let new = key(2, KeyRole::Zsk, KeyState::Generated);
        assert_eq!(
            plan(&[old.clone(), new], &T, 1000),
            NONE,
            "a generated key stays inert until it is published explicitly"
        );

        let new = key(2, KeyRole::Zsk, KeyState::Published);
        let wait = T.publish_wait();
        assert_eq!(wait, 4000);
        assert_eq!(plan(&[old.clone(), new.clone()], &T, 1000 + wait - 1), NONE);
        assert_eq!(
            plan(&[old, new], &T, 1000 + wait),
            [to(2, KeyState::Active), to(1, KeyState::Retired)]
        );

        let retired = key(1, KeyRole::Zsk, KeyState::Retired);
        let active = key(2, KeyRole::Zsk, KeyState::Active);
        let at = 1000 + T.retire_wait();
        assert_eq!(T.retire_wait(), 14_000);
        assert_eq!(plan(&[retired.clone(), active.clone()], &T, at - 1), NONE);
        assert_eq!(plan(&[retired, active], &T, at), [to(1, KeyState::Removed)]);
    }

    #[test]
    fn ksk_rollover_waits_for_ds_confirmation() {
        let old = key(1, KeyRole::Ksk, KeyState::Active);
        let mut new = key(2, KeyRole::Ksk, KeyState::Published);
        assert_eq!(plan(&[old.clone(), new.clone()], &T, 1_000_000), NONE);
        new.ds_confirmed_at = Some(2000);
        assert_eq!(
            plan(&[old.clone(), new.clone()], &T, 3000),
            NONE,
            "confirmed but DNSKEY not yet propagated"
        );
        assert_eq!(
            plan(&[old, new], &T, 6000),
            [to(2, KeyState::Active), to(1, KeyState::Retired)]
        );
    }

    #[test]
    fn csk_follows_double_ds_and_roles_are_independent() {
        let ksk = key(1, KeyRole::Ksk, KeyState::Active);
        let zsk_old = key(2, KeyRole::Zsk, KeyState::Active);
        let zsk_new = key(3, KeyRole::Zsk, KeyState::Published);
        let csk_old = key(4, KeyRole::Csk, KeyState::Active);
        let csk_new = key(5, KeyRole::Csk, KeyState::Published);
        let plan_out = plan(&[ksk, zsk_old, zsk_new, csk_old, csk_new], &T, 10_000);
        assert_eq!(
            plan_out,
            [to(3, KeyState::Active), to(2, KeyState::Retired)]
        );
    }

    #[test]
    fn first_key_activates_without_ds_confirmation() {
        let first = key(1, KeyRole::Csk, KeyState::Published);
        assert_eq!(plan(std::slice::from_ref(&first), &T, 1000), NONE);
        assert_eq!(plan(&[first], &T, 5000), [to(1, KeyState::Active)]);
    }

    #[test]
    fn missing_timestamps_never_advance() {
        let mut k = key(1, KeyRole::Zsk, KeyState::Published);
        k.published_at = None;
        let mut r = key(2, KeyRole::Zsk, KeyState::Retired);
        r.retired_at = None;
        assert_eq!(plan(&[k, r], &T, i64::MAX), NONE);
        let removed = key(3, KeyRole::Zsk, KeyState::Removed);
        assert_eq!(plan(&[removed], &T, i64::MAX), NONE);
    }
}
