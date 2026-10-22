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

use std::time::Duration;

use dnsy_dnssec::Algorithm;
use dnsy_proto::Name;
use rusqlite::{OptionalExtension, params};

use crate::repo::{insert, list_zone, record_of, zone_key};
use crate::{KeyRole, KeyState, KeyStore, KeyStoreError};

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
    #[must_use]
    pub fn publish_wait(&self) -> i64 {
        i64::from(self.dnskey_ttl) + i64::from(self.propagation)
    }

    /// Time a retired key stays published: its last signature must have expired.
    #[must_use]
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
#[must_use]
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

impl KeyStore {
    /// Starts a rollover of `role`: publishes the zone's `generated` key of that role (made
    /// by [`generate_key`](Self::generate_key); it keeps its own algorithm), or generates a
    /// new key of `algorithm` and publishes it. [`tick`](Self::tick) then advances it per
    /// [`plan`].
    ///
    /// # Errors
    /// No active key of that role, a rollover already running (a `published` key exists),
    /// or a database failure.
    pub async fn start_rollover(
        &self,
        zone: &Name,
        role: KeyRole,
        algorithm: Algorithm,
    ) -> Result<KeyRecord, KeyStoreError> {
        let _shared = self.key_lock.read().await;
        let existing = self.keys(zone).await?;
        if existing
            .iter()
            .any(|k| k.role == role && k.state == KeyState::Published)
        {
            return Err(KeyStoreError::RolloverInProgress(role));
        }
        if !existing
            .iter()
            .any(|k| k.role == role && k.state == KeyState::Active)
        {
            return Err(KeyStoreError::NoActiveKey(role));
        }
        if let Some(generated) = existing
            .into_iter()
            .find(|k| k.role == role && k.state == KeyState::Generated)
        {
            let now = self.clock.unix_secs();
            self.store
                .write(move |tx| {
                    tx.execute(
                        "UPDATE dnssec_keys SET state = 'published', published_at = ?1 \
                         WHERE id = ?2",
                        params![now, generated.id],
                    )?;
                    Ok(KeyRecord {
                        state: KeyState::Published,
                        published_at: Some(now),
                        ..generated
                    })
                })
                .await
                .map_err(Into::into)
        } else {
            self.start_new_rollover(zone, role, algorithm).await
        }
    }

    async fn start_new_rollover(
        &self,
        zone: &Name,
        role: KeyRole,
        algorithm: Algorithm,
    ) -> Result<KeyRecord, KeyStoreError> {
        let z = zone.clone();
        let new = self
            .offload(move |s| s.new_key(&z, role, algorithm, KeyState::Published))
            .await?;
        let (id, new) = self
            .store
            .write(move |tx| insert(tx, &new).map(|id| (id, new)))
            .await?;
        Ok(record_of(id, &new))
    }

    /// Records that the operator has published the key's DS at the parent, which lets a
    /// KSK or CSK rollover proceed.
    ///
    /// # Errors
    /// Unknown key, a ZSK, a key that is not `published`, or a database failure.
    pub async fn confirm_ds(&self, id: i64) -> Result<(), KeyStoreError> {
        let now = self.clock.unix_secs();
        self.store
            .write(move |tx| {
                let row: Option<(String, String)> = tx
                    .query_row(
                        "SELECT role, state FROM dnssec_keys WHERE id = ?1",
                        [id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                Ok(match row {
                    None => Err(KeyStoreError::NotFound(id)),
                    Some((role, state)) if role == "zsk" || state != "published" => {
                        Err(KeyStoreError::InvalidState(
                            "DS confirmation applies to a published KSK or CSK",
                        ))
                    }
                    Some(_) => {
                        tx.execute(
                            "UPDATE dnssec_keys SET ds_confirmed_at = ?1 WHERE id = ?2",
                            params![now, id],
                        )?;
                        Ok(())
                    }
                })
            })
            .await?
    }

    /// Aborts the rollovers of a zone: every incoming key (`generated` or `published`) of
    /// `role`, or of every role, is withdrawn and its private key destroyed, and the active
    /// key stays. A rollover whose new key already became active cannot be aborted; start a
    /// rollover back instead. Returns the aborted keys (a key with `ds_confirmed_at` set had
    /// its DS published at the parent, which the operator should remove again).
    ///
    /// # Errors
    /// No rollover in progress, or a database failure.
    pub async fn abort_rollover(
        &self,
        zone: &Name,
        role: Option<KeyRole>,
    ) -> Result<Vec<KeyRecord>, KeyStoreError> {
        let name = zone_key(zone);
        let now = self.clock.unix_secs();
        self.store
            .write(move |tx| {
                let incoming: Vec<KeyRecord> = list_zone(tx, &name)?
                    .into_iter()
                    .filter(|k| {
                        matches!(k.state, KeyState::Generated | KeyState::Published)
                            && role.is_none_or(|r| k.role == r)
                    })
                    .collect();
                if incoming.is_empty() {
                    return Ok(Err(KeyStoreError::NoRollover(
                        role.map_or_else(|| "key".to_owned(), |r| r.to_string()),
                    )));
                }
                for k in &incoming {
                    tx.execute(
                        "UPDATE dnssec_keys SET state = 'removed', removed_at = ?1, \
                         private_key = x'' WHERE id = ?2",
                        params![now, k.id],
                    )?;
                }
                Ok(Ok(incoming
                    .into_iter()
                    .map(|k| KeyRecord {
                        state: KeyState::Removed,
                        removed_at: Some(now),
                        ..k
                    })
                    .collect()))
            })
            .await?
    }

    /// Advances the zone's keys per [`plan`] at the clock's current time and returns what
    /// changed. A key that becomes `removed` has its private key destroyed.
    ///
    /// # Errors
    /// Database failure.
    pub async fn tick(
        &self,
        zone: &Name,
        timings: RolloverTimings,
    ) -> Result<Vec<Transition>, KeyStoreError> {
        let name = zone_key(zone);
        self.tick_named(name, timings).await
    }

    async fn tick_named(
        &self,
        name: String,
        timings: RolloverTimings,
    ) -> Result<Vec<Transition>, KeyStoreError> {
        let now = self.clock.unix_secs();
        Ok(self
            .store
            .write(move |tx| {
                let keys = list_zone(tx, &name)?;
                let transitions = plan(&keys, &timings, now);
                for t in &transitions {
                    tx.execute(
                        "UPDATE dnssec_keys SET state = ?1, \
                         published_at = CASE WHEN ?1 = 'published' THEN ?2 ELSE published_at END, \
                         active_at = CASE WHEN ?1 = 'active' THEN ?2 ELSE active_at END, \
                         retired_at = CASE WHEN ?1 = 'retired' THEN ?2 ELSE retired_at END, \
                         removed_at = CASE WHEN ?1 = 'removed' THEN ?2 ELSE removed_at END, \
                         private_key = CASE WHEN ?1 = 'removed' THEN x'' ELSE private_key END \
                         WHERE id = ?3",
                        params![t.to.as_str(), now, t.key_id],
                    )?;
                }
                Ok(transitions)
            })
            .await?)
    }

    /// Ticks every zone that has keys; `timings` returns a zone's timings, or `None` to skip it.
    ///
    /// # Errors
    /// Database failure.
    pub async fn tick_all(
        &self,
        timings: impl Fn(&str) -> Option<RolloverTimings>,
    ) -> Result<usize, KeyStoreError> {
        let zones: Vec<String> = self
            .store
            .read(|c| {
                let mut stmt = c.prepare("SELECT DISTINCT zone FROM dnssec_keys ORDER BY zone")?;
                Ok(stmt
                    .query_map([], |r| r.get(0))?
                    .collect::<Result<_, _>>()?)
            })
            .await?;
        let mut changed = 0;
        for zone in zones {
            if let Some(t) = timings(&zone) {
                changed += self.tick_named(zone, t).await?.len();
            }
        }
        Ok(changed)
    }

    /// Spawns the timer task: every `interval` it advances all zones' keys. Errors are
    /// logged (without key material) and the task keeps running.
    pub fn spawn_timer(
        self,
        interval: Duration,
        timings: impl Fn(&str) -> Option<RolloverTimings> + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                match self.tick_all(&timings).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(transitions = n, "dnssec key states advanced"),
                    Err(e) => tracing::error!(error = %e, "dnssec key timer failed"),
                }
            }
        })
    }
}

#[cfg(test)]
mod plan_tests {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    #[tokio::test]
    async fn zsk_rollover_states_advance_on_schedule() {
        let f = fixture(Some("pw"));
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::KskZsk, ECDSA).await.unwrap();
        let alg = Algorithm::EcdsaP256Sha256;
        let new = f.ks.start_rollover(&z, KeyRole::Zsk, alg).await.unwrap();
        assert_eq!(new.state, KeyState::Published);
        assert!(matches!(
            f.ks.start_rollover(&z, KeyRole::Zsk, alg).await,
            Err(KeyStoreError::RolloverInProgress(KeyRole::Zsk))
        ));

        f.clock.advance(3599);
        assert_eq!(f.ks.tick(&z, T).await.unwrap(), []);
        f.clock.advance(1);
        assert_eq!(f.ks.tick(&z, T).await.unwrap().len(), 2);
        let keys = f.ks.keys(&z).await.unwrap();
        assert_eq!(
            states(&keys, KeyRole::Zsk),
            [KeyState::Retired, KeyState::Active]
        );
        assert_eq!(states(&keys, KeyRole::Ksk), [KeyState::Active]);
        assert_eq!(f.ks.dnskeys(&z).await.unwrap().len(), 3);

        f.clock.advance(13_599);
        assert_eq!(f.ks.tick(&z, T).await.unwrap(), []);
        f.clock.advance(1);
        f.ks.tick(&z, T).await.unwrap();
        let keys = f.ks.keys(&z).await.unwrap();
        assert_eq!(
            states(&keys, KeyRole::Zsk),
            [KeyState::Removed, KeyState::Active]
        );
        let removed = keys.iter().find(|k| k.state == KeyState::Removed).unwrap();
        assert_eq!(removed.removed_at, Some(T0 + 3600 + 13_600));
        assert_eq!(f.ks.dnskeys(&z).await.unwrap().len(), 2);
        assert!(matches!(
            f.ks.signing_key(removed.id).await,
            Err(KeyStoreError::InvalidState(_))
        ));
        let id = removed.id;
        let wiped: i64 =
            f.ks.store
                .read(move |c| {
                    Ok(c.query_row(
                        "SELECT length(private_key) FROM dnssec_keys WHERE id = ?1",
                        [id],
                        |r| r.get(0),
                    )?)
                })
                .await
                .unwrap();
        assert_eq!(wiped, 0);
        // A new rollover may start once the previous one finished.
        f.ks.start_rollover(&z, KeyRole::Zsk, alg).await.unwrap();
    }

    #[tokio::test]
    async fn generated_key_is_inert_until_a_rollover_publishes_it() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::KskZsk, ECDSA).await.unwrap();
        let alg = Algorithm::EcdsaP256Sha256;
        let generated = f.ks.generate_key(&z, KeyRole::Zsk, alg).await.unwrap();
        f.clock.advance(1_000_000);
        assert_eq!(f.ks.tick(&z, T).await.unwrap(), [], "nothing publishes it");
        let before = f.ks.dnskeys(&z).await.unwrap().len();
        assert!(
            f.ks.keys(&z)
                .await
                .unwrap()
                .iter()
                .any(|k| k.id == generated.id && k.state == KeyState::Generated)
        );

        let started = f.ks.start_rollover(&z, KeyRole::Zsk, alg).await.unwrap();
        assert_eq!(started.id, generated.id, "the generated key is adopted");
        assert_eq!(started.state, KeyState::Published);
        assert_eq!(f.ks.dnskeys(&z).await.unwrap().len(), before + 1);
        assert!(matches!(
            f.ks.start_rollover(&z, KeyRole::Zsk, alg).await,
            Err(KeyStoreError::RolloverInProgress(KeyRole::Zsk))
        ));
        f.clock.advance(3600);
        assert_eq!(f.ks.tick(&z, T).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn ksk_rollover_waits_for_ds_confirmation() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::Csk, ECDSA).await.unwrap();
        let alg = Algorithm::EcdsaP256Sha256;
        assert!(matches!(
            f.ks.start_rollover(&z, KeyRole::Ksk, alg).await,
            Err(KeyStoreError::NoActiveKey(KeyRole::Ksk))
        ));
        let new = f.ks.start_rollover(&z, KeyRole::Csk, alg).await.unwrap();

        f.clock.advance(10_000_000);
        assert!(
            f.ks.tick(&z, T).await.unwrap().is_empty(),
            "no DS confirmation yet"
        );
        assert_eq!(f.ks.keys(&z).await.unwrap()[1].state, KeyState::Published);

        f.ks.confirm_ds(new.id).await.unwrap();
        assert_eq!(f.ks.tick(&z, T).await.unwrap().len(), 2);
        let keys = f.ks.keys(&z).await.unwrap();
        assert_eq!(
            states(&keys, KeyRole::Csk),
            [KeyState::Retired, KeyState::Active]
        );
        assert_eq!(keys[1].ds_confirmed_at, Some(T0 + 10_000_000));
    }

    #[tokio::test]
    async fn abort_rollover_withdraws_the_incoming_key_only() {
        let f = fixture(Some("pw"));
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::KskZsk, ECDSA).await.unwrap();
        let alg = Algorithm::EcdsaP256Sha256;
        assert!(matches!(
            f.ks.abort_rollover(&z, None).await,
            Err(KeyStoreError::NoRollover(_))
        ));
        let ksk = f.ks.start_rollover(&z, KeyRole::Ksk, alg).await.unwrap();
        let zsk = f.ks.start_rollover(&z, KeyRole::Zsk, alg).await.unwrap();

        // Only the named role is aborted; the other rollover continues.
        let aborted = f.ks.abort_rollover(&z, Some(KeyRole::Ksk)).await.unwrap();
        assert_eq!(aborted.len(), 1);
        assert_eq!(aborted[0].id, ksk.id);
        assert_eq!(aborted[0].state, KeyState::Removed);
        assert!(matches!(
            f.ks.abort_rollover(&z, Some(KeyRole::Ksk)).await,
            Err(KeyStoreError::NoRollover(_))
        ));
        let keys = f.ks.keys(&z).await.unwrap();
        assert_eq!(
            states(&keys, KeyRole::Ksk),
            [KeyState::Active, KeyState::Removed]
        );
        assert_eq!(
            states(&keys, KeyRole::Zsk),
            [KeyState::Active, KeyState::Published]
        );
        assert!(matches!(
            f.ks.signing_key(ksk.id).await,
            Err(KeyStoreError::InvalidState(_))
        ));

        // Without a role every rollover is aborted, and the old key keeps signing.
        let aborted = f.ks.abort_rollover(&z, None).await.unwrap();
        assert_eq!(aborted[0].id, zsk.id);
        let keys = f.ks.keys(&z).await.unwrap();
        assert_eq!(
            states(&keys, KeyRole::Zsk),
            [KeyState::Active, KeyState::Removed]
        );
        f.clock.advance(1_000_000);
        assert_eq!(f.ks.tick(&z, T).await.unwrap().len(), 0);
        assert_eq!(f.ks.dnskeys(&z).await.unwrap().len(), 2);
        // A new rollover may start afterwards.
        f.ks.start_rollover(&z, KeyRole::Zsk, alg).await.unwrap();
    }

    #[tokio::test]
    async fn abort_after_activation_is_refused() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::KskZsk, ECDSA).await.unwrap();
        f.ks.start_rollover(&z, KeyRole::Zsk, Algorithm::EcdsaP256Sha256)
            .await
            .unwrap();
        f.clock.advance(3600);
        f.ks.tick(&z, T).await.unwrap();
        assert!(matches!(
            f.ks.abort_rollover(&z, None).await,
            Err(KeyStoreError::NoRollover(_))
        ));
    }

    #[tokio::test]
    async fn confirm_ds_rejects_bad_targets() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::KskZsk, ECDSA).await.unwrap();
        let keys = f.ks.keys(&z).await.unwrap();
        assert!(matches!(
            f.ks.confirm_ds(77).await,
            Err(KeyStoreError::NotFound(77))
        ));
        for k in &keys {
            assert!(matches!(
                f.ks.confirm_ds(k.id).await,
                Err(KeyStoreError::InvalidState(_))
            ));
        }
    }

    #[tokio::test]
    async fn tick_all_and_timer_task() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::Csk, ECDSA).await.unwrap();
        let skipped = Name::from_ascii("skip.test.").unwrap();
        f.ks.bootstrap(&skipped, KeyLayout::Csk, ECDSA)
            .await
            .unwrap();
        f.ks.start_rollover(&z, KeyRole::Csk, Algorithm::Ed25519)
            .await
            .unwrap();
        f.ks.start_rollover(&skipped, KeyRole::Csk, Algorithm::Ed25519)
            .await
            .unwrap();
        f.clock.advance(5000);
        let only = |zone: &str| (zone == "example.com.").then_some(T);
        // Not confirmed: nothing to do; an unconfirmed CSK never activates.
        assert_eq!(f.ks.tick_all(only).await.unwrap(), 0);
        let new = f.ks.keys(&z).await.unwrap()[1].id;
        f.ks.confirm_ds(new).await.unwrap();
        let handle = f.ks.clone().spawn_timer(Duration::from_millis(10), only);
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if f.ks.keys(&z).await.unwrap()[1].state == KeyState::Active {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timer did not advance"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        handle.abort();
        assert_eq!(
            f.ks.keys(&skipped).await.unwrap()[1].state,
            KeyState::Published
        );
    }
}
