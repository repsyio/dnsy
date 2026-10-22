//! The key store: opening it, generating and loading keys, and changing the passphrase.

use std::fmt;
use std::sync::{Arc, RwLock};

use dnsy_core::Clock;
use dnsy_dnssec::{ActiveKeys, Algorithm, DigestType, SigningKey, ZoneKey, ds_for};
use dnsy_proto::{Dnskey, Ds, Name};
use dnsy_store::Store;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::repo::{
    COLUMNS, NewKey, SecretRow, insert, list_zone, open_key, record_of, row_to_record, secret_row,
    to_dnskey, zone_key,
};
use crate::sealed::encrypt;
use crate::{KdfCost, KeyRecord, KeyRole, KeyState, KeyStoreError, Passphrase};

/// Whether one key signs everything or keys are split into KSK and ZSK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyLayout {
    Csk,
    KskZsk,
}

/// Per-zone DNSSEC key sets in SQLite.
#[derive(Clone)]
pub struct KeyStore {
    pub(crate) store: Store,
    /// Shared by clones so a passphrase change reaches every holder of the store.
    pub(crate) passphrase: Arc<RwLock<Option<Arc<Passphrase>>>>,
    /// Held shared by everything that seals, inserts or decrypts keys, and exclusively by a
    /// passphrase change, so no key is sealed or read under a passphrase that is being
    /// replaced.
    pub(crate) key_lock: Arc<tokio::sync::RwLock<()>>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) cost: KdfCost,
    /// Cost of sealing a backup bundle, which leaves the machine and so gets a stronger KDF.
    pub(crate) bundle_cost: KdfCost,
    /// Serialises `bootstrap`: its check for existing keys and the insert must not interleave.
    pub(crate) bootstrap_lock: Arc<tokio::sync::Mutex<()>>,
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStore")
            .field("keys_encrypted", &self.keys_encrypted())
            .finish_non_exhaustive()
    }
}

impl KeyStore {
    /// Opens the key store. Logs a warning when no passphrase is configured.
    pub fn open(store: Store, passphrase: Option<Passphrase>, clock: Arc<dyn Clock>) -> KeyStore {
        if passphrase.is_none() {
            tracing::warn!(
                "no DNSSEC key passphrase configured (DNSY_DNSSEC_PASSPHRASE or key_passphrase_file): \
                 private keys are stored unencrypted"
            );
        }
        KeyStore {
            store,
            passphrase: Arc::new(RwLock::new(passphrase.map(Arc::new))),
            key_lock: Arc::default(),
            clock,
            cost: KdfCost::default(),
            bundle_cost: KdfCost::BUNDLE,
            bootstrap_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Overrides the argon2id cost used for newly sealed keys and bundles (existing blobs
    /// carry their own).
    #[must_use]
    pub fn with_kdf_cost(mut self, cost: KdfCost) -> KeyStore {
        self.cost = cost;
        self.bundle_cost = cost;
        self
    }

    /// The clock key states and signatures are timed by.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// True when new private keys are encrypted at rest (the API's `keys_encrypted` flag).
    #[must_use]
    pub fn keys_encrypted(&self) -> bool {
        self.pass().is_some()
    }

    /// The current passphrase.
    pub(crate) fn pass(&self) -> Option<Arc<Passphrase>> {
        self.passphrase
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Runs CPU-heavy key work (argon2id, key generation) off the async threads.
    pub(crate) async fn offload<T: Send + 'static>(
        &self,
        f: impl FnOnce(&KeyStore) -> Result<T, KeyStoreError> + Send + 'static,
    ) -> Result<T, KeyStoreError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || f(&this))
            .await
            .map_err(|_| KeyStoreError::Io("key task failed".into()))?
    }

    fn seal(&self, pkcs8: &[u8]) -> Result<(Vec<u8>, bool), KeyStoreError> {
        match self.pass() {
            Some(p) => Ok((encrypt(&p, self.cost, pkcs8)?, true)),
            None => Ok((pkcs8.to_vec(), false)),
        }
    }

    pub(crate) fn new_key(
        &self,
        zone: &Name,
        role: KeyRole,
        algorithm: Algorithm,
        state: KeyState,
    ) -> Result<NewKey, KeyStoreError> {
        let now = self.clock.unix_secs();
        let key = SigningKey::generate(algorithm, role.is_sep())?;
        self.stored_key(zone_key(zone), role, &key, state, now)
    }

    pub(crate) fn stored_key(
        &self,
        zone: String,
        role: KeyRole,
        key: &SigningKey,
        state: KeyState,
        now: i64,
    ) -> Result<NewKey, KeyStoreError> {
        let dnskey = key.dnskey();
        let (private_key, encrypted) = self.seal(&key.to_pkcs8())?;
        Ok(NewKey {
            zone,
            role,
            algorithm: key.algorithm(),
            key_tag: dnskey.key_tag(),
            state,
            created_at: now,
            published_at: matches!(state, KeyState::Published | KeyState::Active).then_some(now),
            active_at: (state == KeyState::Active).then_some(now),
            retired_at: None,
            ds_confirmed_at: None,
            encrypted,
            public_key: dnskey.public_key,
            private_key,
        })
    }

    /// Generates a key in the `generated` state (not yet in the DNSKEY `RRset`). The key stays
    /// inert until [`start_rollover`](Self::start_rollover) publishes it.
    ///
    /// # Errors
    /// A rollover of `role` already running (a `generated` or `published` key exists),
    /// an unsupported algorithm (only 13 and 15 can sign) or a database failure.
    pub async fn generate_key(
        &self,
        zone: &Name,
        role: KeyRole,
        algorithm: Algorithm,
    ) -> Result<KeyRecord, KeyStoreError> {
        let _shared = self.key_lock.read().await;
        if self
            .keys(zone)
            .await?
            .iter()
            .any(|k| k.role == role && matches!(k.state, KeyState::Generated | KeyState::Published))
        {
            return Err(KeyStoreError::RolloverInProgress(role));
        }
        let z = zone.clone();
        let new = self
            .offload(move |s| s.new_key(&z, role, algorithm, KeyState::Generated))
            .await?;
        let (id, new) = self
            .store
            .write(move |tx| insert(tx, &new).map(|id| (id, new)))
            .await?;
        Ok(record_of(id, &new))
    }

    /// Creates the initial active key set for a zone with no live keys: one CSK, or a KSK
    /// and a ZSK, as `layout` says, all of `algorithm`. Returns the zone's live keys.
    ///
    /// # Errors
    /// Unsupported algorithm or a database failure.
    pub async fn bootstrap(
        &self,
        zone: &Name,
        layout: KeyLayout,
        algorithm: Algorithm,
    ) -> Result<Vec<KeyRecord>, KeyStoreError> {
        let _guard = self.bootstrap_lock.lock().await;
        let _shared = self.key_lock.read().await;
        let existing = self.keys(zone).await?;
        if existing.iter().any(|k| k.state != KeyState::Removed) {
            return Ok(existing);
        }
        let roles: &[KeyRole] = match layout {
            KeyLayout::Csk => &[KeyRole::Csk],
            KeyLayout::KskZsk => &[KeyRole::Ksk, KeyRole::Zsk],
        };
        let z = zone.clone();
        let new = self
            .offload(move |s| {
                roles
                    .iter()
                    .map(|r| s.new_key(&z, *r, algorithm, KeyState::Active))
                    .collect::<Result<Vec<_>, _>>()
            })
            .await?;
        // The "no live keys" check is repeated inside the write transaction: concurrent
        // callers (an API enable and the zone reload) must not both insert a key set.
        let name = zone_key(zone);
        self.store
            .write(move |tx| {
                if list_zone(tx, &name)?
                    .iter()
                    .any(|k| k.state != KeyState::Removed)
                {
                    return Ok(());
                }
                for k in &new {
                    insert(tx, k)?;
                }
                Ok(())
            })
            .await?;
        self.keys(zone).await
    }

    /// Every key of a zone, including removed ones, oldest first.
    ///
    /// # Errors
    /// Database failure.
    pub async fn keys(&self, zone: &Name) -> Result<Vec<KeyRecord>, KeyStoreError> {
        let name = zone_key(zone);
        Ok(self.store.read(move |c| list_zone(c, &name)).await?)
    }

    /// The DNSKEYs to publish for a zone (published, active and retired keys); needs no
    /// passphrase.
    ///
    /// # Errors
    /// Database failure.
    pub async fn dnskeys(&self, zone: &Name) -> Result<Vec<(KeyRecord, Dnskey)>, KeyStoreError> {
        let name = zone_key(zone);
        let rows = self
            .store
            .read(move |c| {
                let mut stmt = c.prepare(&format!(
                    "SELECT {COLUMNS}, public_key FROM dnssec_keys WHERE zone = ?1 \
                     AND state IN ('published', 'active', 'retired') ORDER BY id"
                ))?;
                Ok(stmt
                    .query_map([name], |r| {
                        Ok((row_to_record(r)?, r.get::<_, Vec<u8>>(12)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?)
            })
            .await?;
        Ok(rows
            .into_iter()
            .map(|(rec, public)| {
                let dnskey = to_dnskey(rec.algorithm, rec.role, public);
                (rec, dnskey)
            })
            .collect())
    }

    /// The DS records to hand to the parent zone: SHA-256 then SHA-384 for every published or
    /// active key signing entry point (KSK or CSK), oldest key first, with the key each came from.
    ///
    /// # Errors
    /// Database failure or a key a digest cannot be made of.
    pub async fn ds_records(&self, zone: &Name) -> Result<Vec<(KeyRecord, Ds)>, KeyStoreError> {
        let mut out = Vec::new();
        for (rec, dnskey) in self.dnskeys(zone).await? {
            if !rec.role.is_sep() || !matches!(rec.state, KeyState::Published | KeyState::Active) {
                continue;
            }
            for digest in [DigestType::Sha256, DigestType::Sha384] {
                out.push((rec.clone(), ds_for(zone, &dnskey, digest)?));
            }
        }
        Ok(out)
    }

    /// Loads and decrypts one key for signing.
    ///
    /// # Errors
    /// Unknown or removed key, missing or wrong passphrase, or a database failure.
    pub async fn signing_key(&self, id: i64) -> Result<SigningKey, KeyStoreError> {
        let _shared = self.key_lock.read().await;
        let row = self
            .store
            .read(move |c| {
                Ok(c.query_row(
                    &format!(
                        "SELECT {COLUMNS}, encrypted, private_key FROM dnssec_keys WHERE id = ?1"
                    ),
                    [id],
                    secret_row,
                )
                .optional()?)
            })
            .await?;
        self.offload(move |s| open_key(row, id, s.pass().as_deref()).map(|(_, k)| k))
            .await
    }

    /// The keys [`dnsy_dnssec::ZoneSigner`] needs for a zone: every published, active and
    /// retired DNSKEY, with the private key decrypted only for keys that sign
    /// ([`ZoneKey::signs`]).
    ///
    /// # Errors
    /// Missing or wrong passphrase, or a database failure.
    pub async fn active_keys(&self, zone: &Name) -> Result<ActiveKeys, KeyStoreError> {
        let mut keys = Vec::new();
        for (rec, dnskey) in self.dnskeys(zone).await? {
            keys.push(if ZoneKey::signs(rec.role, rec.state) {
                ZoneKey::new(rec.role, rec.state, self.signing_key(rec.id).await?)
            } else {
                ZoneKey::public(rec.role, rec.state, dnskey)
            });
        }
        Ok(ActiveKeys { keys })
    }

    /// Re-encrypts every stored private key under `new` in one transaction: either all keys
    /// move to the new passphrase or none does. Also encrypts keys that were stored
    /// unencrypted. The new passphrase is used from then on; the operator must update the
    /// configured source (`DNSY_DNSSEC_PASSPHRASE` or the passphrase file) before the next
    /// start. Returns the number of keys re-encrypted.
    ///
    /// # Errors
    /// A key that cannot be decrypted with the current passphrase, keys changing while the
    /// passphrase is changed, or a database failure. Nothing is changed on error.
    pub async fn change_passphrase(&self, new: Passphrase) -> Result<usize, KeyStoreError> {
        // No key is sealed, inserted or decrypted while the passphrase is replaced, and the
        // key set is read inside the write transaction, so every key that exists when the
        // transaction commits is re-sealed.
        let _exclusive = self.key_lock.write().await;
        let new = Arc::new(new);
        let this = self.clone();
        let sealer = Arc::clone(&new);
        let count = self
            .store
            .write(move |tx| {
                let rows: Vec<SecretRow> = {
                    let mut stmt = tx.prepare(&format!(
                        "SELECT {COLUMNS}, encrypted, private_key FROM dnssec_keys \
                         WHERE state != 'removed' ORDER BY id"
                    ))?;
                    stmt.query_map([], secret_row)?
                        .collect::<Result<Vec<_>, _>>()?
                };
                let current = this.pass();
                // Re-seal everything first: a key that cannot be opened ends the change
                // before any row is touched.
                let mut resealed = Vec::with_capacity(rows.len());
                for row in rows {
                    let id = row.0.id;
                    let opened = open_key(Some(row), id, current.as_deref())
                        .and_then(|(_, key)| encrypt(&sealer, this.cost, &key.to_pkcs8()));
                    match opened {
                        Ok(blob) => resealed.push((id, blob)),
                        Err(e) => return Ok(Err(e)),
                    }
                }
                let count = resealed.len();
                for (id, blob) in resealed {
                    let n = tx.execute(
                        "UPDATE dnssec_keys SET private_key = ?1, encrypted = 1 WHERE id = ?2",
                        params![blob, id],
                    )?;
                    if n != 1 {
                        // An error return rolls the whole transaction back.
                        return Err(rusqlite::Error::StatementChangedRows(n).into());
                    }
                }
                Ok(Ok(count))
            })
            .await??;
        *self
            .passphrase
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(new);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use std::fmt::Write as _;

    #[tokio::test]
    async fn generate_csk_ecdsa_and_ed25519() {
        let f = fixture(Some("pw"));
        for (i, alg) in [Algorithm::EcdsaP256Sha256, Algorithm::Ed25519]
            .into_iter()
            .enumerate()
        {
            let z = if i == 0 {
                zone()
            } else {
                Name::from_ascii("other.test.").unwrap()
            };
            let rec = f.ks.generate_key(&z, KeyRole::Csk, alg).await.unwrap();
            assert_eq!(rec.state, KeyState::Generated);
            assert_eq!(rec.zone, z.to_string().to_ascii_lowercase());
            assert_eq!(rec.algorithm, alg);
            let key = f.ks.signing_key(rec.id).await.unwrap();
            assert_eq!(key.dnskey().key_tag(), rec.key_tag);
            assert_eq!(key.dnskey().flags, 257);
        }
        let err =
            f.ks.generate_key(&zone(), KeyRole::Zsk, Algorithm::RsaSha256)
                .await;
        assert!(matches!(err, Err(KeyStoreError::Key(_))));
    }

    #[tokio::test]
    async fn ds_records_are_sha256_then_sha384_for_the_entry_key_only() {
        let f = fixture(Some("pw"));
        assert_eq!(f.ks.ds_records(&zone()).await.unwrap(), []);
        f.ks.bootstrap(&zone(), KeyLayout::KskZsk, Algorithm::EcdsaP256Sha256)
            .await
            .unwrap();
        let records = f.ks.ds_records(&zone()).await.unwrap();
        let dnskeys = f.ks.dnskeys(&zone()).await.unwrap();
        let (ksk, ksk_dnskey) = dnskeys
            .iter()
            .find(|(r, _)| r.role == KeyRole::Ksk)
            .unwrap();
        assert_eq!(records.len(), 2, "the ZSK has no DS");
        for ((rec, ds), digest) in records.iter().zip([DigestType::Sha256, DigestType::Sha384]) {
            assert_eq!(rec.id, ksk.id);
            assert_eq!(*ds, ds_for(&zone(), ksk_dnskey, digest).unwrap());
        }
        let digest_types: Vec<u8> = records.iter().map(|(_, d)| d.digest_type).collect();
        assert_eq!(digest_types, [2, 4]);
    }

    #[tokio::test]
    async fn wrong_passphrase_on_stored_key_and_missing_passphrase() {
        let f = fixture(Some("right"));
        let rec =
            f.ks.generate_key(&zone(), KeyRole::Zsk, Algorithm::EcdsaP256Sha256)
                .await
                .unwrap();
        let wrong = KeyStore {
            passphrase: Arc::new(RwLock::new(Some(Arc::new(Passphrase::new("wrong"))))),
            key_lock: Arc::default(),
            ..f.ks.clone()
        };
        assert!(matches!(
            wrong.signing_key(rec.id).await,
            Err(KeyStoreError::Decrypt)
        ));
        let none = KeyStore {
            passphrase: Arc::new(RwLock::new(None)),
            key_lock: Arc::default(),
            ..f.ks.clone()
        };
        assert!(matches!(
            none.signing_key(rec.id).await,
            Err(KeyStoreError::PassphraseRequired)
        ));
        assert!(matches!(
            f.ks.signing_key(9999).await,
            Err(KeyStoreError::NotFound(9999))
        ));
    }

    #[tokio::test]
    async fn unencrypted_mode_flagged() {
        let plain = fixture(None);
        assert!(!plain.ks.keys_encrypted());
        let rec = plain
            .ks
            .generate_key(&zone(), KeyRole::Csk, Algorithm::Ed25519)
            .await
            .unwrap();
        let key = plain.ks.signing_key(rec.id).await.unwrap();
        let raw: (bool, Vec<u8>) = plain
            .ks
            .store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT encrypted, private_key FROM dnssec_keys WHERE id = ?1",
                    [rec.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert!(!raw.0);
        assert_eq!(raw.1, key.to_pkcs8().to_vec());

        let enc = fixture(Some("pw"));
        assert!(enc.ks.keys_encrypted());
        let rec = enc
            .ks
            .generate_key(&zone(), KeyRole::Csk, Algorithm::Ed25519)
            .await
            .unwrap();
        let der = enc.ks.signing_key(rec.id).await.unwrap().to_pkcs8();
        let raw: (bool, Vec<u8>) = enc
            .ks
            .store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT encrypted, private_key FROM dnssec_keys WHERE id = ?1",
                    [rec.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert!(raw.0);
        assert!(!raw.1.windows(der.len()).any(|w| w == der.as_slice()));
    }

    #[tokio::test]
    async fn debug_redacts_private_key() {
        let f = fixture(Some("hunter2-passphrase"));
        let rec =
            f.ks.generate_key(&zone(), KeyRole::Csk, Algorithm::EcdsaP256Sha256)
                .await
                .unwrap();
        let key = f.ks.signing_key(rec.id).await.unwrap();
        let der = key.to_pkcs8();
        let dump = format!(
            "{key:?} {:?} {:?}",
            f.ks,
            Passphrase::new("hunter2-passphrase")
        );
        assert!(!dump.contains("hunter2"));
        let hex = der.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        assert!(!dump.contains(&hex));
        assert!(!dump.contains(&format!("{:?}", der.as_slice())));
        assert!(dump.contains("redacted"));
    }

    #[tokio::test]
    async fn concurrent_bootstrap_creates_one_key_set() {
        let f = fixture(None);
        let zn = zone();
        let (first, second, third) = tokio::join!(
            f.ks.bootstrap(&zn, KeyLayout::Csk, ECDSA),
            f.ks.bootstrap(&zn, KeyLayout::Csk, ECDSA),
            f.ks.bootstrap(&zn, KeyLayout::Csk, ECDSA)
        );
        for result in [first, second, third] {
            result.unwrap();
        }
        let live = f.ks.keys(&zn).await.unwrap();
        assert_eq!(live.len(), 1, "racing bootstraps must not each add a CSK");
    }

    #[tokio::test]
    async fn bootstrap_creates_layout_once() {
        let f = fixture(None);
        let csk =
            f.ks.bootstrap(&zone(), KeyLayout::Csk, ECDSA)
                .await
                .unwrap();
        assert_eq!(csk.len(), 1);
        assert_eq!(csk[0].role, KeyRole::Csk);
        assert_eq!(csk[0].state, KeyState::Active);
        assert_eq!(csk[0].active_at, Some(T0));
        assert_eq!(
            f.ks.bootstrap(&zone(), KeyLayout::Csk, ECDSA)
                .await
                .unwrap()
                .len(),
            1
        );

        let other = Name::from_ascii("split.test.").unwrap();
        let split =
            f.ks.bootstrap(&other, KeyLayout::KskZsk, Algorithm::Ed25519)
                .await
                .unwrap();
        let roles: Vec<_> = split.iter().map(|k| k.role).collect();
        assert_eq!(roles, [KeyRole::Ksk, KeyRole::Zsk]);
        assert!(split.iter().all(|k| k.algorithm == Algorithm::Ed25519));
        let dnskeys = f.ks.dnskeys(&other).await.unwrap();
        assert_eq!(dnskeys.len(), 2);
        assert_eq!(dnskeys[0].1.flags, 257);
        assert_eq!(dnskeys[1].1.flags, 256);
        assert_eq!(dnskeys[0].1.key_tag(), dnskeys[0].0.key_tag);
    }

    #[tokio::test]
    async fn concurrent_split_layout_bootstrap_creates_one_key_pair() {
        let f = fixture(None);
        let zn = zone();
        let (first, second, third) = tokio::join!(
            f.ks.bootstrap(&zn, KeyLayout::KskZsk, ECDSA),
            f.ks.bootstrap(&zn, KeyLayout::KskZsk, ECDSA),
            f.ks.bootstrap(&zn, KeyLayout::KskZsk, ECDSA)
        );
        for result in [first, second, third] {
            assert_eq!(result.unwrap().len(), 2);
        }
        assert_eq!(f.ks.keys(&zn).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn generate_key_twice_is_conflict() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::KskZsk, ECDSA).await.unwrap();
        let alg = Algorithm::EcdsaP256Sha256;
        let first = f.ks.generate_key(&z, KeyRole::Zsk, alg).await.unwrap();
        assert_eq!(first.state, KeyState::Generated);
        assert!(matches!(
            f.ks.generate_key(&z, KeyRole::Zsk, alg).await,
            Err(KeyStoreError::RolloverInProgress(KeyRole::Zsk))
        ));
        // Another role is independent.
        f.ks.generate_key(&z, KeyRole::Ksk, alg).await.unwrap();
    }

    #[tokio::test]
    async fn change_passphrase_reencrypts_all_keys() {
        let f = fixture(Some("old"));
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::KskZsk, ECDSA).await.unwrap();
        let other = Name::from_ascii("other.test.").unwrap();
        f.ks.bootstrap(&other, KeyLayout::Csk, ECDSA).await.unwrap();
        let before = f.ks.keys(&z).await.unwrap();

        assert_eq!(
            f.ks.change_passphrase(Passphrase::new("new"))
                .await
                .unwrap(),
            3
        );
        for k in &before {
            f.ks.signing_key(k.id).await.unwrap();
        }
        assert_eq!(f.ks.keys(&z).await.unwrap(), before, "metadata untouched");

        // A store opened with the old passphrase can no longer read the keys, the new one can.
        let reopen = |pass: &str| {
            KeyStore::open(
                f.ks.store.clone(),
                Some(Passphrase::new(pass)),
                Arc::new(f.clock.clone()),
            )
            .with_kdf_cost(CHEAP)
        };
        assert!(matches!(
            reopen("old").signing_key(before[0].id).await,
            Err(KeyStoreError::Decrypt)
        ));
        reopen("new").signing_key(before[0].id).await.unwrap();
        // New keys are sealed under the new passphrase too.
        let k =
            f.ks.generate_key(&z, KeyRole::Zsk, Algorithm::Ed25519)
                .await
                .unwrap();
        reopen("new").signing_key(k.id).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn keys_created_during_a_passphrase_change_end_up_under_the_new_passphrase() {
        let f = fixture(Some("old"));
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::Csk, ECDSA).await.unwrap();
        let mut tasks = Vec::new();
        for i in 0..8 {
            let ks = f.ks.clone();
            let zone = Name::from_ascii(&format!("z{i}.test.")).unwrap();
            tasks.push(tokio::spawn(async move {
                ks.generate_key(&zone, KeyRole::Zsk, Algorithm::Ed25519)
                    .await
                    .unwrap()
                    .id
            }));
        }
        let change = tokio::spawn({
            let ks = f.ks.clone();
            async move { ks.change_passphrase(Passphrase::new("new")).await.unwrap() }
        });
        let mut ids = vec![f.ks.keys(&z).await.unwrap()[0].id];
        for t in tasks {
            ids.push(t.await.unwrap());
        }
        change.await.unwrap();
        // Every key, whenever it was created, opens with the new passphrase and with that only.
        let fresh = KeyStore::open(
            f.ks.store.clone(),
            Some(Passphrase::new("new")),
            Arc::new(f.clock.clone()),
        )
        .with_kdf_cost(CHEAP);
        let stale = KeyStore::open(
            f.ks.store.clone(),
            Some(Passphrase::new("old")),
            Arc::new(f.clock.clone()),
        )
        .with_kdf_cost(CHEAP);
        for id in ids {
            fresh.signing_key(id).await.unwrap();
            assert!(matches!(
                stale.signing_key(id).await,
                Err(KeyStoreError::Decrypt)
            ));
        }
    }

    #[tokio::test]
    async fn change_passphrase_encrypts_unencrypted_keys_and_is_atomic() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, KeyLayout::KskZsk, ECDSA).await.unwrap();
        assert!(!f.ks.keys_encrypted());
        f.ks.change_passphrase(Passphrase::new("pw")).await.unwrap();
        assert!(f.ks.keys_encrypted());
        let ids: Vec<i64> = f.ks.keys(&z).await.unwrap().iter().map(|k| k.id).collect();
        let encrypted: i64 =
            f.ks.store
                .read(|c| {
                    Ok(c.query_row(
                        "SELECT count(*) FROM dnssec_keys WHERE encrypted = 1",
                        [],
                        |r| r.get(0),
                    )?)
                })
                .await
                .unwrap();
        assert_eq!(encrypted, 2);

        // One undecryptable key: the change fails and the other key keeps its old blob.
        let bad = ids[1];
        f.ks.store
            .write(move |tx| {
                tx.execute(
                    "UPDATE dnssec_keys SET private_key = x'00' WHERE id = ?1",
                    [bad],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            f.ks.change_passphrase(Passphrase::new("third")).await,
            Err(KeyStoreError::Decrypt)
        ));
        f.ks.signing_key(ids[0]).await.unwrap();
    }
}
