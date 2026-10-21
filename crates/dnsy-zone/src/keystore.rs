//! Persistent per-zone DNSSEC key sets with encrypted private keys and rollover.
//!
//! Private keys are PKCS#8 documents sealed with AES-256-GCM under a key derived from the
//! operator's passphrase with argon2id (fresh salt and nonce per key). Without a passphrase
//! they are stored unencrypted and [`KeyStore::keys_encrypted`] is false. Key material is
//! zeroized after use and never appears in `Debug` output, errors or logs.

use std::fmt;
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use dnsy_dnssec::{
    ActiveKeys, Algorithm, Clock, DnssecError, KeyRecord, KeyRole, KeyState, RolloverTimings,
    SigningKey, Transition, ZoneKey, plan,
};
use dnsy_proto::{Dnskey, Name};
use dnsy_store::{Store, StoreError};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::policy::{DnssecPolicy, KeyLayout};

const BLOB_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
/// version, memory KiB (u32), iterations (u32), salt
const HEADER_LEN: usize = 1 + 4 + 4 + SALT_LEN;
/// Largest KDF cost accepted from a stored blob or bundle, so hostile input cannot exhaust memory.
const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_KDF_ITERATIONS: u32 = 16;
const BUNDLE_FORMAT: u32 = 1;

/// Failures of the key store. None of them carries key material or the passphrase.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("key error: {0}")]
    Key(#[from] DnssecError),
    #[error("keys are encrypted but no passphrase is configured")]
    PassphraseRequired,
    #[error("cannot decrypt key material (wrong passphrase or corrupted data)")]
    Decrypt,
    #[error("passphrase file {path}: {reason}")]
    PassphraseFile { path: String, reason: String },
    #[error("i/o error: {0}")]
    Io(String),
    #[error("key {0} not found")]
    NotFound(i64),
    #[error("a {0} rollover is already in progress for this zone")]
    RolloverInProgress(KeyRole),
    #[error("zone has no active {0} to roll over")]
    NoActiveKey(KeyRole),
    #[error("{0}")]
    InvalidState(&'static str),
    #[error("no {0} rollover is in progress for this zone")]
    NoRollover(String),
    #[error("invalid key bundle: {0}")]
    Bundle(&'static str),
}

/// A key-encryption passphrase. Zeroized on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    pub fn new(secret: impl Into<String>) -> Passphrase {
        Passphrase(Zeroizing::new(secret.into()))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

/// Resolves the passphrase from `env` (the value of `DNSY_DNSSEC_PASSPHRASE`, empty counts as
/// unset), else from the first line of `file`. `None` means keys are stored unencrypted.
///
/// # Errors
/// The file cannot be read or is empty.
pub fn resolve_passphrase(
    env: Option<String>,
    file: Option<&Path>,
) -> Result<Option<Passphrase>, KeyStoreError> {
    if let Some(v) = env.filter(|v| !v.is_empty()) {
        return Ok(Some(Passphrase::new(v)));
    }
    let Some(path) = file else { return Ok(None) };
    let fail = |reason: &str| KeyStoreError::PassphraseFile {
        path: path.display().to_string(),
        reason: reason.to_owned(),
    };
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| fail(&e.to_string()))?);
    let line = text.lines().next().unwrap_or_default();
    if line.is_empty() {
        return Err(fail("file is empty"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .map_err(|e| fail(&e.to_string()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            tracing::warn!(path = %path.display(), "passphrase file is accessible to other users; use mode 0600");
        }
    }
    Ok(Some(Passphrase::new(line)))
}

/// [`resolve_passphrase`] reading the real `DNSY_DNSSEC_PASSPHRASE` environment variable.
///
/// # Errors
/// See [`resolve_passphrase`].
pub fn passphrase_from_environment(
    file: Option<&Path>,
) -> Result<Option<Passphrase>, KeyStoreError> {
    resolve_passphrase(std::env::var(dnsy_config::PASSPHRASE_ENV).ok(), file)
}

/// Argon2id cost for deriving the key-encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    pub memory_kib: u32,
    pub iterations: u32,
}

impl KdfCost {
    /// Cost of backup bundles: 64 MiB, 3 iterations, 1 lane.
    pub const BUNDLE: KdfCost = KdfCost {
        memory_kib: 64 * 1024,
        iterations: 3,
    };
}

impl Default for KdfCost {
    /// OWASP minimum for argon2id: 19 MiB, 2 iterations, 1 lane.
    fn default() -> Self {
        KdfCost {
            memory_kib: 19 * 1024,
            iterations: 2,
        }
    }
}

fn derive(
    pass: &Passphrase,
    cost: KdfCost,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, KeyStoreError> {
    let params = Params::new(cost.memory_kib, cost.iterations, 1, Some(32))
        .map_err(|_| KeyStoreError::Decrypt)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), salt, key.as_mut())
        .map_err(|_| KeyStoreError::Decrypt)?;
    Ok(key)
}

fn fill(buf: &mut [u8]) -> Result<(), KeyStoreError> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| KeyStoreError::Key(DnssecError::KeyGeneration))
}

fn aead(key: &[u8; 32]) -> Result<LessSafeKey, KeyStoreError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| KeyStoreError::Decrypt)
}

/// Seals `plain` as `header || nonce || ciphertext+tag`; the header (version, KDF cost, salt)
/// is authenticated.
fn encrypt(pass: &Passphrase, cost: KdfCost, plain: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    fill(&mut salt)?;
    fill(&mut nonce)?;
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + plain.len() + 16);
    out.push(BLOB_VERSION);
    out.extend_from_slice(&cost.memory_kib.to_be_bytes());
    out.extend_from_slice(&cost.iterations.to_be_bytes());
    out.extend_from_slice(&salt);
    let key = derive(pass, cost, &salt)?;
    let header = out.clone();
    let mut body = Zeroizing::new(plain.to_vec());
    aead(&key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header),
            &mut *body,
        )
        .map_err(|_| KeyStoreError::Decrypt)?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decrypt(pass: &Passphrase, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
    if blob.len() < HEADER_LEN + NONCE_LEN + AES_256_GCM.tag_len() || blob[0] != BLOB_VERSION {
        return Err(KeyStoreError::Decrypt);
    }
    let (header, rest) = blob.split_at(HEADER_LEN);
    let (nonce, sealed) = rest.split_at(NONCE_LEN);
    let memory_kib = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let iterations = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    if memory_kib > MAX_KDF_MEMORY_KIB || iterations > MAX_KDF_ITERATIONS {
        return Err(KeyStoreError::Decrypt);
    }
    let key = derive(
        pass,
        KdfCost {
            memory_kib,
            iterations,
        },
        &header[9..],
    )?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| KeyStoreError::Decrypt)?;
    let mut buf = Zeroizing::new(sealed.to_vec());
    let plain_len = aead(&key)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(header),
            &mut buf,
        )
        .map_err(|_| KeyStoreError::Decrypt)?
        .len();
    buf.truncate(plain_len);
    Ok(buf)
}

fn zone_key(zone: &Name) -> String {
    zone.to_string().to_ascii_lowercase()
}

const COLUMNS: &str = "id, zone, role, algorithm, key_tag, state, created_at, published_at, \
                       active_at, retired_at, removed_at, ds_confirmed_at";

fn row_to_record(r: &rusqlite::Row<'_>) -> Result<KeyRecord, rusqlite::Error> {
    let bad = |i: usize| {
        rusqlite::Error::InvalidColumnType(i, "enum".into(), rusqlite::types::Type::Text)
    };
    let role: String = r.get(2)?;
    let state: String = r.get(5)?;
    Ok(KeyRecord {
        id: r.get(0)?,
        zone: r.get(1)?,
        role: KeyRole::parse(&role).ok_or_else(|| bad(2))?,
        algorithm: Algorithm::from(r.get::<_, u8>(3)?),
        key_tag: r.get(4)?,
        state: KeyState::parse(&state).ok_or_else(|| bad(5))?,
        created_at: r.get(6)?,
        published_at: r.get(7)?,
        active_at: r.get(8)?,
        retired_at: r.get(9)?,
        removed_at: r.get(10)?,
        ds_confirmed_at: r.get(11)?,
    })
}

fn list_zone(c: &Connection, zone: &str) -> Result<Vec<KeyRecord>, StoreError> {
    let mut stmt = c.prepare(&format!(
        "SELECT {COLUMNS} FROM dnssec_keys WHERE zone = ?1 ORDER BY id"
    ))?;
    Ok(stmt
        .query_map([zone], row_to_record)?
        .collect::<Result<_, _>>()?)
}

/// A key to insert: public metadata plus the already-sealed private key.
struct NewKey {
    zone: String,
    role: KeyRole,
    algorithm: Algorithm,
    key_tag: u16,
    state: KeyState,
    created_at: i64,
    published_at: Option<i64>,
    active_at: Option<i64>,
    retired_at: Option<i64>,
    ds_confirmed_at: Option<i64>,
    encrypted: bool,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

fn insert(tx: &Transaction<'_>, k: &NewKey) -> Result<i64, StoreError> {
    tx.execute(
        "INSERT INTO dnssec_keys (zone, role, algorithm, key_tag, state, created_at, published_at, \
         active_at, retired_at, ds_confirmed_at, encrypted, public_key, private_key) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            k.zone,
            k.role.as_str(),
            k.algorithm.number(),
            k.key_tag,
            k.state.as_str(),
            k.created_at,
            k.published_at,
            k.active_at,
            k.retired_at,
            k.ds_confirmed_at,
            k.encrypted,
            k.public_key,
            k.private_key
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

fn record_of(id: i64, k: &NewKey) -> KeyRecord {
    KeyRecord {
        id,
        zone: k.zone.clone(),
        role: k.role,
        algorithm: k.algorithm,
        key_tag: k.key_tag,
        state: k.state,
        created_at: k.created_at,
        published_at: k.published_at,
        active_at: k.active_at,
        retired_at: k.retired_at,
        removed_at: None,
        ds_confirmed_at: k.ds_confirmed_at,
    }
}

fn to_dnskey(algorithm: Algorithm, role: KeyRole, public_key: Vec<u8>) -> Dnskey {
    Dnskey {
        flags: 0x0100 | u16::from(role.is_sep()),
        protocol: 3,
        algorithm: algorithm.number(),
        public_key,
    }
}

/// One key inside an export bundle. The PKCS#8 is base64 and wiped on drop.
#[derive(Serialize, Deserialize)]
struct BundleKey {
    zone: String,
    role: String,
    algorithm: u8,
    key_tag: u16,
    state: String,
    created_at: i64,
    published_at: Option<i64>,
    active_at: Option<i64>,
    retired_at: Option<i64>,
    ds_confirmed_at: Option<i64>,
    pkcs8: String,
}

impl Drop for BundleKey {
    fn drop(&mut self) {
        self.pkcs8.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct Bundle {
    format: u32,
    keys: Vec<BundleKey>,
}

/// Per-zone DNSSEC key sets in SQLite.
#[derive(Clone)]
pub struct KeyStore {
    store: Store,
    /// Shared by clones so a passphrase change reaches every holder of the store.
    passphrase: Arc<RwLock<Option<Arc<Passphrase>>>>,
    /// Held shared by everything that seals, inserts or decrypts keys, and exclusively by a
    /// passphrase change, so no key is sealed or read under a passphrase that is being
    /// replaced.
    key_lock: Arc<tokio::sync::RwLock<()>>,
    clock: Arc<dyn Clock>,
    cost: KdfCost,
    /// Cost of sealing a backup bundle, which leaves the machine and so gets a stronger KDF.
    bundle_cost: KdfCost,
    /// Serialises `bootstrap`: its check for existing keys and the insert must not interleave.
    bootstrap_lock: Arc<tokio::sync::Mutex<()>>,
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
    pub(crate) fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// True when new private keys are encrypted at rest (the API's `keys_encrypted` flag).
    #[must_use]
    pub fn keys_encrypted(&self) -> bool {
        self.pass().is_some()
    }

    /// The current passphrase.
    fn pass(&self) -> Option<Arc<Passphrase>> {
        self.passphrase
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Runs CPU-heavy key work (argon2id, key generation) off the async threads.
    async fn offload<T: Send + 'static>(
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

    fn new_key(
        &self,
        zone: &Name,
        role: KeyRole,
        algorithm: Algorithm,
        state: KeyState,
    ) -> Result<NewKey, KeyStoreError> {
        let now = self.clock.now();
        let key = SigningKey::generate(algorithm, role.is_sep())?;
        self.stored_key(zone_key(zone), role, &key, state, now)
    }

    fn stored_key(
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

    fn bundle_key(&self, k: &BundleKey) -> Result<NewKey, KeyStoreError> {
        let role = KeyRole::parse(&k.role).ok_or(KeyStoreError::Bundle("unknown key role"))?;
        let state = KeyState::parse(&k.state).ok_or(KeyStoreError::Bundle("unknown key state"))?;
        if state == KeyState::Removed {
            return Err(KeyStoreError::Bundle("removed key in bundle"));
        }
        let der = Zeroizing::new(
            B64.decode(&k.pkcs8)
                .map_err(|_| KeyStoreError::Bundle("malformed key"))?,
        );
        let key = SigningKey::from_pkcs8(Algorithm::from(k.algorithm), role.is_sep(), &der)
            .map_err(|_| KeyStoreError::Bundle("malformed key"))?;
        if key.dnskey().key_tag() != k.key_tag {
            return Err(KeyStoreError::Bundle("key tag does not match the key"));
        }
        let mut nk =
            self.stored_key(k.zone.to_ascii_lowercase(), role, &key, state, k.created_at)?;
        nk.published_at = k.published_at;
        nk.active_at = k.active_at;
        nk.retired_at = k.retired_at;
        nk.ds_confirmed_at = k.ds_confirmed_at;
        Ok(nk)
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
        if self.keys(zone).await?.iter().any(|k| {
            k.role == role && matches!(k.state, KeyState::Generated | KeyState::Published)
        }) {
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
    /// and a ZSK, as the policy's layout says. Returns the zone's live keys.
    ///
    /// # Errors
    /// Unsupported policy algorithm or a database failure.
    pub async fn bootstrap(
        &self,
        zone: &Name,
        policy: &DnssecPolicy,
    ) -> Result<Vec<KeyRecord>, KeyStoreError> {
        let _guard = self.bootstrap_lock.lock().await;
        let _shared = self.key_lock.read().await;
        let existing = self.keys(zone).await?;
        if existing.iter().any(|k| k.state != KeyState::Removed) {
            return Ok(existing);
        }
        let roles: &[KeyRole] = match policy.key_layout {
            KeyLayout::Csk => &[KeyRole::Csk],
            KeyLayout::KskZsk => &[KeyRole::Ksk, KeyRole::Zsk],
        };
        let algorithm = Algorithm::from(policy.algorithm);
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
            let now = self.clock.now();
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
        let now = self.clock.now();
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
        let now = self.clock.now();
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
        let now = self.clock.now();
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

    /// Exports every non-removed key (of one zone, or all) as a bundle encrypted under
    /// `bundle_passphrase`, which may differ from the store's passphrase.
    ///
    /// # Errors
    /// Missing store passphrase for encrypted keys, or a database failure.
    pub async fn export_bundle(
        &self,
        zone: Option<&Name>,
        bundle_passphrase: &Passphrase,
    ) -> Result<Vec<u8>, KeyStoreError> {
        let _shared = self.key_lock.read().await;
        let filter = zone.map(zone_key);
        let rows = self
            .store
            .read(move |c| {
                let mut stmt = c.prepare(&format!(
                    "SELECT {COLUMNS}, encrypted, private_key FROM dnssec_keys \
                     WHERE state != 'removed' AND (?1 IS NULL OR zone = ?1) ORDER BY id"
                ))?;
                Ok(stmt
                    .query_map([filter], secret_row)?
                    .collect::<Result<Vec<_>, _>>()?)
            })
            .await?;
        let bundle_pass = bundle_passphrase.clone();
        self.offload(move |s| {
            let mut keys = Vec::with_capacity(rows.len());
            for row in rows {
                let id = row.0.id;
                let (rec, key) = open_key(Some(row), id, s.pass().as_deref())?;
                keys.push(BundleKey {
                    zone: rec.zone,
                    role: rec.role.as_str().into(),
                    algorithm: rec.algorithm.number(),
                    key_tag: rec.key_tag,
                    state: rec.state.as_str().into(),
                    created_at: rec.created_at,
                    published_at: rec.published_at,
                    active_at: rec.active_at,
                    retired_at: rec.retired_at,
                    ds_confirmed_at: rec.ds_confirmed_at,
                    pkcs8: B64.encode(key.to_pkcs8().as_slice()),
                });
            }
            let bundle = Bundle {
                format: BUNDLE_FORMAT,
                keys,
            };
            let json = Zeroizing::new(
                serde_json::to_vec(&bundle)
                    .map_err(|_| KeyStoreError::Bundle("cannot serialize"))?,
            );
            drop(bundle);
            encrypt(&bundle_pass, s.bundle_cost, &json)
        })
        .await
    }

    /// Imports a bundle made by [`export_bundle`](Self::export_bundle), re-sealing the keys
    /// under the store's passphrase. Keys already present (same zone, algorithm and public
    /// key) are skipped. Returns the number of keys added.
    ///
    /// # Errors
    /// Wrong bundle passphrase, a corrupt or inconsistent bundle, or a database failure.
    pub async fn import_bundle(
        &self,
        bundle: &[u8],
        bundle_passphrase: &Passphrase,
    ) -> Result<usize, KeyStoreError> {
        let _shared = self.key_lock.read().await;
        let bundle = bundle.to_vec();
        let bundle_pass = bundle_passphrase.clone();
        let new = self
            .offload(move |s| {
                let json = decrypt(&bundle_pass, &bundle)?;
                let parsed: Bundle = serde_json::from_slice(&json)
                    .map_err(|_| KeyStoreError::Bundle("not a key bundle"))?;
                drop(json);
                if parsed.format != BUNDLE_FORMAT {
                    return Err(KeyStoreError::Bundle("unsupported bundle format"));
                }
                parsed
                    .keys
                    .iter()
                    .map(|k| s.bundle_key(k))
                    .collect::<Result<Vec<_>, _>>()
            })
            .await?;
        Ok(self
            .store
            .write(move |tx| {
                let mut added = 0;
                for k in &new {
                    let dup: bool = tx.query_row(
                        "SELECT EXISTS (SELECT 1 FROM dnssec_keys WHERE zone = ?1 AND algorithm = ?2 \
                         AND public_key = ?3 AND state != 'removed')",
                        params![k.zone, k.algorithm.number(), k.public_key],
                        |r| r.get(0),
                    )?;
                    if !dup {
                        insert(tx, k)?;
                        added += 1;
                    }
                }
                Ok(added)
            })
            .await?)
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

    /// [`export_bundle`](Self::export_bundle) into a new file with mode 0600.
    ///
    /// # Errors
    /// As `export_bundle`, plus an existing file or an i/o failure.
    pub async fn export_bundle_to_file(
        &self,
        zone: Option<&Name>,
        bundle_passphrase: &Passphrase,
        path: &Path,
    ) -> Result<(), KeyStoreError> {
        let bytes = self.export_bundle(zone, bundle_passphrase).await?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(path)
            .map_err(|e| KeyStoreError::Io(e.to_string()))?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| KeyStoreError::Io(e.to_string()))
    }

    /// [`import_bundle`](Self::import_bundle) from a file.
    ///
    /// # Errors
    /// As `import_bundle`, plus an i/o failure.
    pub async fn import_bundle_from_file(
        &self,
        path: &Path,
        bundle_passphrase: &Passphrase,
    ) -> Result<usize, KeyStoreError> {
        let bytes = std::fs::read(path).map_err(|e| KeyStoreError::Io(e.to_string()))?;
        self.import_bundle(&bytes, bundle_passphrase).await
    }
}

type SecretRow = (KeyRecord, bool, Vec<u8>);

fn secret_row(r: &rusqlite::Row<'_>) -> Result<SecretRow, rusqlite::Error> {
    Ok((row_to_record(r)?, r.get(12)?, r.get(13)?))
}

/// Decrypts a fetched row into its record and signing key.
fn open_key(
    row: Option<SecretRow>,
    id: i64,
    pass: Option<&Passphrase>,
) -> Result<(KeyRecord, SigningKey), KeyStoreError> {
    let (rec, encrypted, blob) = row.ok_or(KeyStoreError::NotFound(id))?;
    if rec.state == KeyState::Removed {
        return Err(KeyStoreError::InvalidState("key was removed"));
    }
    let der = if encrypted {
        decrypt(pass.ok_or(KeyStoreError::PassphraseRequired)?, &blob)?
    } else {
        Zeroizing::new(blob)
    };
    let key = SigningKey::from_pkcs8(rec.algorithm, rec.role.is_sep(), &der)?;
    Ok((rec, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dnsy_dnssec::ManualClock;
    use std::fmt::Write as _;

    const CHEAP: KdfCost = KdfCost {
        memory_kib: 8,
        iterations: 1,
    };
    const T: RolloverTimings = RolloverTimings {
        dnskey_ttl: 3600,
        propagation: 0,
        max_signature_validity: 10_000,
    };
    const T0: i64 = 1_000_000;

    struct Fixture {
        ks: KeyStore,
        clock: ManualClock,
        _dir: tempfile::TempDir,
    }

    fn fixture(pass: Option<&str>) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("dnsy.db")).unwrap();
        let clock = ManualClock::new(T0);
        let ks = KeyStore::open(store, pass.map(Passphrase::new), Arc::new(clock.clone()))
            .with_kdf_cost(CHEAP);
        Fixture {
            ks,
            clock,
            _dir: dir,
        }
    }

    fn zone() -> Name {
        Name::from_ascii("Example.COM.").unwrap()
    }

    fn policy(json: &str) -> DnssecPolicy {
        serde_json::from_str(json).unwrap()
    }

    fn states(keys: &[KeyRecord], role: KeyRole) -> Vec<KeyState> {
        keys.iter()
            .filter(|k| k.role == role)
            .map(|k| k.state)
            .collect()
    }

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

    #[test]
    fn pkcs8_encrypt_roundtrip() {
        let key = SigningKey::generate(Algorithm::Ed25519, false).unwrap();
        let der = key.to_pkcs8();
        let pass = Passphrase::new("correct horse");
        let blob = encrypt(&pass, CHEAP, &der).unwrap();
        assert!(!blob.windows(der.len()).any(|w| w == der.as_slice()));
        assert_eq!(decrypt(&pass, &blob).unwrap().as_slice(), der.as_slice());
        // Fresh salt and nonce per seal.
        assert_ne!(blob, encrypt(&pass, CHEAP, &der).unwrap());
    }

    #[test]
    fn wrong_passphrase_fails_cleanly() {
        let blob = encrypt(&Passphrase::new("right"), CHEAP, b"secret").unwrap();
        assert!(matches!(
            decrypt(&Passphrase::new("wrong"), &blob),
            Err(KeyStoreError::Decrypt)
        ));
        let pass = Passphrase::new("right");
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            decrypt(&pass, &tampered),
            Err(KeyStoreError::Decrypt)
        ));
        let mut header = blob.clone();
        header[8] ^= 1;
        assert!(matches!(
            decrypt(&pass, &header),
            Err(KeyStoreError::Decrypt)
        ));
        assert!(matches!(
            decrypt(&pass, &blob[..10]),
            Err(KeyStoreError::Decrypt)
        ));
        let mut greedy = blob;
        greedy[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decrypt(&pass, &greedy),
            Err(KeyStoreError::Decrypt)
        ));
        let msg = KeyStoreError::Decrypt.to_string();
        assert!(!msg.contains("right") && !msg.contains("secret"));
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
    async fn active_keys_load_signers_and_sign_a_zone() {
        let f = fixture(Some("pw"));
        f.ks.bootstrap(&zone(), &policy(r#"{"key_layout":"ksk_zsk"}"#))
            .await
            .unwrap();
        f.ks.start_rollover(&zone(), KeyRole::Ksk, Algorithm::EcdsaP256Sha256)
            .await
            .unwrap();
        let rec =
            f.ks.start_rollover(&zone(), KeyRole::Zsk, Algorithm::EcdsaP256Sha256)
                .await
                .unwrap();
        let keys = f.ks.active_keys(&zone()).await.unwrap();
        let published_zsk = keys.keys.iter().find(|k| k.dnskey.key_tag() == rec.key_tag);
        assert_eq!(keys.keys.len(), 4);
        assert_eq!(published_zsk.unwrap().state, KeyState::Published);

        let (z, _) =
            crate::Zone::from_json(include_str!("../tests/fixtures/example.com.json")).unwrap();
        let p = z.dnssec.as_ref().unwrap().signing_policy().unwrap();
        let now = u32::try_from(T0).unwrap();
        let signed = dnsy_dnssec::ZoneSigner::sign(&z.signing_data(), &keys, &p, now).unwrap();
        let dnskey = signed
            .rrset(&z.origin, dnsy_proto::RecordType::Dnskey)
            .unwrap();
        assert_eq!(dnskey.records.len(), 4);
        assert_eq!(dnskey.rrsigs.len(), 2, "both KSKs sign the DNSKEY RRset");

        let locked = KeyStore {
            passphrase: Arc::new(RwLock::new(None)),
            key_lock: Arc::default(),
            ..f.ks.clone()
        };
        assert!(locked.active_keys(&zone()).await.is_err());
    }

    #[tokio::test]
    async fn concurrent_bootstrap_creates_one_key_set() {
        let f = fixture(None);
        let pol = policy("{}");
        let zn = zone();
        let (first, second, third) = tokio::join!(
            f.ks.bootstrap(&zn, &pol),
            f.ks.bootstrap(&zn, &pol),
            f.ks.bootstrap(&zn, &pol)
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
        let csk = f.ks.bootstrap(&zone(), &policy("{}")).await.unwrap();
        assert_eq!(csk.len(), 1);
        assert_eq!(csk[0].role, KeyRole::Csk);
        assert_eq!(csk[0].state, KeyState::Active);
        assert_eq!(csk[0].active_at, Some(T0));
        assert_eq!(
            f.ks.bootstrap(&zone(), &policy("{}")).await.unwrap().len(),
            1
        );

        let other = Name::from_ascii("split.test.").unwrap();
        let split =
            f.ks.bootstrap(
                &other,
                &policy(r#"{"key_layout":"ksk_zsk","algorithm":15}"#),
            )
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
        let pol = policy(r#"{"key_layout":"ksk_zsk"}"#);
        let zn = zone();
        let (first, second, third) = tokio::join!(
            f.ks.bootstrap(&zn, &pol),
            f.ks.bootstrap(&zn, &pol),
            f.ks.bootstrap(&zn, &pol)
        );
        for result in [first, second, third] {
            assert_eq!(result.unwrap().len(), 2);
        }
        assert_eq!(f.ks.keys(&zn).await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn zsk_rollover_states_advance_on_schedule() {
        let f = fixture(Some("pw"));
        let z = zone();
        let p = policy(r#"{"key_layout":"ksk_zsk"}"#);
        f.ks.bootstrap(&z, &p).await.unwrap();
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
    async fn generate_key_twice_is_conflict() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, &policy(r#"{"key_layout":"ksk_zsk"}"#))
            .await
            .unwrap();
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
    async fn generated_key_is_inert_until_a_rollover_publishes_it() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, &policy(r#"{"key_layout":"ksk_zsk"}"#))
            .await
            .unwrap();
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
    async fn bundles_use_the_strong_kdf_cost() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(&dir.path().join("k.db")).unwrap();
        let ks = KeyStore::open(db, None, Arc::new(ManualClock::new(T0)));
        let z = zone();
        ks.bootstrap(&z, &policy("{}")).await.unwrap();
        let bundle = ks
            .export_bundle(None, &Passphrase::new("twelve-chars"))
            .await
            .unwrap();
        assert_eq!(
            u32::from_be_bytes(bundle[1..5].try_into().unwrap()),
            64 * 1024
        );
        assert_eq!(u32::from_be_bytes(bundle[5..9].try_into().unwrap()), 3);
    }

    #[tokio::test]
    async fn ksk_rollover_waits_for_ds_confirmation() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, &policy("{}")).await.unwrap();
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
        f.ks.bootstrap(&z, &policy(r#"{"key_layout":"ksk_zsk"}"#))
            .await
            .unwrap();
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
        f.ks.bootstrap(&z, &policy(r#"{"key_layout":"ksk_zsk"}"#))
            .await
            .unwrap();
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
    async fn change_passphrase_reencrypts_all_keys() {
        let f = fixture(Some("old"));
        let z = zone();
        f.ks.bootstrap(&z, &policy(r#"{"key_layout":"ksk_zsk"}"#))
            .await
            .unwrap();
        let other = Name::from_ascii("other.test.").unwrap();
        f.ks.bootstrap(&other, &policy("{}")).await.unwrap();
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
        f.ks.bootstrap(&z, &policy("{}")).await.unwrap();
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
        f.ks.bootstrap(&z, &policy(r#"{"key_layout":"ksk_zsk"}"#))
            .await
            .unwrap();
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

    #[tokio::test]
    async fn confirm_ds_rejects_bad_targets() {
        let f = fixture(None);
        let z = zone();
        f.ks.bootstrap(&z, &policy(r#"{"key_layout":"ksk_zsk"}"#))
            .await
            .unwrap();
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
        f.ks.bootstrap(&z, &policy("{}")).await.unwrap();
        let skipped = Name::from_ascii("skip.test.").unwrap();
        f.ks.bootstrap(&skipped, &policy("{}")).await.unwrap();
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

    #[tokio::test]
    async fn backup_bundle_roundtrip() {
        let src = fixture(Some("store-a"));
        let z = zone();
        let other = Name::from_ascii("other.test.").unwrap();
        src.ks
            .bootstrap(&z, &policy(r#"{"key_layout":"ksk_zsk"}"#))
            .await
            .unwrap();
        src.ks.bootstrap(&other, &policy("{}")).await.unwrap();
        let bp = Passphrase::new("bundle-pass");

        let bundle = src.ks.export_bundle(Some(&z), &bp).await.unwrap();
        let all = src.ks.export_bundle(None, &bp).await.unwrap();
        assert!(!String::from_utf8_lossy(&bundle).contains("example"));

        let dst = fixture(Some("store-b"));
        assert_eq!(dst.ks.import_bundle(&bundle, &bp).await.unwrap(), 2);
        assert_eq!(
            dst.ks.import_bundle(&bundle, &bp).await.unwrap(),
            0,
            "idempotent"
        );
        assert_eq!(dst.ks.import_bundle(&all, &bp).await.unwrap(), 1);
        let (a, b) = (
            src.ks.keys(&z).await.unwrap(),
            dst.ks.keys(&z).await.unwrap(),
        );
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(
                (x.role, x.key_tag, x.state, x.created_at),
                (y.role, y.key_tag, y.state, y.created_at)
            );
            let (kx, ky) = (
                src.ks.signing_key(x.id).await.unwrap(),
                dst.ks.signing_key(y.id).await.unwrap(),
            );
            assert_eq!(kx.to_pkcs8().as_slice(), ky.to_pkcs8().as_slice());
        }

        assert!(matches!(
            dst.ks
                .import_bundle(&bundle, &Passphrase::new("nope"))
                .await,
            Err(KeyStoreError::Decrypt)
        ));
    }

    #[tokio::test]
    async fn bundle_rejects_inconsistent_content() {
        let f = fixture(None);
        let bp = Passphrase::new("bp");
        let good = SigningKey::generate(Algorithm::Ed25519, false).unwrap();
        let entry = |role: &str, state: &str, tag: u16, alg: u8, pkcs8: String| BundleKey {
            zone: "x.test.".into(),
            role: role.into(),
            algorithm: alg,
            key_tag: tag,
            state: state.into(),
            created_at: 0,
            published_at: None,
            active_at: None,
            retired_at: None,
            ds_confirmed_at: None,
            pkcs8,
        };
        let tag = good.dnskey().key_tag();
        let b64 = B64.encode(good.to_pkcs8().as_slice());
        let cases = [
            entry("bogus", "active", tag, 15, b64.clone()),
            entry("zsk", "bogus", tag, 15, b64.clone()),
            entry("zsk", "removed", tag, 15, b64.clone()),
            entry("zsk", "active", tag, 15, "!!!".into()),
            entry("zsk", "active", tag, 13, b64.clone()),
            entry("zsk", "active", tag.wrapping_add(1), 15, b64.clone()),
        ];
        for c in cases {
            let bundle = Bundle {
                format: 1,
                keys: vec![c],
            };
            let blob = encrypt(&bp, CHEAP, &serde_json::to_vec(&bundle).unwrap()).unwrap();
            assert!(matches!(
                f.ks.import_bundle(&blob, &bp).await,
                Err(KeyStoreError::Bundle(_))
            ));
        }
        let wrong_format = encrypt(&bp, CHEAP, br#"{"format":9,"keys":[]}"#).unwrap();
        assert!(matches!(
            f.ks.import_bundle(&wrong_format, &bp).await,
            Err(KeyStoreError::Bundle(_))
        ));
        let garbage = encrypt(&bp, CHEAP, b"not json").unwrap();
        assert!(matches!(
            f.ks.import_bundle(&garbage, &bp).await,
            Err(KeyStoreError::Bundle(_))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bundle_files_are_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = fixture(None);
        f.ks.bootstrap(&zone(), &policy("{}")).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.bundle");
        let bp = Passphrase::new("bp");
        f.ks.export_bundle_to_file(None, &bp, &path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(matches!(
            f.ks.export_bundle_to_file(None, &bp, &path).await,
            Err(KeyStoreError::Io(_))
        ));
        let dst = fixture(None);
        assert_eq!(dst.ks.import_bundle_from_file(&path, &bp).await.unwrap(), 1);
        assert!(matches!(
            dst.ks
                .import_bundle_from_file(&dir.path().join("missing"), &bp)
                .await,
            Err(KeyStoreError::Io(_))
        ));
    }

    #[test]
    fn passphrase_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pass");
        std::fs::write(&file, "from-file\nsecond line\n").unwrap();
        let get = |env: Option<&str>, f: Option<&Path>| {
            resolve_passphrase(env.map(str::to_owned), f)
                .unwrap()
                .map(|p| p.0.to_string())
        };
        assert_eq!(
            get(Some("from-env"), Some(&file)).as_deref(),
            Some("from-env")
        );
        assert_eq!(get(Some(""), Some(&file)).as_deref(), Some("from-file"));
        assert_eq!(get(None, Some(&file)).as_deref(), Some("from-file"));
        assert_eq!(get(None, None), None);
        assert_eq!(get(Some(""), None), None);
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        for bad in [empty.as_path(), dir.path().join("nope").as_path()] {
            let err = resolve_passphrase(None, Some(bad)).unwrap_err();
            assert!(matches!(err, KeyStoreError::PassphraseFile { .. }));
        }
        // The process environment is not set in tests, so this only checks the wiring.
        assert!(passphrase_from_environment(None).is_ok());
    }
}
