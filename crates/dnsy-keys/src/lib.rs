//! Persistent per-zone DNSSEC key sets with encrypted private keys and rollover.
//!
//! Private keys are PKCS#8 documents sealed with AES-256-GCM under a key derived from the
//! operator's passphrase with argon2id (fresh salt and nonce per key). Without a passphrase
//! they are stored unencrypted and [`KeyStore::keys_encrypted`] is false. Key material is
//! zeroized after use and never appears in `Debug` output, errors or logs.
//!
//! * `passphrase`: the passphrase type and where it comes from.
//! * `sealed`: the KDF and AEAD that seal a private key or a bundle (no SQLite).
//! * `repo`: the `dnssec_keys` rows.
//! * `rollover`: key records, the rollover planner and the rollover steps.
//! * `bundle`: encrypted backup bundles.

mod bundle;
mod keystore;
mod passphrase;
mod repo;
mod rollover;
mod sealed;
#[cfg(test)]
mod test_support;

pub use dnsy_core::{KeyRole, KeyState};
pub use keystore::{KeyLayout, KeyStore};
pub use passphrase::{Passphrase, passphrase_from_environment, resolve_passphrase};
pub use rollover::{KeyRecord, RolloverTimings, Transition, plan};
pub use sealed::KdfCost;

use dnsy_dnssec::DnssecError;
use dnsy_store::StoreError;

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
