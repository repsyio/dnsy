//! Fixtures shared by the unit tests of every module.

pub(crate) use std::sync::Arc;

pub(crate) use crate::KeyLayout;
pub(crate) use dnsy_core::ManualClock;
pub(crate) use dnsy_dnssec::Algorithm;
pub(crate) use dnsy_proto::Name;
pub(crate) use dnsy_store::Store;

use crate::{KdfCost, KeyRecord, KeyRole, KeyState, KeyStore, Passphrase, RolloverTimings};

/// The default policy algorithm (13).
pub(crate) const ECDSA: Algorithm = Algorithm::EcdsaP256Sha256;

pub(crate) const CHEAP: KdfCost = KdfCost {
    memory_kib: 8,
    iterations: 1,
};
pub(crate) const T: RolloverTimings = RolloverTimings {
    dnskey_ttl: 3600,
    propagation: 0,
    max_signature_validity: 10_000,
};
pub(crate) const T0: i64 = 1_000_000;

pub(crate) struct Fixture {
    pub(crate) ks: KeyStore,
    pub(crate) clock: ManualClock,
    _dir: tempfile::TempDir,
}

pub(crate) fn fixture(pass: Option<&str>) -> Fixture {
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

pub(crate) fn zone() -> Name {
    Name::from_ascii("Example.COM.").unwrap()
}

pub(crate) fn states(keys: &[KeyRecord], role: KeyRole) -> Vec<KeyState> {
    keys.iter()
        .filter(|k| k.role == role)
        .map(|k| k.state)
        .collect()
}
