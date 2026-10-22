//! Key stores written before the keystore moved out of `dnsy-zone` still open.
//!
//! `fixtures/legacy-keystore.sqlite` and `fixtures/legacy.bundle` were written by the
//! `dnsy_zone::KeyStore` of commit f4391a9 (passphrase `legacy-passphrase`, bundle passphrase
//! `bundle-passphrase`): `example.com.` with a KSK and a ZSK (algorithm 13) and a published
//! Ed25519 ZSK, `other.test.` with an Ed25519 CSK, and `plain.test.` with a CSK stored
//! without a passphrase. The digests below are SHA-256 of each key's PKCS#8 document as the
//! old code decrypted it.

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use dnsy_core::ManualClock;
use dnsy_keys::{KeyRole, KeyState, KeyStore, KeyStoreError, Passphrase};
use dnsy_proto::Name;
use dnsy_store::Store;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// id, zone, role, algorithm, key tag, state, SHA-256 of the PKCS#8 document.
const KEYS: [(i64, &str, KeyRole, u8, u16, KeyState, &str); 5] = [
    (
        1,
        "example.com.",
        KeyRole::Ksk,
        13,
        56584,
        KeyState::Active,
        "9d2f9a5fa980d2455b1603833c2de08c1092b3f39d01908eaa627c3faf7a20e8",
    ),
    (
        2,
        "example.com.",
        KeyRole::Zsk,
        13,
        44973,
        KeyState::Active,
        "9e8d52dcf070467a73434248b7aa4990eabea7095028d97744acbc8b89567f56",
    ),
    (
        3,
        "other.test.",
        KeyRole::Csk,
        15,
        53032,
        KeyState::Active,
        "1b0f49d6f38ee1253b1165209c80b115bfe600a13484b235cc11e0b81195863e",
    ),
    (
        4,
        "example.com.",
        KeyRole::Zsk,
        15,
        20601,
        KeyState::Published,
        "49c7db18559c9f98a3f31936b599b858d0cd2ea479c10f21e90ea11691d45218",
    ),
    (
        5,
        "plain.test.",
        KeyRole::Csk,
        13,
        36282,
        KeyState::Active,
        "9056d3354c7d7983538b1c207eabda5c34d7aee075cc0befed74fe25c21e8a24",
    ),
];

fn sha256_hex(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn open(dir: &Path, pass: Option<&str>) -> KeyStore {
    let db = dir.join("dnsy.db");
    if !db.exists() {
        std::fs::copy(Path::new(FIXTURES).join("legacy-keystore.sqlite"), &db).unwrap();
    }
    KeyStore::open(
        Store::open(&db).unwrap(),
        pass.map(Passphrase::new),
        Arc::new(ManualClock::new(2_000_000)),
    )
}

/// Checks every key's metadata and decrypted PKCS#8 against the old code's values.
async fn assert_legacy_keys(ks: &KeyStore, check_ids: bool) {
    for zone in ["example.com.", "other.test.", "plain.test."] {
        let name = Name::from_ascii(zone).unwrap();
        let mut expected: Vec<_> = KEYS.iter().filter(|k| k.1 == zone).collect();
        let mut keys = ks.keys(&name).await.unwrap();
        expected.sort_by_key(|k| k.4);
        keys.sort_by_key(|k| k.key_tag);
        assert_eq!(keys.len(), expected.len(), "{zone}");
        for (rec, &&(id, z, role, alg, tag, state, digest)) in keys.iter().zip(&expected) {
            if check_ids {
                assert_eq!(rec.id, id);
            }
            assert_eq!(
                (
                    rec.zone.as_str(),
                    rec.role,
                    rec.algorithm.number(),
                    rec.key_tag,
                    rec.state
                ),
                (z, role, alg, tag, state)
            );
            let key = ks.signing_key(rec.id).await.unwrap();
            assert_eq!(key.dnskey().key_tag(), tag);
            assert_eq!(sha256_hex(&key.to_pkcs8()), digest, "key {id}");
        }
        assert_eq!(
            ks.active_keys(&name).await.unwrap().keys.len(),
            expected.len()
        );
    }
}

#[tokio::test]
async fn keystore_written_by_the_old_code_still_opens() {
    let dir = tempfile::tempdir().unwrap();
    let ks = open(dir.path(), Some("legacy-passphrase"));
    assert!(ks.keys_encrypted());
    assert_legacy_keys(&ks, true).await;

    // The sealed keys open with the old passphrase only; the unencrypted one needs none.
    let wrong = open(dir.path(), Some("other-passphrase"));
    assert!(matches!(
        wrong.signing_key(1).await,
        Err(KeyStoreError::Decrypt)
    ));
    let none = open(dir.path(), None);
    assert!(matches!(
        none.signing_key(1).await,
        Err(KeyStoreError::PassphraseRequired)
    ));
    none.signing_key(5).await.unwrap();
}

#[tokio::test]
async fn bundle_written_by_the_old_code_still_imports() {
    let bundle = std::fs::read(Path::new(FIXTURES).join("legacy.bundle")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ks = KeyStore::open(
        Store::open(&dir.path().join("dnsy.db")).unwrap(),
        Some(Passphrase::new("new-store-passphrase")),
        Arc::new(ManualClock::new(2_000_000)),
    );
    assert!(matches!(
        ks.import_bundle(&bundle, &Passphrase::new("wrong")).await,
        Err(KeyStoreError::Decrypt)
    ));
    let added = ks
        .import_bundle(&bundle, &Passphrase::new("bundle-passphrase"))
        .await
        .unwrap();
    assert_eq!(added, KEYS.len());
    assert_legacy_keys(&ks, false).await;
}
