//! Encrypted backup bundles: every key of a zone (or of all zones) as JSON, sealed under a
//! bundle passphrase with the stronger [`KdfCost::BUNDLE`](crate::KdfCost::BUNDLE).

use std::io::Write as _;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use dnsy_dnssec::{Algorithm, SigningKey};
use dnsy_proto::Name;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::repo::{COLUMNS, NewKey, insert, open_key, secret_row, zone_key};
use crate::sealed::{decrypt, encrypt};
use crate::{KeyRole, KeyState, KeyStore, KeyStoreError, Passphrase};

const BUNDLE_FORMAT: u32 = 1;

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

impl KeyStore {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    #[tokio::test]
    async fn bundles_use_the_strong_kdf_cost() {
        let dir = tempfile::tempdir().unwrap();
        let db = Store::open(&dir.path().join("k.db")).unwrap();
        let ks = KeyStore::open(db, None, Arc::new(ManualClock::new(T0)));
        let z = zone();
        ks.bootstrap(&z, KeyLayout::Csk, ECDSA).await.unwrap();
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
    async fn backup_bundle_roundtrip() {
        let src = fixture(Some("store-a"));
        let z = zone();
        let other = Name::from_ascii("other.test.").unwrap();
        src.ks
            .bootstrap(&z, KeyLayout::KskZsk, ECDSA)
            .await
            .unwrap();
        src.ks
            .bootstrap(&other, KeyLayout::Csk, ECDSA)
            .await
            .unwrap();
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
        f.ks.bootstrap(&zone(), KeyLayout::Csk, ECDSA)
            .await
            .unwrap();
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
}
