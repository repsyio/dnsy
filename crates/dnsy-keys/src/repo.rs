//! Rows of the `dnssec_keys` table.

use dnsy_dnssec::{Algorithm, SigningKey};
use dnsy_proto::{Dnskey, Name};
use dnsy_store::StoreError;
use rusqlite::{Connection, Transaction, params};
use zeroize::{Zeroize, Zeroizing};

use crate::sealed::decrypt;
use crate::{KeyRecord, KeyRole, KeyState, KeyStoreError, Passphrase};

pub(crate) fn zone_key(zone: &Name) -> String {
    zone.to_string().to_ascii_lowercase()
}

pub(crate) const COLUMNS: &str = "id, zone, role, algorithm, key_tag, state, created_at, published_at, \
                       active_at, retired_at, removed_at, ds_confirmed_at";

pub(crate) fn row_to_record(r: &rusqlite::Row<'_>) -> Result<KeyRecord, rusqlite::Error> {
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

pub(crate) fn list_zone(c: &Connection, zone: &str) -> Result<Vec<KeyRecord>, StoreError> {
    let mut stmt = c.prepare(&format!(
        "SELECT {COLUMNS} FROM dnssec_keys WHERE zone = ?1 ORDER BY id"
    ))?;
    Ok(stmt
        .query_map([zone], row_to_record)?
        .collect::<Result<_, _>>()?)
}

/// A key to insert: public metadata plus the already-sealed private key.
pub(crate) struct NewKey {
    pub(crate) zone: String,
    pub(crate) role: KeyRole,
    pub(crate) algorithm: Algorithm,
    pub(crate) key_tag: u16,
    pub(crate) state: KeyState,
    pub(crate) created_at: i64,
    pub(crate) published_at: Option<i64>,
    pub(crate) active_at: Option<i64>,
    pub(crate) retired_at: Option<i64>,
    pub(crate) ds_confirmed_at: Option<i64>,
    pub(crate) encrypted: bool,
    pub(crate) public_key: Vec<u8>,
    /// Sealed, or the plain PKCS#8 document when no passphrase is set: wiped on drop.
    pub(crate) private_key: Vec<u8>,
}

impl Drop for NewKey {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for NewKey {}

pub(crate) fn insert(tx: &Transaction<'_>, k: &NewKey) -> Result<i64, StoreError> {
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

pub(crate) fn record_of(id: i64, k: &NewKey) -> KeyRecord {
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

pub(crate) fn to_dnskey(algorithm: Algorithm, role: KeyRole, public_key: Vec<u8>) -> Dnskey {
    Dnskey {
        flags: 0x0100 | u16::from(role.is_sep()),
        protocol: 3,
        algorithm: algorithm.number(),
        public_key,
    }
}

pub(crate) type SecretRow = (KeyRecord, bool, Vec<u8>);

pub(crate) fn secret_row(r: &rusqlite::Row<'_>) -> Result<SecretRow, rusqlite::Error> {
    Ok((row_to_record(r)?, r.get(12)?, r.get(13)?))
}

/// Decrypts a fetched row into its record and signing key.
pub(crate) fn open_key(
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

    #[test]
    fn new_key_private_key_is_zeroized_on_drop() {
        fn zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroize_on_drop::<NewKey>();
        let src = include_str!("repo.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap();
        assert!(prod.contains(
            "impl Drop for NewKey {\n    fn drop(&mut self) {\n        self.private_key.zeroize();"
        ));
    }
}
