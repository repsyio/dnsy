use dnsy_store::{Store, StoreError};
use rusqlite::{Connection, OptionalExtension, Row, params};

use crate::unix_now;

/// One allowlisted client certificate, identified by the SHA-256 of its DER encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCert {
    pub id: i64,
    pub sha256: [u8; 32],
    pub label: String,
    pub enabled: bool,
    /// Unix seconds; `None` never expires.
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

const COLUMNS: &str = "id, sha256, label, enabled, expires_at, created_at";

fn from_row(r: &Row<'_>) -> rusqlite::Result<ClientCert> {
    let raw: Vec<u8> = r.get(1)?;
    let sha256 = <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
        rusqlite::Error::InvalidColumnType(1, "sha256".into(), rusqlite::types::Type::Blob)
    })?;
    Ok(ClientCert {
        id: r.get(0)?,
        sha256,
        label: r.get(2)?,
        enabled: r.get::<_, i64>(3)? != 0,
        expires_at: r.get(4)?,
        created_at: r.get(5)?,
    })
}

fn list_where(c: &Connection, filter: &str) -> Result<Vec<ClientCert>, StoreError> {
    let mut stmt = c.prepare(&format!(
        "SELECT {COLUMNS} FROM client_certs {filter} ORDER BY id"
    ))?;
    let rows = stmt.query_map([], from_row)?.collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Persisted fingerprint allowlist for mTLS client certificates.
#[derive(Clone)]
pub struct ClientCertService {
    store: Store,
}

impl ClientCertService {
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    /// Adds an enabled certificate. A duplicate fingerprint is a SQLite constraint error.
    ///
    /// # Errors
    /// Store failure, an empty or over-long label, or a duplicate fingerprint.
    pub async fn add(
        &self,
        sha256: [u8; 32],
        label: &str,
        expires_at: Option<i64>,
    ) -> Result<ClientCert, StoreError> {
        let label = label.to_owned();
        self.store
            .write(move |tx| {
                let now = unix_now();
                tx.execute(
                    "INSERT INTO client_certs (sha256, label, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)",
                    params![sha256.as_slice(), label, expires_at, now],
                )?;
                Ok(ClientCert {
                    id: tx.last_insert_rowid(),
                    sha256,
                    label,
                    enabled: true,
                    expires_at,
                    created_at: now,
                })
            })
            .await
    }

    /// # Errors
    /// Store failure.
    pub async fn list(&self) -> Result<Vec<ClientCert>, StoreError> {
        self.store.read(|c| list_where(c, "")).await
    }

    /// Enabled entries that have not expired yet; what the verifier loads.
    ///
    /// # Errors
    /// Store failure.
    pub async fn active(&self) -> Result<Vec<ClientCert>, StoreError> {
        let now = unix_now();
        Ok(self
            .store
            .read(|c| list_where(c, "WHERE enabled = 1"))
            .await?
            .into_iter()
            .filter(|e| e.expires_at.is_none_or(|t| t > now))
            .collect())
    }

    /// # Errors
    /// Store failure.
    pub async fn get(&self, id: i64) -> Result<Option<ClientCert>, StoreError> {
        self.store
            .read(move |c| {
                Ok(c.query_row(
                    &format!("SELECT {COLUMNS} FROM client_certs WHERE id = ?1"),
                    [id],
                    from_row,
                )
                .optional()?)
            })
            .await
    }

    /// Returns whether the entry existed.
    ///
    /// # Errors
    /// Store failure.
    pub async fn set_enabled(&self, id: i64, enabled: bool) -> Result<bool, StoreError> {
        self.store
            .write(move |tx| {
                Ok(tx.execute(
                    "UPDATE client_certs SET enabled = ?2 WHERE id = ?1",
                    params![id, i64::from(enabled)],
                )? > 0)
            })
            .await
    }

    /// Returns whether the entry existed.
    ///
    /// # Errors
    /// Store failure.
    pub async fn remove(&self, id: i64) -> Result<bool, StoreError> {
        self.store
            .write(move |tx| Ok(tx.execute("DELETE FROM client_certs WHERE id = ?1", [id])? > 0))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> (ClientCertService, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("t.db")).unwrap();
        (ClientCertService::new(store), dir)
    }

    #[tokio::test]
    async fn add_list_toggle_remove() {
        let (s, _d) = svc();
        let a = s.add([1; 32], "laptop", None).await.unwrap();
        assert!(a.enabled);
        assert_eq!(s.list().await.unwrap(), vec![a.clone()]);
        assert!(s.add([1; 32], "dup", None).await.is_err());
        assert!(s.set_enabled(a.id, false).await.unwrap());
        assert_eq!(s.active().await.unwrap().len(), 0);
        assert!(!s.get(a.id).await.unwrap().unwrap().enabled);
        assert!(s.remove(a.id).await.unwrap());
        assert!(!s.remove(a.id).await.unwrap());
        assert!(!s.set_enabled(a.id, true).await.unwrap());
        assert!(s.get(a.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn active_skips_expired() {
        let (s, _d) = svc();
        s.add([1; 32], "old", Some(unix_now() - 10)).await.unwrap();
        let live = s
            .add([2; 32], "new", Some(unix_now() + 1000))
            .await
            .unwrap();
        assert_eq!(s.active().await.unwrap(), vec![live]);
    }

    #[tokio::test]
    async fn rejects_bad_label() {
        let (s, _d) = svc();
        assert!(s.add([3; 32], "", None).await.is_err());
    }
}
