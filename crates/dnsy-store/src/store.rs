use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, OpenFlags, Transaction};

use crate::migrate::{self, MIGRATIONS, Migration, MigrationStatus};

const READERS: usize = 4;
const BUSY_TIMEOUT_MS: u32 = 5000;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("migration {version:04}_{name} failed: {source}")]
    Migration {
        version: u32,
        name: String,
        source: rusqlite::Error,
    },
    #[error(
        "migration {version:04}_{name} was edited after being applied (checksum mismatch); never edit an applied migration"
    )]
    ChecksumMismatch { version: u32, name: String },
    #[error(
        "database contains migration {version:04}_{name} unknown to this binary; it was written by a newer version, refusing to start"
    )]
    UnknownMigration { version: u32, name: String },
    #[error("database task failed: {0}")]
    Task(String),
}

struct Inner {
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    next: AtomicUsize,
    known: &'static [Migration],
}

/// Async-friendly SQLite handle: one writer, a pool of read-only connections.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

fn configure(conn: &Connection) -> Result<(), StoreError> {
    conn.pragma_update(None, "foreign_keys", true)?;
    conn.busy_timeout(std::time::Duration::from_millis(u64::from(BUSY_TIMEOUT_MS)))?;
    Ok(())
}

fn lock(m: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Store {
    /// Open (creating if needed) the database at `path`, enable WAL and run migrations.
    ///
    /// # Errors
    /// Fails on SQLite errors, a failing migration, an edited migration, or a database
    /// containing a migration this binary does not know.
    pub fn open(path: &Path) -> Result<Store, StoreError> {
        Self::open_with(path, MIGRATIONS)
    }

    pub(crate) fn open_with(path: &Path, known: &'static [Migration]) -> Result<Store, StoreError> {
        let mut writer = Connection::open(path)?;
        writer.pragma_update(None, "journal_mode", "WAL")?;
        configure(&writer)?;
        migrate::run(&mut writer, known)?;
        let readers = (0..READERS)
            .map(|_| {
                let c = Connection::open_with_flags(
                    path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                configure(&c)?;
                Ok(Mutex::new(c))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(Store {
            inner: Arc::new(Inner {
                writer: Mutex::new(writer),
                readers,
                next: AtomicUsize::new(0),
                known,
            }),
        })
    }

    /// Run `f` on a read-only connection.
    ///
    /// # Errors
    /// Whatever `f` returns, or a task failure.
    pub async fn read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let inner = Arc::clone(&self.inner);
        join(tokio::task::spawn_blocking(move || {
            let i = inner.next.fetch_add(1, Ordering::Relaxed) % inner.readers.len();
            f(&lock(&inner.readers[i]))
        }))
        .await
    }

    /// Run `f` in a write transaction: committed on `Ok`, rolled back on `Err`.
    ///
    /// # Errors
    /// Whatever `f` returns, a commit failure, or a task failure.
    pub async fn write<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Transaction) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let inner = Arc::clone(&self.inner);
        join(tokio::task::spawn_blocking(move || {
            let mut conn = lock(&inner.writer);
            let mut tx = conn.transaction()?;
            let out = f(&mut tx)?;
            tx.commit()?;
            Ok(out)
        }))
        .await
    }

    /// Applied/pending state of every known migration (for `dnsy migrate --status`).
    ///
    /// # Errors
    /// SQLite or task failure.
    pub async fn migration_status(&self) -> Result<Vec<MigrationStatus>, StoreError> {
        let known = self.inner.known;
        self.read(move |c| migrate::status(c, known)).await
    }
}

async fn join<T>(h: tokio::task::JoinHandle<Result<T, StoreError>>) -> Result<T, StoreError> {
    h.await.map_err(|e| StoreError::Task(e.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const M1: Migration = Migration {
        version: 1,
        name: "a",
        sql: "CREATE TABLE a (id INTEGER PRIMARY KEY);",
    };
    const M2: Migration = Migration {
        version: 2,
        name: "b",
        sql: "CREATE TABLE b (id INTEGER PRIMARY KEY);",
    };

    fn db() -> (TempDir, std::path::PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.db");
        (d, p)
    }

    fn tables(s: &Store) -> Vec<String> {
        let c = lock(&s.inner.writer);
        let mut st = c
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[tokio::test]
    async fn fresh_db_applies_all() {
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1, M2]).unwrap();
        assert_eq!(tables(&s), ["a", "b", "schema_migrations"]);
        let st = s.migration_status().await.unwrap();
        assert_eq!(st.len(), 2);
        assert!(st.iter().all(|m| m.applied_at.is_some()));
        let fk: i64 = s
            .read(|c| Ok(c.pragma_query_value(None, "foreign_keys", |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(fk, 1);
        let mode: String = s
            .write(|t| Ok(t.pragma_query_value(None, "journal_mode", |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(mode, "wal");
    }

    #[test]
    fn open_default_has_no_migrations_yet() {
        let (_d, p) = db();
        Store::open(&p).unwrap();
    }

    #[tokio::test]
    async fn reopen_is_noop() {
        let (_d, p) = db();
        let first = Store::open_with(&p, &[M1, M2])
            .unwrap()
            .migration_status()
            .await
            .unwrap();
        let second = Store::open_with(&p, &[M1, M2])
            .unwrap()
            .migration_status()
            .await
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn edited_migration_fails() {
        let (_d, p) = db();
        Store::open_with(&p, &[M1]).unwrap();
        let edited = Migration {
            sql: "CREATE TABLE a (id INTEGER PRIMARY KEY, x TEXT);",
            ..M1
        };
        let err = Store::open_with(&p, Box::leak(Box::new([edited])))
            .err()
            .unwrap();
        assert!(matches!(
            err,
            StoreError::ChecksumMismatch { version: 1, .. }
        ));
        assert!(err.to_string().contains("0001_a"));
    }

    #[test]
    fn unknown_migration_refuses() {
        let (_d, p) = db();
        Store::open_with(&p, &[M1, M2]).unwrap();
        let err = Store::open_with(&p, &[M1]).err().unwrap();
        assert!(matches!(
            err,
            StoreError::UnknownMigration { version: 2, .. }
        ));
    }

    #[test]
    fn out_of_order_merge_converges() {
        let (_d, p) = db();
        // Binary A shipped only migration 2; binary B later knows 1 and 2.
        Store::open_with(&p, &[M2]).unwrap();
        let s = Store::open_with(&p, &[M1, M2]).unwrap();
        assert_eq!(tables(&s), ["a", "b", "schema_migrations"]);
        // Same result when applied the other way round, regardless of listing order.
        let (_d2, p2) = db();
        let s2 = Store::open_with(&p2, &[M2, M1]).unwrap();
        assert_eq!(tables(&s2), tables(&s));
    }

    #[test]
    fn failed_migration_rolls_back() {
        let (_d, p) = db();
        let bad = Migration {
            version: 2,
            name: "bad",
            sql: "CREATE TABLE half (id INTEGER); INSERT INTO nope VALUES (1);",
        };
        let err = Store::open_with(&p, Box::leak(Box::new([M1, bad])))
            .err()
            .unwrap();
        assert!(matches!(err, StoreError::Migration { version: 2, .. }));
        let s = Store::open_with(&p, &[M1]).unwrap();
        assert_eq!(tables(&s), ["a", "schema_migrations"]);
    }

    #[tokio::test]
    async fn write_rolls_back_on_error() {
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1]).unwrap();
        let r: Result<(), _> = s
            .write(|t| {
                t.execute("INSERT INTO a (id) VALUES (1)", [])?;
                Err(StoreError::Task("boom".into()))
            })
            .await;
        assert!(r.is_err());
        let n: i64 = s
            .read(|c| Ok(c.query_row("SELECT count(*) FROM a", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn concurrent_reads_during_write() {
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1]).unwrap();
        s.write(|t| Ok(t.execute("INSERT INTO a (id) VALUES (1)", []).map(drop)?))
            .await
            .unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let w = s.clone();
        let writer = tokio::spawn(async move {
            w.write(move |t| {
                t.execute("INSERT INTO a (id) VALUES (2)", [])?;
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
        });
        tokio::task::spawn_blocking(move || started_rx.recv().unwrap())
            .await
            .unwrap();
        // Write transaction is open and uncommitted: readers still see the old snapshot.
        for _ in 0..8 {
            let n: i64 = s
                .read(|c| Ok(c.query_row("SELECT count(*) FROM a", [], |r| r.get(0))?))
                .await
                .unwrap();
            assert_eq!(n, 1);
        }
        release_tx.send(()).unwrap();
        writer.await.unwrap().unwrap();
        let n: i64 = s
            .read(|c| Ok(c.query_row("SELECT count(*) FROM a", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(n, 2);
    }
}
