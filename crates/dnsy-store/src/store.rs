use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior};
use tokio::sync::Semaphore;

use crate::migrate::{self, MIGRATIONS, Migration, MigrationStatus};

const READERS: usize = 4;
const BUSY_TIMEOUT_MS: u32 = 5000;
/// The WAL file is truncated to this size after a checkpoint, so one big purge does not leave
/// hundreds of megabytes on disk.
const JOURNAL_SIZE_LIMIT: i64 = 64 * 1024 * 1024;

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
    #[error("database file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the database is in use by another process (stop the server first)")]
    Busy,
    #[error("database task failed: {0}")]
    Task(String),
}

struct Inner {
    writer: Mutex<Connection>,
    /// Idle read-only connections; a permit of `permits` guarantees one is present.
    readers: Mutex<Vec<Connection>>,
    permits: Arc<Semaphore>,
    commits: AtomicU64,
    known: &'static [Migration],
}

/// A reader connection taken from the pool; returned on drop, also when the closure panics.
struct Reader<'a> {
    pool: &'a Mutex<Vec<Connection>>,
    conn: Option<Connection>,
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(conn);
        }
    }
}

impl Reader<'_> {
    fn run<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.conn.as_ref().map_or_else(
            || Err(StoreError::Task("reader connection missing".to_owned())),
            f,
        )
    }
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

/// Create the database file with mode 0600 when it does not exist yet; SQLite gives the WAL and
/// shared-memory files the mode of the main file. An existing file keeps its mode.
fn create_private(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
    }
    #[cfg(not(unix))]
    let _ = path;
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
        create_private(path)?;
        let mut writer = Connection::open(path)?;
        writer.pragma_update(None, "journal_mode", "WAL")?;
        writer.pragma_update(None, "synchronous", "NORMAL")?;
        writer.pragma_update(None, "journal_size_limit", JOURNAL_SIZE_LIMIT)?;
        configure(&writer)?;
        migrate::run(&mut writer, known)?;
        let readers = (0..READERS)
            .map(|_| {
                let c = Connection::open_with_flags(
                    path,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                configure(&c)?;
                Ok(c)
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(Store {
            inner: Arc::new(Inner {
                writer: Mutex::new(writer),
                permits: Arc::new(Semaphore::new(readers.len())),
                readers: Mutex::new(readers),
                commits: AtomicU64::new(0),
                known,
            }),
        })
    }

    /// Run `f` on a read-only connection: any idle one, so a slow read only occupies its own
    /// connection.
    ///
    /// # Errors
    /// Whatever `f` returns, or a task failure.
    pub async fn read<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        let inner = Arc::clone(&self.inner);
        let permit = Arc::clone(&inner.permits)
            .acquire_owned()
            .await
            .map_err(|e| StoreError::Task(e.to_string()))?;
        join(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let conn = inner
                .readers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop()
                .ok_or_else(|| StoreError::Task("no idle reader connection".to_owned()))?;
            let reader = Reader {
                pool: &inner.readers,
                conn: Some(conn),
            };
            reader.run(f)
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
            // Immediate: take the write lock first, so a writer in another process (the CLI
            // beside a running server) waits instead of failing on a stale read snapshot.
            let mut tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let out = f(&mut tx)?;
            tx.commit()?;
            inner.commits.fetch_add(1, Ordering::Relaxed);
            Ok(out)
        }))
        .await
    }

    /// Number of write transactions committed through this handle (for tests and diagnostics).
    #[must_use]
    pub fn write_count(&self) -> u64 {
        self.inner.commits.load(Ordering::Relaxed)
    }

    /// Run `PRAGMA optimize` on the writer: `ANALYZE` only where the planner statistics are
    /// stale. Run on shutdown and once a day.
    ///
    /// # Errors
    /// SQLite or task failure.
    pub async fn optimize(&self) -> Result<(), StoreError> {
        self.write(|tx| Ok(tx.execute_batch("PRAGMA optimize")?))
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

/// Applied/pending state of every known migration of the database at `path`, without creating
/// or migrating it (a missing file or table means everything is pending).
///
/// # Errors
/// SQLite failure.
pub fn migration_status_at(path: &Path) -> Result<Vec<MigrationStatus>, StoreError> {
    let mut done = std::collections::BTreeMap::new();
    if path.exists() {
        let conn = open_immutable(path)?;
        let table: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
            [],
            |r| r.get(0),
        )?;
        if table > 0 {
            let mut stmt = conn.prepare("SELECT version, applied_at FROM schema_migrations")?;
            for row in stmt.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, i64>(1)?)))? {
                let (version, at) = row?;
                done.insert(version, at);
            }
        }
    }
    let mut out: Vec<MigrationStatus> = MIGRATIONS
        .iter()
        .map(|m| MigrationStatus {
            version: m.version,
            name: m.name.to_owned(),
            applied_at: done.get(&m.version).copied(),
        })
        .collect();
    out.sort_by_key(|s| s.version);
    Ok(out)
}

/// Opens `path` read-only with `immutable=1`: SQLite takes no locks and creates no `-shm`, so
/// this works on a read-only directory. It ignores the WAL, so a database a server is writing
/// shows its last checkpointed state.
fn open_immutable(path: &Path) -> Result<Connection, StoreError> {
    let uri = format!(
        "file:{}?immutable=1",
        path.to_string_lossy()
            .replace('%', "%25")
            .replace('?', "%3F")
            .replace('#', "%23")
    );
    Ok(Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )?)
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

    /// Another process (the CLI next to a running server) may commit between this transaction's
    /// first read and its first write. A deferred transaction then fails at once with "database
    /// is locked" (stale snapshot); an immediate one takes the write lock up front and the other
    /// writer waits for it.
    #[tokio::test]
    async fn a_second_writer_waits_instead_of_failing_on_a_stale_snapshot() {
        let (_d, p) = db();
        let a = Store::open_with(&p, &[M1]).unwrap();
        let b = Store::open_with(&p, &[M1]).unwrap();
        let slow = b.write(|tx| {
            tx.query_row("SELECT COUNT(*) FROM a", [], |r| r.get::<_, i64>(0))?;
            std::thread::sleep(std::time::Duration::from_millis(400));
            tx.execute("INSERT INTO a DEFAULT VALUES", [])?;
            Ok(())
        });
        let quick = async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            a.write(|tx| {
                tx.execute("INSERT INTO a DEFAULT VALUES", [])?;
                Ok(())
            })
            .await
        };
        let (slow, quick) = tokio::join!(slow, quick);
        slow.expect("the long transaction keeps its snapshot valid");
        quick.expect("the other writer waits for the lock");
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

    #[test]
    fn status_at_reports_pending_then_applied_without_migrating() {
        let (_d, p) = db();
        let before = migration_status_at(&p).unwrap();
        assert!(!before.is_empty() && before.iter().all(|m| m.applied_at.is_none()));
        assert!(!p.exists(), "status must not create the database");
        Store::open(&p).unwrap();
        let after = migration_status_at(&p).unwrap();
        assert!(after.iter().all(|m| m.applied_at.is_some()));
    }

    #[cfg(unix)]
    #[test]
    fn status_at_works_on_a_read_only_directory() {
        use std::os::unix::fs::PermissionsExt;
        let (d, p) = db();
        Store::open(&p).unwrap();
        let dir = d.path();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let status = migration_status_at(&p);
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let status = status.expect("read-only directory");
        assert!(status.iter().all(|m| m.applied_at.is_some()));
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

    #[tokio::test]
    async fn one_slow_read_does_not_block_other_reads() {
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1]).unwrap();
        let slow = s.clone();
        let slow = tokio::spawn(async move {
            slow.read(|_| {
                std::thread::sleep(std::time::Duration::from_millis(500));
                Ok(())
            })
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let start = std::time::Instant::now();
        let fast = (0..8).map(|_| {
            let s = s.clone();
            tokio::spawn(async move {
                s.read(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?))
                    .await
            })
        });
        for f in fast.collect::<Vec<_>>() {
            f.await.unwrap().unwrap();
        }
        // Quick when idle (a few ms); the margin only absorbs a loaded machine, a read stuck
        // behind the slow one would take at least 450 ms.
        assert!(
            start.elapsed() < std::time::Duration::from_millis(250),
            "fast reads waited behind the slow one (500 ms): {:?}",
            start.elapsed()
        );
        slow.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_panicking_read_returns_its_connection() {
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1]).unwrap();
        for _ in 0..(READERS * 2) {
            let r = s.read::<()>(|_| panic!("boom")).await;
            assert!(r.is_err());
        }
        s.read(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn writer_pragmas_are_set() {
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1]).unwrap();
        let (sync, limit): (i64, i64) = s
            .write(|t| {
                Ok((
                    t.pragma_query_value(None, "synchronous", |r| r.get(0))?,
                    t.pragma_query_value(None, "journal_size_limit", |r| r.get(0))?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(sync, 1, "synchronous = NORMAL");
        assert_eq!(limit, 67_108_864);
    }

    #[tokio::test]
    async fn the_wal_shrinks_after_a_big_purge() {
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1]).unwrap();
        s.write(|t| {
            t.execute("CREATE TABLE blobs (id INTEGER PRIMARY KEY, b BLOB)", [])?;
            for _ in 0..1400 {
                t.execute("INSERT INTO blobs (b) VALUES (zeroblob(100000))", [])?;
            }
            Ok(())
        })
        .await
        .unwrap();
        let wal = p.with_extension("db-wal");
        let big = std::fs::metadata(&wal).unwrap().len();
        assert!(
            big > 64 * 1024 * 1024,
            "setup: the WAL must exceed the limit, was {big}"
        );
        s.write(|t| Ok(t.execute("DELETE FROM blobs", []).map(drop)?))
            .await
            .unwrap();
        s.write(|t| Ok(t.execute("INSERT INTO a DEFAULT VALUES", []).map(drop)?))
            .await
            .unwrap();
        let small = std::fs::metadata(&wal).unwrap().len();
        assert!(small <= 64 * 1024 * 1024, "WAL stayed at {small} bytes");
    }

    #[tokio::test]
    async fn commits_are_counted() {
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1]).unwrap();
        let before = s.write_count();
        s.write(|_| Ok(())).await.unwrap();
        let _ = s.write::<()>(|_| Err(StoreError::Task("x".into()))).await;
        assert_eq!(s.write_count(), before + 1, "only committed writes count");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fresh_store_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1]).unwrap();
        s.write(|t| Ok(t.execute("INSERT INTO a DEFAULT VALUES", []).map(drop)?))
            .await
            .unwrap();
        for f in [
            p.clone(),
            p.with_extension("db-wal"),
            p.with_extension("db-shm"),
        ] {
            let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", f.display());
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_database_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, p) = db();
        Store::open_with(&p, &[M1]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        Store::open_with(&p, &[M1]).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[tokio::test]
    async fn optimize_runs() {
        let (_d, p) = db();
        let s = Store::open_with(&p, &[M1]).unwrap();
        s.optimize().await.unwrap();
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn pending_index_migrations_are_announced_before_they_run() {
        let (_d, p) = db();
        let idx = Migration {
            version: 2,
            name: "idx",
            sql: "CREATE INDEX a_id ON a (id);",
        };
        Store::open_with(&p, &[M1]).unwrap();
        let cap = Capture::default();
        let sub = tracing_subscriber::fmt()
            .with_writer({
                let cap = cap.clone();
                move || cap.clone()
            })
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(sub, || {
            Store::open_with(&p, Box::leak(Box::new([M1, idx]))).unwrap();
        });
        let log = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("applying migration 0002_idx, this can take a while on a large query log"),
            "{log}"
        );
        assert!(
            !log.contains("0001_a"),
            "applied migrations are not announced: {log}"
        );
    }

    /// A database at migration 14 gains `response_ip_policy` on upgrade, whatever lands between.
    #[tokio::test]
    async fn response_ip_policy_table_is_added_to_a_version_14_database() {
        let (_d, p) = db();
        let old = &MIGRATIONS[..14];
        assert_eq!(old.last().unwrap().version, 14);
        drop(Store::open_with(&p, old).unwrap());
        let after = Store::open(&p).unwrap();
        let n: i64 = after
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = 'response_ip_policy'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    /// A database written by the schema of main before this story (migrations 0001 to 0009),
    /// populated, upgrades in place: nothing is lost, the new indexes appear and the runner's
    /// checksum and registry rules still hold.
    #[tokio::test]
    async fn a_populated_database_from_main_upgrades() {
        let (_d, p) = db();
        let old = &MIGRATIONS[..9];
        assert_eq!(old.last().unwrap().name, "user_disabled");
        let before = Store::open_with(&p, old).unwrap();
        before
            .write(|t| {
                let mut ins = t.prepare(
                    "INSERT INTO query_log (ts_ms, client, transport, principal, qname, qtype, rcode,
                                            source, source_detail, dnssec, latency_us)
                     VALUES (?1, ?2, 'udp', NULL, 'a.example.', 1, ?3, ?4, NULL, 'unchecked', 10)",
                )?;
                for i in 0..20_000_i64 {
                    let (rcode, source) = if i % 100 == 0 { (5, "refused") } else { (0, "upstream") };
                    ins.execute(rusqlite::params![i, format!("192.0.2.{}", i % 50), rcode, source])?;
                }
                Ok(())
            })
            .await
            .unwrap();
        drop(before);
        let after = Store::open(&p).unwrap();
        let (rows, idx): (i64, Vec<String>) = after
            .read(|c| {
                let rows = c.query_row("SELECT count(*) FROM query_log", [], |r| r.get(0))?;
                let mut st = c.prepare(
                    "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='query_log' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )?;
                let idx = st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
                Ok((rows, idx))
            })
            .await
            .unwrap();
        assert_eq!(rows, 20_000);
        assert_eq!(idx, ["query_log_client", "query_log_rare", "query_log_ts"]);
        let st = after.migration_status().await.unwrap();
        assert!(st.iter().all(|m| m.applied_at.is_some()));
        assert!(st.iter().any(|m| m.version == 10) && st.iter().any(|m| m.version == 11));
        // The partial index holds exactly the rare rows (1 in 100).
        let rare: i64 = after
            .read(|c| Ok(c.query_row("SELECT count(*) FROM query_log INDEXED BY query_log_rare WHERE source IN (4, 5, 6) OR rcode NOT IN (0, 3)", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(rare, 200);
    }

    const BEFORE_COMPACT: usize = 14;

    /// Rows with every transport, source, dnssec value, IPv4 and IPv6 clients (compressed and
    /// IPv4-mapped forms) and a text sequence high-water mark above the largest id.
    fn populate_text_rows(c: &rusqlite::Connection, n: i64) {
        let mut ins = c
            .prepare(
                "INSERT INTO query_log (ts_ms, client, transport, principal, qname, qtype, rcode,
                                        source, source_detail, dnssec, latency_us)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7, ?8, ?9, 10)",
            )
            .unwrap();
        let clients = [
            "192.0.2.7",
            "2001:db8:1::",
            "::ffff:192.0.2.1",
            "::1",
            "2001:db8::8a2e:370:7334",
        ];
        let transports = ["udp", "tcp", "dot", "doh"];
        let sources = [
            "authoritative",
            "cache",
            "cache_stale",
            "upstream",
            "blocked",
            "refused",
            "error",
        ];
        let dnssec = ["unchecked", "secure", "insecure", "bogus", "indeterminate"];
        for i in 0..n {
            let u = usize::try_from(i).unwrap();
            ins.execute(rusqlite::params![
                i,
                clients[u % clients.len()],
                transports[u % 4],
                (u % 3 == 0).then_some("tok"),
                format!("host{i}.example."),
                i % 6,
                sources[u % 7],
                (u % 7 == 3).then_some("198.51.100.1:53"),
                dnssec[u % 5],
            ])
            .unwrap();
        }
    }

    /// A 0014 database with 3 500 text rows, the last ten deleted (sequence 3 500, 3 490 rows),
    /// migrated by the current binary.
    fn upgraded_log() -> (TempDir, std::path::PathBuf) {
        let (d, p) = db();
        Store::open_with(&p, &MIGRATIONS[..BEFORE_COMPACT]).unwrap();
        assert_eq!(MIGRATIONS[BEFORE_COMPACT - 1].version, 14);
        let c = rusqlite::Connection::open(&p).unwrap();
        populate_text_rows(&c, 3_500);
        c.execute("DELETE FROM query_log WHERE id > 3490", [])
            .unwrap();
        let seq: i64 = c
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'query_log'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(seq, 3_500);
        drop(c);
        drop(Store::open(&p).unwrap());
        (d, p)
    }

    /// A populated database at the previous migration (0014) upgrades through 0015: every row
    /// keeps its meaning (read back through the integer codes).
    #[test]
    fn compact_migration_converts_a_populated_database() {
        let (_d, p) = upgraded_log();
        let c = rusqlite::Connection::open(&p).unwrap();
        let rows: i64 = c
            .query_row("SELECT count(*) FROM query_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 3_490);
        let mut st = c
            .prepare(
                "SELECT id, client, transport, principal, qname, source, source_detail, dnssec
                 FROM query_log ORDER BY id",
            )
            .unwrap();
        let clients: [Vec<u8>; 5] = [
            vec![192, 0, 2, 7],
            "2001:db8:1::"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            "::ffff:192.0.2.1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            "::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
            "2001:db8::8a2e:370:7334"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        ];
        let mut seen = 0;
        for r in st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, i64>(7)?,
                ))
            })
            .unwrap()
        {
            let (id, client, transport, principal, qname, source, detail, dnssec) = r.unwrap();
            let u = usize::try_from(id - 1).unwrap();
            assert_eq!(client, clients[u % 5], "id {id}");
            assert_eq!(usize::try_from(transport).unwrap(), u % 4);
            assert_eq!(principal.as_deref(), (u % 3 == 0).then_some("tok"));
            assert_eq!(qname, format!("host{}.example.", id - 1));
            assert_eq!(usize::try_from(source).unwrap(), u % 7);
            assert_eq!(detail.is_some(), u % 7 == 3);
            assert_eq!(usize::try_from(dnssec).unwrap(), u % 5);
            seen += 1;
        }
        assert_eq!(seen, 3_490);
    }

    /// Ids survive, the sequence high-water mark carries over (no id is reused) and the three
    /// indexes exist, the partial one over the codes.
    #[test]
    fn compact_migration_keeps_ids_sequence_and_indexes() {
        let (_d, p) = upgraded_log();
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute(
            "INSERT INTO query_log (ts_ms, client, transport, qname, qtype, rcode, source, dnssec, latency_us)
             VALUES (1, X'C0000201', 0, 'n.example.', 1, 0, 3, 0, 1)",
            [],
        )
        .unwrap();
        assert_eq!(c.last_insert_rowid(), 3_501);
        let idx: Vec<String> = c
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='query_log' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(idx, ["query_log_client", "query_log_rare", "query_log_ts"]);
        let rare: i64 = c
            .query_row("SELECT count(*) FROM query_log INDEXED BY query_log_rare WHERE source IN (4, 5, 6) OR rcode NOT IN (0, 3)", [], |r| r.get(0))
            .unwrap();
        let expected: i64 = c
            .query_row(
                "SELECT count(*) FROM query_log WHERE source IN (4, 5, 6) OR rcode NOT IN (0, 3)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rare, expected);
        assert!(rare > 0);
    }

    /// Empty table: the migration applies and the sequence row is not invented.
    #[test]
    fn compact_migration_on_an_empty_log() {
        let (_d, p) = db();
        Store::open_with(&p, &MIGRATIONS[..BEFORE_COMPACT]).unwrap();
        Store::open(&p).unwrap();
        let c = rusqlite::Connection::open(&p).unwrap();
        let n: i64 = c
            .query_row("SELECT count(*) FROM query_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    /// A row the mapping cannot represent aborts the whole migration: nothing is applied, the
    /// text table is intact and the error names the migration.
    #[test]
    fn compact_migration_rolls_back_on_a_bad_row() {
        for bad in [
            "UPDATE query_log SET client = 'not-an-ip' WHERE id = 3",
            "UPDATE query_log SET source = 'mystery' WHERE id = 3",
            "UPDATE query_log SET transport = 'quic' WHERE id = 3",
            "UPDATE query_log SET dnssec = 'odd' WHERE id = 3",
        ] {
            let (_d, p) = db();
            Store::open_with(&p, &MIGRATIONS[..BEFORE_COMPACT]).unwrap();
            let c = rusqlite::Connection::open(&p).unwrap();
            populate_text_rows(&c, 10);
            c.execute(bad, []).unwrap();
            drop(c);
            let err = Store::open(&p).err().expect("migration fails");
            assert!(
                matches!(err, StoreError::Migration { version: 15, .. }),
                "{bad}: {err:?}"
            );
            let c = rusqlite::Connection::open(&p).unwrap();
            let (n, ty): (i64, String) = c
                .query_row(
                    "SELECT count(*), typeof(min(client)) FROM query_log",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!((n, ty.as_str()), (10, "text"), "{bad}");
            let tables: i64 = c
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = 'query_log_new'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(tables, 0, "{bad}");
            let applied: i64 = c
                .query_row(
                    "SELECT count(*) FROM schema_migrations WHERE version = 15",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(applied, 0, "{bad}");
        }
    }

    /// Size per row, measured on the file after a VACUUM so free pages do not count.
    fn vacuumed_bytes(p: &std::path::Path) -> i64 {
        let c = rusqlite::Connection::open(p).unwrap();
        c.execute_batch("VACUUM").unwrap();
        let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        let size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        pages * size
    }

    /// Benchmark for the story's size criterion: the same 200k rows before and after the
    /// migration (all three indexes present both times), at least 20 percent smaller.
    #[test]
    fn compact_encoding_shrinks_the_query_log_by_at_least_20_percent() {
        let (_d, p) = db();
        Store::open_with(&p, &MIGRATIONS[..BEFORE_COMPACT]).unwrap();
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch(
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 199999)
             INSERT INTO query_log (ts_ms, client, transport, principal, qname, qtype, rcode,
                                    source, source_detail, dnssec, latency_us)
             SELECT 1700000000000 + i * 37, '10.' || (i % 7) || '.' || (i % 251) || '.' || (i % 13),
                    CASE i % 4 WHEN 0 THEN 'udp' WHEN 1 THEN 'tcp' WHEN 2 THEN 'dot' ELSE 'doh' END,
                    NULL, 'host' || (i % 5000) || '.example.com.', 1 + i % 3, CASE WHEN i % 50 = 0 THEN 3 ELSE 0 END,
                    CASE i % 5 WHEN 0 THEN 'cache' WHEN 1 THEN 'upstream' WHEN 2 THEN 'cache' WHEN 3 THEN 'authoritative' ELSE 'blocked' END,
                    NULL, CASE i % 9 WHEN 0 THEN 'secure' ELSE 'unchecked' END, 100 + i % 900
             FROM n",
        )
        .unwrap();
        drop(c);
        let before = vacuumed_bytes(&p);
        Store::open(&p).unwrap();
        let after = vacuumed_bytes(&p);
        let saved = 100 - after * 100 / before;
        eprintln!("query_log 200k rows: {before} -> {after} bytes, {saved} percent smaller");
        assert!(after * 100 <= before * 80, "{before} -> {after}");
    }
}
