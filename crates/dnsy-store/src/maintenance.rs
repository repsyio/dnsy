//! Offline database maintenance for `dnsy db check|vacuum|backup`: plain functions on a database
//! path, with their own connections, so they run beside a live server (check, backup) or only
//! when no other process holds the database (vacuum).

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use crate::StoreError;

const BUSY_TIMEOUT_MS: u64 = 5000;
/// Pages copied per backup step; the source is unlocked between steps so a running server's
/// writer is never held up for long.
const BACKUP_STEP_PAGES: std::ffi::c_int = 1024;
const BACKUP_PAUSE: Duration = Duration::from_millis(5);

fn open_read_only(path: &Path) -> Result<Connection, StoreError> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    Ok(conn)
}

/// Runs `PRAGMA quick_check` (`full`: `integrity_check`) and returns the problems it reports;
/// empty means the database is sound. A file that is not a database is an error.
///
/// Safe beside a running server: it only reads.
///
/// # Errors
/// A missing or unreadable file, or SQLite refusing to read it.
pub fn check(path: &Path, full: bool) -> Result<Vec<String>, StoreError> {
    let conn = open_read_only(path)?;
    let pragma = if full {
        "PRAGMA integrity_check"
    } else {
        "PRAGMA quick_check"
    };
    let mut stmt = conn.prepare(pragma)?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut problems = Vec::new();
    for row in rows {
        let line = row?;
        if line != "ok" {
            problems.push(line);
        }
    }
    Ok(problems)
}

/// Size of the database file before and after a [`vacuum`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vacuumed {
    pub before: u64,
    pub after: u64,
}

/// Rebuilds the database file to return free pages to the filesystem. Needs up to twice the
/// database size in free disk space and blocks every writer while it runs, so it refuses when
/// any other connection (a running server or another command) has the database open.
///
/// # Errors
/// [`StoreError::Busy`] when another process holds the database; SQLite or file errors.
pub fn vacuum(path: &Path) -> Result<Vacuumed, StoreError> {
    let before = std::fs::metadata(path)?.len();
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::ZERO)?;
    // Exclusive locking mode in WAL needs the WAL index to ourselves: it fails with BUSY while
    // any other connection, in any process, has the database open.
    conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
    let busy = |e: rusqlite::Error| match e.sqlite_error_code() {
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
            StoreError::Busy
        }
        _ => StoreError::Sqlite(e),
    };
    conn.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(busy)?;
    conn.execute_batch("VACUUM").map_err(busy)?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(busy)?;
    drop(conn);
    let after = std::fs::metadata(path)?.len();
    Ok(Vacuumed { before, after })
}

/// Writes a consistent copy of the database to the new file `dest` (mode 0600) with SQLite's
/// online backup API, including everything in the WAL. Safe beside a running server: the source
/// is only read, in steps.
///
/// # Errors
/// `dest` already exists, or SQLite or file errors.
pub fn backup(path: &Path, dest: &Path) -> Result<(), StoreError> {
    let source = open_read_only(path)?;
    create_new_private(dest)?;
    let result = (|| {
        let mut target = Connection::open(dest)?;
        let backup = rusqlite::backup::Backup::new(&source, &mut target)?;
        backup.run_to_completion(BACKUP_STEP_PAGES, BACKUP_PAUSE, None)?;
        drop(backup);
        // The copy is one self-contained file: no WAL to lose when it is copied around.
        target.pragma_update(None, "journal_mode", "DELETE")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(dest);
    }
    result
}

fn create_new_private(dest: &Path) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    async fn filled(dir: &Path) -> (std::path::PathBuf, Store) {
        let path = dir.join("dnsy.db");
        let store = Store::open(&path).unwrap();
        store
            .write(|tx| {
                tx.execute_batch("CREATE TABLE junk (id INTEGER PRIMARY KEY, v BLOB)")?;
                for _ in 0..200 {
                    tx.execute("INSERT INTO junk (v) VALUES (zeroblob(8192))", [])?;
                }
                Ok(())
            })
            .await
            .unwrap();
        (path, store)
    }

    #[tokio::test]
    async fn check_passes_on_a_sound_database_and_beside_a_live_store() {
        let d = tempfile::tempdir().unwrap();
        let (path, _store) = filled(d.path()).await;
        assert_eq!(check(&path, false).unwrap(), Vec::<String>::new());
        assert_eq!(check(&path, true).unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn check_detects_a_corrupted_file() {
        let d = tempfile::tempdir().unwrap();
        let (path, store) = filled(d.path()).await;
        drop(store); // the last connection closing checkpoints the WAL into the file
        let mut bytes = std::fs::read(&path).unwrap();
        // Scribble over a run of table pages, past the header and the schema page.
        for b in &mut bytes[40_000..120_000] {
            *b = 0xA5;
        }
        std::fs::write(&path, bytes).unwrap();
        let outcome = check(&path, true);
        assert!(
            outcome.map_or(true, |problems| !problems.is_empty()),
            "corruption must be reported"
        );
    }

    #[test]
    fn check_rejects_a_file_that_is_not_a_database() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("junk.db");
        std::fs::write(&path, vec![0x42; 20_000]).unwrap();
        assert!(check(&path, false).is_err());
        assert!(check(&d.path().join("missing.db"), false).is_err());
    }

    #[tokio::test]
    async fn vacuum_shrinks_a_purged_file() {
        let d = tempfile::tempdir().unwrap();
        let (path, store) = filled(d.path()).await;
        store
            .write(|tx| Ok(tx.execute("DELETE FROM junk", [])?))
            .await
            .unwrap();
        drop(store);
        let done = vacuum(&path).unwrap();
        assert!(done.before > 1_000_000, "{done:?}");
        assert!(done.after < done.before / 10, "{done:?}");
        assert_eq!(check(&path, true).unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn vacuum_refuses_while_another_connection_holds_the_database() {
        let d = tempfile::tempdir().unwrap();
        let (path, store) = filled(d.path()).await;
        assert!(matches!(vacuum(&path), Err(StoreError::Busy)));
        drop(store);
        vacuum(&path).expect("free once the holder is gone");
    }

    #[tokio::test]
    async fn backup_beside_a_live_store_opens_and_passes_quick_check() {
        let d = tempfile::tempdir().unwrap();
        let (path, store) = filled(d.path()).await;
        // Rows still only in the WAL must be in the copy.
        store
            .write(|tx| Ok(tx.execute("INSERT INTO junk (v) VALUES (x'01')", [])?))
            .await
            .unwrap();
        let dest = d.path().join("copy.db");
        backup(&path, &dest).unwrap();
        assert_eq!(check(&dest, false).unwrap(), Vec::<String>::new());
        let copy = Connection::open(&dest).unwrap();
        let rows: i64 = copy
            .query_row("SELECT COUNT(*) FROM junk", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 201);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Never overwrites.
        assert!(backup(&path, &dest).is_err());
        drop(store);
    }
}
