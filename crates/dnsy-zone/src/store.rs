//! The zones directory: loading, atomic writes, hot reload.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use dnsy_proto::Name;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::model::{Zone, ZoneError};

/// Quiet period after the last file event before the directory is reloaded.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// Immutable snapshot of all loaded zones.
#[derive(Debug, Default)]
pub struct ZoneSet {
    zones: BTreeMap<Name, Arc<Zone>>,
}

impl ZoneSet {
    /// The zone with exactly this origin.
    #[must_use]
    pub fn get(&self, origin: &Name) -> Option<&Arc<Zone>> {
        self.zones.get(origin)
    }

    /// The closest enclosing zone of `name`.
    #[must_use]
    pub fn find(&self, name: &Name) -> Option<&Arc<Zone>> {
        let mut cur = Some(name.clone());
        while let Some(n) = cur {
            if let Some(z) = self.zones.get(&n) {
                return Some(z);
            }
            cur = n.parent();
        }
        None
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<Zone>> {
        self.zones.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}

#[derive(Default)]
struct State {
    /// Last good zone per file name.
    good: BTreeMap<String, Arc<Zone>>,
    /// Current load error per file name.
    errors: BTreeMap<String, String>,
}

/// Zones directory with an atomically swapped snapshot.
pub struct ZoneStore {
    dir: PathBuf,
    set: ArcSwap<ZoneSet>,
    state: Mutex<State>,
}

impl ZoneStore {
    /// Opens `dir` (created if missing) and loads every zone file in it. Invalid files are
    /// recorded as load errors, not failures.
    ///
    /// # Errors
    /// Fails on invalid zone data or an i/o error.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Arc<Self>, ZoneError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let store = Arc::new(Self {
            dir,
            set: ArcSwap::from_pointee(ZoneSet::default()),
            state: Mutex::new(State::default()),
        });
        store.reload()?;
        Ok(store)
    }

    /// The current snapshot.
    pub fn snapshot(&self) -> Arc<ZoneSet> {
        self.set.load_full()
    }

    /// The load error of a zone file (by file name, e.g. `example.com.json`), if its latest
    /// version was invalid.
    pub fn load_error(&self, file_name: &str) -> Option<String> {
        self.lock().errors.get(file_name).cloned()
    }

    /// All current load errors keyed by file name.
    pub fn load_errors(&self) -> BTreeMap<String, String> {
        self.lock().errors.clone()
    }

    /// Rescans the directory. A file that fails to load keeps its previous version serving.
    ///
    /// # Errors
    /// Fails on invalid zone data or an i/o error.
    pub fn reload(&self) -> Result<(), ZoneError> {
        let mut found = BTreeMap::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if path.extension().is_some_and(|e| e == "json") && !file_name.starts_with('.') {
                found.insert(file_name.to_owned(), load_file(&path, file_name));
            }
        }
        let mut st = self.lock();
        let mut good = BTreeMap::new();
        let mut errors = BTreeMap::new();
        for (file, result) in found {
            match result {
                Ok((zone, warnings)) => {
                    for w in warnings {
                        tracing::warn!(zone = %zone.origin, "{w}");
                    }
                    good.insert(file, Arc::new(zone));
                }
                Err(e) => {
                    tracing::error!(file = %file, "zone file rejected, keeping previous version: {e}");
                    if let Some(prev) = st.good.get(&file) {
                        good.insert(file.clone(), Arc::clone(prev));
                    }
                    errors.insert(file, e.to_string());
                }
            }
        }
        let zones = good
            .values()
            .map(|z| (z.origin.clone(), Arc::clone(z)))
            .collect();
        st.good = good;
        st.errors = errors;
        self.set.store(Arc::new(ZoneSet { zones }));
        Ok(())
    }

    /// Validates `zone` and writes it atomically (temp file in the same directory, fsync,
    /// rename). Readers see the old or the new file, never a partial one. The snapshot is
    /// refreshed immediately.
    ///
    /// # Errors
    /// Fails on invalid zone data or an i/o error.
    pub fn write_zone(&self, zone: &Zone) -> Result<(), ZoneError> {
        let json = zone.to_json();
        Zone::from_json(&json)?;
        let file_name = zone.file_name()?;
        write_atomic(&self.dir, &file_name, json.as_bytes())?;
        self.reload()
    }

    /// Deletes a zone file and refreshes the snapshot.
    ///
    /// # Errors
    /// Fails on invalid zone data or an i/o error.
    pub fn remove_zone(&self, origin: &Name) -> Result<(), ZoneError> {
        fs::remove_file(self.dir.join(crate::zone_file_name(origin)?))?;
        self.reload()
    }

    /// Starts a watcher that reloads the directory 250 ms after the last change. Dropping the
    /// returned handle stops it.
    ///
    /// # Errors
    /// Fails on invalid zone data or an i/o error.
    pub fn watch(self: &Arc<Self>) -> Result<ZoneWatcher, ZoneError> {
        let (tx, rx) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |ev: notify::Result<notify::Event>| {
            // The receiver only disappears while the watcher is being dropped.
            let _ = tx.send(ev.is_ok());
        })
        .map_err(notify_err)?;
        watcher
            .watch(&self.dir, RecursiveMode::NonRecursive)
            .map_err(notify_err)?;
        let store = Arc::clone(self);
        let thread = std::thread::spawn(move || {
            while rx.recv().is_ok() {
                loop {
                    match rx.recv_timeout(DEBOUNCE) {
                        Ok(_) => {}
                        Err(RecvTimeoutError::Timeout) => break,
                        Err(RecvTimeoutError::Disconnected) => return,
                    }
                }
                if let Err(e) = store.reload() {
                    tracing::error!("zone reload failed: {e}");
                }
            }
        });
        Ok(ZoneWatcher {
            watcher: Some(watcher),
            thread: Some(thread),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Keeps the directory watcher alive.
pub struct ZoneWatcher {
    watcher: Option<RecommendedWatcher>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for ZoneWatcher {
    fn drop(&mut self) {
        // Dropping the watcher drops the channel sender, which ends the thread.
        self.watcher.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn notify_err(e: notify::Error) -> ZoneError {
    ZoneError::Io(std::io::Error::other(e))
}

fn load_file(path: &Path, file_name: &str) -> Result<(Zone, Vec<String>), ZoneError> {
    let text = fs::read_to_string(path)?;
    let (zone, warnings) = Zone::from_json(&text)?;
    let expected = zone.file_name()?;
    if expected != file_name {
        return Err(ZoneError::Invalid(format!(
            "file name must be {expected} for zone {}",
            zone.origin
        )));
    }
    Ok((zone, warnings))
}

fn write_atomic(dir: &Path, file_name: &str, bytes: &[u8]) -> Result<(), ZoneError> {
    let tmp = dir.join(format!(".{file_name}.tmp"));
    let mut f = fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(file_name))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use super::*;

    const EXAMPLE: &str = include_str!("../tests/fixtures/example.com.json");

    fn origin() -> Name {
        Name::from_ascii("example.com.").unwrap()
    }

    fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    #[test]
    fn reload_picks_up_change() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("example.com.json"), EXAMPLE).unwrap();
        let store = ZoneStore::open(dir.path()).unwrap();
        let _watch = store.watch().unwrap();
        assert_eq!(
            store.snapshot().get(&origin()).unwrap().soa.serial,
            2_026_102_001
        );
        fs::write(
            dir.path().join("example.com.json"),
            EXAMPLE.replace("2026102001", "2026102002"),
        )
        .unwrap();
        assert!(wait_for(|| store
            .snapshot()
            .get(&origin())
            .is_some_and(|z| z.soa.serial == 2_026_102_002)));
        fs::remove_file(dir.path().join("example.com.json")).unwrap();
        assert!(wait_for(|| store.snapshot().is_empty()));
    }

    #[test]
    fn reload_keeps_previous_zone_on_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("example.com.json");
        fs::write(&path, EXAMPLE).unwrap();
        let store = ZoneStore::open(dir.path()).unwrap();
        let _watch = store.watch().unwrap();
        fs::write(&path, "{ half written").unwrap();
        assert!(wait_for(|| store.load_error("example.com.json").is_some()));
        assert_eq!(store.snapshot().get(&origin()).unwrap().records.len(), 10);
        // A fixed file clears the error.
        fs::write(&path, EXAMPLE.replace("2026102001", "2026102003")).unwrap();
        assert!(wait_for(|| store.load_error("example.com.json").is_none()));
        assert_eq!(
            store.snapshot().get(&origin()).unwrap().soa.serial,
            2_026_102_003
        );
    }

    #[test]
    fn invalid_at_startup_and_misnamed_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("bad.json"), "nope").unwrap();
        fs::write(dir.path().join("other.json"), EXAMPLE).unwrap();
        fs::write(dir.path().join("notes.txt"), "ignored").unwrap();
        let store = ZoneStore::open(dir.path()).unwrap();
        assert!(store.snapshot().is_empty());
        let errors = store.load_errors();
        assert_eq!(errors.len(), 2);
        assert!(errors["other.json"].contains("example.com.json"));
    }

    #[test]
    fn write_zone_roundtrip_and_find() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path().join("zones")).unwrap();
        let (zone, _) = Zone::from_json(EXAMPLE).unwrap();
        store.write_zone(&zone).unwrap();
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap.iter().count(), 1);
        let www = Name::from_ascii("a.b.WWW.example.com.").unwrap();
        assert_eq!(snap.find(&www).unwrap().origin, origin());
        assert!(
            snap.find(&Name::from_ascii("example.org.").unwrap())
                .is_none()
        );
        store.remove_zone(&origin()).unwrap();
        assert!(store.snapshot().is_empty());
        assert!(store.remove_zone(&origin()).is_err());
    }

    #[test]
    fn atomic_write_never_partial() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path()).unwrap();
        let (mut zone, _) = Zone::from_json(EXAMPLE).unwrap();
        store.write_zone(&zone).unwrap();
        let path = dir.path().join("example.com.json");
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let mut reads = 0_u32;
                while !done.load(Ordering::Relaxed) {
                    let text = fs::read_to_string(&path).unwrap();
                    Zone::from_json(&text).expect("reader saw a partial file");
                    reads += 1;
                }
                reads
            })
        };
        for serial in 1..200 {
            zone.soa.serial = serial;
            store.write_zone(&zone).unwrap();
        }
        done.store(true, Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0);
        assert_eq!(store.snapshot().get(&origin()).unwrap().soa.serial, 199);
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1, "{leftovers:?}");
    }

    #[test]
    fn write_zone_rejects_invalid_zone() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path()).unwrap();
        let (mut zone, _) = Zone::from_json(EXAMPLE).unwrap();
        zone.dnssec.as_mut().unwrap().algorithm = 8;
        assert!(store.write_zone(&zone).is_err());
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }
}
