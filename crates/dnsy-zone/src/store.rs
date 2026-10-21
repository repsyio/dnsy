//! The zones directory: loading, atomic writes, hot reload.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use dnsy_dnssec::SignedZone;
use dnsy_proto::Name;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::Notify;

use crate::lookup::ZoneIndex;
use crate::model::{Zone, ZoneError};

/// Quiet period after the last file event before the directory is reloaded.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// Immutable snapshot of all loaded zones, with the signed snapshot of each zone that is
/// served signed.
#[derive(Debug, Default)]
pub struct ZoneSet {
    zones: BTreeMap<Name, Arc<Zone>>,
    signed: BTreeMap<Name, Arc<SignedZone>>,
    /// Zones with `dnssec.enabled` that could not be signed and have no signed snapshot to
    /// fall back on: queries for them are answered SERVFAIL rather than served unsigned.
    unavailable: BTreeSet<Name>,
    /// Per-zone lookup index, keyed like `zones`.
    pub(crate) indexes: BTreeMap<Name, ZoneIndex>,
    /// Query counter driving record set rotation.
    pub(crate) rotation: AtomicUsize,
}

impl ZoneSet {
    #[cfg(test)]
    pub(crate) fn new(zones: BTreeMap<Name, Arc<Zone>>) -> Self {
        Self::with_signed(zones, BTreeMap::new(), BTreeSet::new())
    }

    /// A snapshot serving each zone of `signed` (keyed by origin) from its signed snapshot.
    pub(crate) fn with_signed(
        zones: BTreeMap<Name, Arc<Zone>>,
        signed: BTreeMap<Name, Arc<SignedZone>>,
        unavailable: BTreeSet<Name>,
    ) -> Self {
        let indexes = zones
            .iter()
            .map(|(origin, zone)| {
                let index = ZoneIndex::build(zone, signed.get(origin).map(AsRef::as_ref));
                (origin.clone(), index)
            })
            .collect();
        Self {
            zones,
            signed,
            unavailable,
            indexes,
            rotation: AtomicUsize::new(0),
        }
    }

    /// The signed snapshot a zone is served from, when it is served signed.
    #[must_use]
    pub fn signed(&self, origin: &Name) -> Option<&Arc<SignedZone>> {
        self.signed.get(origin)
    }

    /// True when the zone is withheld because its signing failed (see [`ZoneSet::lookup`]).
    #[must_use]
    pub fn is_unavailable(&self, origin: &Name) -> bool {
        self.unavailable.contains(origin)
    }

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

/// The latest signed snapshot of a zone and the zone version it was signed from.
#[derive(Debug, Clone)]
pub(crate) struct SignedEntry {
    pub(crate) zone: Arc<Zone>,
    pub(crate) signed: Arc<SignedZone>,
}

#[derive(Default)]
struct State {
    /// Last good zone per file name.
    good: BTreeMap<String, Arc<Zone>>,
    /// Current load error per file name.
    errors: BTreeMap<String, String>,
    /// Latest signed snapshot per origin.
    signed: BTreeMap<Name, SignedEntry>,
    /// Why signing a zone failed, per origin, until it succeeds again.
    failures: BTreeMap<Name, String>,
}

/// Zones directory with an atomically swapped snapshot.
pub struct ZoneStore {
    dir: PathBuf,
    set: ArcSwap<ZoneSet>,
    state: Mutex<State>,
    /// Serialises every write (read-modify-write cycles included); never held by readers.
    write: Mutex<()>,
    /// Set once a [`crate::ZoneSigning`] serves zones with `dnssec.enabled` signed.
    signing: AtomicBool,
    /// Wakes the signing task when a signed zone needs a new snapshot.
    resign: Arc<Notify>,
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
            write: Mutex::new(()),
            signing: AtomicBool::new(false),
            resign: Arc::new(Notify::new()),
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
        st.good = good;
        st.errors = errors;
        self.publish(&mut st);
        Ok(())
    }

    /// Builds and swaps in the snapshot. A zone with `dnssec.enabled` is served from its
    /// latest signed snapshot once signing is on: when the zone changed since, the previous
    /// version keeps serving (still signed) until the signing task has re-signed it; a zone
    /// that was never signed serves unsigned until then.
    fn publish(&self, st: &mut State) {
        let signing = self.signing.load(Ordering::Acquire);
        let mut zones = BTreeMap::new();
        let mut signed = BTreeMap::new();
        let mut entries = BTreeMap::new();
        let mut unavailable = BTreeSet::new();
        let mut stale = false;
        for zone in st.good.values() {
            let origin = zone.origin.clone();
            let wants = signing && zone.dnssec.as_ref().is_some_and(|p| p.enabled);
            if !wants {
                st.failures.remove(&origin);
            }
            if let Some(entry) = st.signed.remove(&origin).filter(|_| wants) {
                stale |= *entry.zone != **zone;
                zones.insert(origin.clone(), Arc::clone(&entry.zone));
                signed.insert(origin.clone(), Arc::clone(&entry.signed));
                entries.insert(origin, entry);
            } else {
                stale |= wants;
                if wants && st.failures.contains_key(&origin) {
                    unavailable.insert(origin.clone());
                }
                zones.insert(origin, Arc::clone(zone));
            }
        }
        st.signed = entries;
        self.set
            .store(Arc::new(ZoneSet::with_signed(zones, signed, unavailable)));
        if stale {
            self.resign.notify_one();
        }
    }

    /// Serves signed snapshots for zones with `dnssec.enabled` from now on.
    pub(crate) fn enable_signing(&self) {
        self.signing.store(true, Ordering::Release);
    }

    /// The signal [`ZoneStore::publish`] raises when a signed zone needs signing.
    pub(crate) fn resign_signal(&self) -> Arc<Notify> {
        Arc::clone(&self.resign)
    }

    /// Every loaded zone with `dnssec.enabled`, with its latest signed snapshot.
    pub(crate) fn signing_state(&self) -> Vec<(Arc<Zone>, Option<SignedEntry>)> {
        let st = self.lock();
        st.good
            .values()
            .filter(|z| z.dnssec.as_ref().is_some_and(|p| p.enabled))
            .map(|z| (Arc::clone(z), st.signed.get(&z.origin).cloned()))
            .collect()
    }

    /// Records that signing `origin` failed (`Some(reason)`) or recovered (`None`), and swaps
    /// in a new snapshot. A zone with `dnssec.enabled` that fails before it was ever signed
    /// answers SERVFAIL; one with a signed snapshot keeps serving it. Returns true when the
    /// recorded failure changed, so the caller can log it once.
    pub(crate) fn set_signing_failure(&self, origin: &Name, failure: Option<String>) -> bool {
        let mut st = self.lock();
        let changed = match failure {
            Some(reason) => st.failures.insert(origin.clone(), reason.clone()) != Some(reason),
            None => st.failures.remove(origin).is_some(),
        };
        if changed {
            self.publish(&mut st);
        }
        changed
    }

    /// Zones that failed signing, with the reason; empty when every signed zone is healthy.
    #[must_use]
    pub fn signing_failures(&self) -> BTreeMap<Name, String> {
        self.lock().failures.clone()
    }

    /// Installs a signed snapshot of `zone` and swaps in a new snapshot.
    pub(crate) fn install_signed(&self, zone: Arc<Zone>, signed: Arc<SignedZone>) {
        let mut st = self.lock();
        st.failures.remove(&zone.origin);
        st.signed
            .insert(zone.origin.clone(), SignedEntry { zone, signed });
        self.publish(&mut st);
    }

    /// Validates `zone` and writes it atomically (temp file in the same directory, fsync,
    /// rename). Readers see the old or the new file, never a partial one. The snapshot is
    /// refreshed immediately. Replaces any existing version without touching its serial; use
    /// [`ZoneStore::update`] to edit a zone.
    ///
    /// # Errors
    /// Fails on invalid zone data or an i/o error.
    pub fn write_zone(&self, zone: &Zone) -> Result<(), ZoneError> {
        let _w = self.write_guard();
        self.write_locked(zone).map(|_| ())
    }

    /// Writes a new zone. Fails when the zone (or an invalid file of that name) exists, or
    /// when the store already holds `max_zones` zones.
    ///
    /// # Errors
    /// [`ZoneError::ZoneExists`], [`ZoneError::Invalid`] on invalid zone data or the limit,
    /// or an i/o error.
    pub fn create(&self, zone: &Zone, max_zones: usize) -> Result<Arc<Zone>, ZoneError> {
        let _w = self.write_guard();
        let file = zone.file_name()?;
        let exists = {
            let st = self.lock();
            st.good.contains_key(&file) || st.errors.contains_key(&file)
        };
        if exists {
            return Err(ZoneError::ZoneExists(zone.origin.clone()));
        }
        if self.lock().good.len() >= max_zones {
            return Err(ZoneError::Invalid(format!(
                "at most {max_zones} zones can be created"
            )));
        }
        self.write_locked(zone)
    }

    /// The single way to edit a zone. Under the store's write lock: loads the latest stored
    /// version of `origin`, fails with [`ZoneError::SerialMismatch`] when `expected_serial` is
    /// set and differs, applies `f` to a copy, bumps the SOA serial (every successful write
    /// does; whatever `f` set is overwritten), validates the result exactly like a zone file,
    /// and writes it atomically. When `f` or validation fails nothing is written. Returns the
    /// stored zone and `f`'s result.
    ///
    /// # Errors
    /// [`ZoneError::NoSuchZone`], [`ZoneError::SerialMismatch`], whatever `f` returns,
    /// [`ZoneError::Invalid`] when the edited zone is invalid or its origin changed, or an
    /// i/o error.
    pub fn update<T>(
        &self,
        origin: &Name,
        expected_serial: Option<u32>,
        f: impl FnOnce(&mut Zone) -> Result<T, ZoneError>,
    ) -> Result<(Arc<Zone>, T), ZoneError> {
        let _w = self.write_guard();
        let old = self.stored(origin)?;
        check_serial(expected_serial, &old)?;
        let mut zone = (*old).clone();
        let out = f(&mut zone)?;
        if zone.origin != old.origin {
            return Err(ZoneError::Invalid("the zone origin cannot change".into()));
        }
        zone.soa.serial = old.soa.serial.wrapping_add(1);
        Ok((self.write_locked(&zone)?, out))
    }

    /// Deletes a zone file and refreshes the snapshot. With `expected_serial` set, fails with
    /// [`ZoneError::SerialMismatch`] when the stored serial differs.
    ///
    /// # Errors
    /// [`ZoneError::NoSuchZone`], [`ZoneError::SerialMismatch`] or an i/o error.
    pub fn remove_zone(
        &self,
        origin: &Name,
        expected_serial: Option<u32>,
    ) -> Result<(), ZoneError> {
        let _w = self.write_guard();
        let old = self.stored(origin)?;
        check_serial(expected_serial, &old)?;
        fs::remove_file(self.dir.join(crate::zone_file_name(origin)?))?;
        self.reload()
    }

    /// The latest stored version of a zone. Unlike the snapshot, which may still serve an older
    /// signed version while a re-sign is pending, this is what [`ZoneStore::update`] edits.
    ///
    /// # Errors
    /// [`ZoneError::NoSuchZone`] when the zone is not loaded.
    pub fn stored(&self, origin: &Name) -> Result<Arc<Zone>, ZoneError> {
        let file = crate::zone_file_name(origin)?;
        self.lock()
            .good
            .get(&file)
            .cloned()
            .ok_or_else(|| ZoneError::NoSuchZone(origin.clone()))
    }

    /// Validates and writes `zone`, then reloads. The caller holds the write lock.
    fn write_locked(&self, zone: &Zone) -> Result<Arc<Zone>, ZoneError> {
        let json = zone.to_json();
        let (checked, _) = Zone::from_json(&json)?;
        let file_name = zone.file_name()?;
        write_atomic(&self.dir, &file_name, json.as_bytes())?;
        self.reload()?;
        Ok(Arc::new(checked))
    }

    fn write_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts a watcher that reloads the directory 250 ms after the last change. Dropping the
    /// returned handle stops it.
    ///
    /// # Errors
    /// Fails on invalid zone data or an i/o error.
    pub fn watch(self: &Arc<Self>) -> Result<ZoneWatcher, ZoneError> {
        let (tx, rx) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |ev: notify::Result<notify::Event>| {
            // Reading the zone files (which a reload does) produces access events; reacting to
            // them would make every reload trigger the next one.
            if ev.as_ref().map_or(true, |e| !e.kind.is_access()) {
                // The receiver only disappears while the watcher is being dropped.
                let _ = tx.send(ev.is_ok());
            }
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

fn check_serial(expected: Option<u32>, stored: &Zone) -> Result<(), ZoneError> {
    match expected {
        Some(expected) if expected != stored.soa.serial => Err(ZoneError::SerialMismatch {
            expected,
            actual: stored.soa.serial,
        }),
        _ => Ok(()),
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
        store.remove_zone(&origin(), None).unwrap();
        assert!(store.snapshot().is_empty());
        assert!(store.remove_zone(&origin(), None).is_err());
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

    fn open_example() -> (tempfile::TempDir, Arc<ZoneStore>) {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("example.com.json"), EXAMPLE).unwrap();
        let store = ZoneStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn a_record(host: &str, addr: &str) -> crate::Record {
        crate::Record {
            name: Name::from_ascii(&format!("{host}.example.com.")).unwrap(),
            ttl: 300,
            rdata: dnsy_proto::RData::parse(dnsy_proto::RecordType::A, addr).unwrap(),
        }
    }

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn update_bumps_serial_and_is_atomic() {
        let (dir, store) = open_example();
        let before = store.snapshot().get(&origin()).unwrap().records.len();
        let (zone, id) = store
            .update(&origin(), Some(2_026_102_001), |z| {
                // Whatever the closure sets for the serial is overwritten.
                z.soa.serial = 7;
                Ok(z.add_record(a_record("new", "192.0.2.77")))
            })
            .unwrap();
        assert_eq!(zone.soa.serial, 2_026_102_002);
        assert_eq!(zone.records.len(), before + 1);
        assert_eq!(id, a_record("new", "192.0.2.77").id());
        let live = store.snapshot();
        assert_eq!(live.get(&origin()).unwrap().soa.serial, 2_026_102_002);
        assert!(
            fs::read_to_string(dir.path().join("example.com.json"))
                .unwrap()
                .contains("192.0.2.77")
        );

        // A failing closure and an invalid result both leave file and serial untouched.
        let on_disk = fs::read_to_string(dir.path().join("example.com.json")).unwrap();
        let failed = store.update(&origin(), None, |z| -> Result<(), ZoneError> {
            z.add_record(a_record("lost", "192.0.2.78"));
            Err(ZoneError::Invalid("no".into()))
        });
        assert!(matches!(failed, Err(ZoneError::Invalid(_))));
        let invalid = store.update(&origin(), None, |z| {
            z.add_record(crate::Record {
                name: Name::from_ascii("www.example.com.").unwrap(),
                ttl: 60,
                rdata: dnsy_proto::RData::parse(
                    dnsy_proto::RecordType::Cname,
                    "elsewhere.example.com.",
                )
                .unwrap(),
            });
            Ok(())
        });
        assert!(matches!(invalid, Err(ZoneError::Invalid(_))), "{invalid:?}");
        assert_eq!(
            fs::read_to_string(dir.path().join("example.com.json")).unwrap(),
            on_disk
        );
        assert_eq!(
            store.snapshot().get(&origin()).unwrap().soa.serial,
            2_026_102_002
        );
        assert_eq!(file_names(dir.path()), ["example.com.json"]);
    }

    #[test]
    fn update_with_stale_serial_is_conflict() {
        let (dir, store) = open_example();
        store.update(&origin(), None, |_| Ok(())).unwrap();
        let on_disk = fs::read_to_string(dir.path().join("example.com.json")).unwrap();
        let res = store.update(&origin(), Some(2_026_102_001), |z| {
            z.add_record(a_record("late", "192.0.2.9"));
            Ok(())
        });
        assert!(
            matches!(
                res,
                Err(ZoneError::SerialMismatch {
                    expected: 2_026_102_001,
                    actual: 2_026_102_002
                })
            ),
            "{res:?}"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("example.com.json")).unwrap(),
            on_disk
        );
        let missing = store.update(&Name::from_ascii("nope.test.").unwrap(), None, |_| Ok(()));
        assert!(matches!(missing, Err(ZoneError::NoSuchZone(_))));
    }

    #[test]
    fn concurrent_updates_serialise() {
        let (_dir, store) = open_example();
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    for i in 0..5 {
                        store
                            .update(&origin(), None, |z| {
                                z.add_record(a_record(&format!("h{t}-{i}"), "192.0.2.5"));
                                Ok(())
                            })
                            .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let zone = store.snapshot().get(&origin()).cloned().unwrap();
        assert_eq!(zone.soa.serial, 2_026_102_001 + 40);
        assert_eq!(zone.records.len(), 10 + 40);
    }

    #[test]
    fn record_edits_need_no_api() {
        let (_dir, store) = open_example();
        let www = store
            .snapshot()
            .get(&origin())
            .unwrap()
            .records
            .iter()
            .find(|r| {
                r.name.to_string() == "www.example.com." && r.rdata.to_string() == "192.0.2.1"
            })
            .unwrap()
            .id();
        assert_eq!(
            www.as_str(),
            "d23bf1f7831e9cb4",
            "record ids are a stable format"
        );
        let (zone, ()) = store
            .update(&origin(), None, |z| {
                z.replace_record(&www, a_record("www", "192.0.2.2"))
            })
            .unwrap();
        assert!(zone.records.iter().all(|r| r.id() != www));
        let new = a_record("www", "192.0.2.2").id();
        let (zone, ()) = store
            .update(&origin(), None, |z| z.remove_record(&new))
            .unwrap();
        assert!(zone.records.iter().all(|r| r.id() != new));
        let gone = store.update(&origin(), None, |z| z.remove_record(&new));
        assert!(matches!(gone, Err(ZoneError::NoSuchRecord(_))));
    }

    #[test]
    fn create_and_remove_honour_limits_and_serial() {
        let dir = tempfile::tempdir().unwrap();
        let store = ZoneStore::open(dir.path()).unwrap();
        let (zone, _) = Zone::from_json(EXAMPLE).unwrap();
        store.create(&zone, 1).unwrap();
        assert!(matches!(
            store.create(&zone, 5),
            Err(ZoneError::ZoneExists(_))
        ));
        let (mut other, _) =
            Zone::from_json(&EXAMPLE.replace("example.com.", "other.test.")).unwrap();
        other.origin = Name::from_ascii("other.test.").unwrap();
        assert!(matches!(
            store.create(&other, 1),
            Err(ZoneError::Invalid(_))
        ));
        let stale = store.remove_zone(&origin(), Some(1));
        assert!(matches!(stale, Err(ZoneError::SerialMismatch { .. })));
        store.remove_zone(&origin(), Some(2_026_102_001)).unwrap();
        assert!(store.snapshot().is_empty());
        assert!(matches!(
            store.remove_zone(&origin(), None),
            Err(ZoneError::NoSuchZone(_))
        ));
    }
}
