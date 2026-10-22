//! The compiled filter: hashed suffix sets with allowlist precedence.

use std::io::BufRead;
use std::sync::Arc;

use dnsy_proto::Name;

use crate::parse::{self, ListFormat, ParseStats, ReadStop};

/// Name reported for custom (operator) rules.
pub const CUSTOM_LIST: &str = "custom";

/// Default cap on block plus allow entries held in memory.
pub const DEFAULT_MAX_ENTRIES: usize = 5_000_000;

/// Default cap on the bytes read from one list source.
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

pub use dnsy_core::BlockMode;

/// The filter decision for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block { list: Arc<str>, mode: BlockMode },
}

/// Why building a filter failed.
#[derive(Debug, thiserror::Error)]
pub enum BlocklistError {
    #[error("blocklist input exceeds the size limit")]
    InputTooLarge,
    #[error("too many entries (limit {0})")]
    TooManyEntries(usize),
    #[error("too many lists")]
    TooManyLists,
    #[error("invalid domain `{0}`")]
    InvalidDomain(String),
    #[error("reading blocklist: {0}")]
    Io(#[from] std::io::Error),
}

/// Memory limits applied while building.
#[derive(Debug, Clone, Copy)]
pub struct FilterLimits {
    pub max_entries: usize,
    pub max_input_bytes: u64,
}

impl Default for FilterLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
        }
    }
}

/// Collects lists and rules, then freezes them into a [`FilterSet`].
#[derive(Debug)]
pub struct FilterSetBuilder {
    mode: BlockMode,
    limits: FilterLimits,
    lists: Vec<Arc<str>>,
    block: KeyTable,
    allow: KeyTable,
}

impl FilterSetBuilder {
    #[must_use]
    pub fn new(mode: BlockMode, limits: FilterLimits) -> Self {
        Self {
            mode,
            limits,
            lists: Vec::new(),
            block: KeyTable::default(),
            allow: KeyTable::default(),
        }
    }

    /// Reserves room for `entries` more block entries, so that building does not grow the table
    /// by doubling (which holds the old and the new table at once). Pass the entry count the
    /// sources reported at their last load.
    pub fn reserve(&mut self, entries: usize) {
        self.block.reserve(entries.min(self.limits.max_entries));
    }

    /// Parses a list source into the set. Malformed lines are counted in the returned stats.
    ///
    /// # Errors
    /// Input larger than the byte limit, more entries than the entry limit, or an I/O error. On
    /// error the builder keeps whatever was added before the failure; discard it.
    pub fn add_list<R: BufRead>(
        &mut self,
        name: &str,
        format: ListFormat,
        reader: R,
    ) -> Result<ParseStats, BlocklistError> {
        let list = self.list_index(name)?;
        let mut stats = ParseStats::default();
        let mut failure: Option<BlocklistError> = None;
        let result = parse::for_each_line(reader, self.limits.max_input_bytes, |line| {
            let Some(line) = line else {
                stats.invalid += 1;
                return true;
            };
            let mut found: Vec<(Box<[u8]>, bool)> = Vec::new();
            let kind = parse::parse_line(line, format, &mut |e| {
                if let Some(key) = key_of(e.domain) {
                    found.push((key, e.allow));
                }
            });
            match kind {
                parse::LineKind::Skipped => stats.skipped += 1,
                parse::LineKind::Invalid => stats.invalid += 1,
                parse::LineKind::Parsed => {}
            }
            for (key, allow) in found {
                if let Err(e) = self.insert(&key, allow, list) {
                    failure = Some(e);
                    return false;
                }
                if allow {
                    stats.allows += 1;
                } else {
                    stats.blocks += 1;
                }
            }
            true
        });
        match result {
            Err(ReadStop::TooLarge) => return Err(BlocklistError::InputTooLarge),
            Err(ReadStop::Io(e)) => return Err(e.into()),
            Ok(()) => {}
        }
        failure.map_or(Ok(stats), Err)
    }

    /// Adds a custom block rule (suffix match) reported as [`CUSTOM_LIST`].
    ///
    /// # Errors
    /// An invalid domain or the entry limit.
    pub fn add_block_rule(&mut self, domain: &str) -> Result<(), BlocklistError> {
        let key = key_of(domain).ok_or_else(|| BlocklistError::InvalidDomain(domain.to_owned()))?;
        let list = self.list_index(CUSTOM_LIST)?;
        self.insert(&key, false, list)
    }

    /// Adds a custom allow rule (suffix match); allow always beats block.
    ///
    /// # Errors
    /// An invalid domain or the entry limit.
    pub fn add_allow_rule(&mut self, domain: &str) -> Result<(), BlocklistError> {
        let key = key_of(domain).ok_or_else(|| BlocklistError::InvalidDomain(domain.to_owned()))?;
        self.insert(&key, true, 0)
    }

    fn list_index(&mut self, name: &str) -> Result<u16, BlocklistError> {
        if let Some(i) = self.lists.iter().position(|l| &**l == name) {
            return u16::try_from(i).map_err(|_| BlocklistError::TooManyLists);
        }
        let i = u16::try_from(self.lists.len()).map_err(|_| BlocklistError::TooManyLists)?;
        self.lists.push(name.into());
        Ok(i)
    }

    fn insert(&mut self, key: &[u8], allow: bool, list: u16) -> Result<(), BlocklistError> {
        let max = self.limits.max_entries;
        let table = if allow {
            &mut self.allow
        } else {
            &mut self.block
        };
        if table.get(key).is_some() {
            return Ok(());
        }
        if self.block.len() + self.allow.len() >= max {
            return Err(BlocklistError::TooManyEntries(max));
        }
        let table = if allow {
            &mut self.allow
        } else {
            &mut self.block
        };
        table.insert(key, list);
        Ok(())
    }

    #[must_use]
    pub fn build(mut self) -> FilterSet {
        self.block.shrink();
        self.allow.shrink();
        FilterSet {
            mode: self.mode,
            lists: self.lists,
            block: self.block,
            allow: self.allow,
        }
    }
}

/// Immutable, cheap to query filter. Keys are lowercase wire-form suffixes, so a name and all
/// its subdomains match one entry.
#[derive(Debug)]
pub struct FilterSet {
    mode: BlockMode,
    lists: Vec<Arc<str>>,
    block: KeyTable,
    allow: KeyTable,
}

impl FilterSet {
    /// Number of block plus allow entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.block.len() + self.allow.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Decides `qname`: an allow entry on the name or any parent wins; otherwise the most
    /// specific blocking entry decides.
    #[must_use]
    pub fn check(&self, qname: &Name) -> Verdict {
        self.check_lowercase(&qname.to_lowercase())
    }

    /// [`FilterSet::check`] for a name the caller has already lowercased.
    #[must_use]
    pub fn check_lowercase(&self, qname: &Name) -> Verdict {
        let wire = qname.as_wire();
        let mut hit: Option<u16> = None;
        let mut pos = 0;
        while pos < wire.len() && wire[pos] != 0 {
            let suffix = &wire[pos..];
            if self.allow.get(suffix).is_some() {
                return Verdict::Allow;
            }
            if hit.is_none() {
                hit = self.block.get(suffix);
            }
            pos += usize::from(wire[pos]) + 1;
        }
        match hit.and_then(|i| self.lists.get(usize::from(i))) {
            Some(list) => Verdict::Block {
                list: Arc::clone(list),
                mode: self.mode,
            },
            None => Verdict::Allow,
        }
    }
}

fn key_of(domain: &str) -> Option<Box<[u8]>> {
    let domain = parse::normalize(domain)?;
    let name = Name::from_ascii(domain).ok()?;
    Some(name.to_lowercase().as_wire().into())
}

/// A set of lowercase wire-form names, each with the index of the list it came from.
///
/// The keys live back to back in one arena (`len`, name, list index) and an open-addressing
/// table of 32-bit arena offsets points at them, so a million entries cost about 30 bytes each
/// instead of a heap allocation and a 24-byte bucket apiece. Only list content inserts names
/// (queries only look entries up), but a hostile list could still ship names that collide under a
/// fixed hash and build long probe runs. So the multiply-rotate hash is seeded per process, and
/// when an insert leaves a probe run longer than [`MAX_PROBE`] the table is rebuilt under a new seed.
#[derive(Debug)]
struct KeyTable {
    /// Arena offset plus one per slot; zero is an empty slot. The length is zero or a power of two.
    slots: Vec<u32>,
    arena: Vec<u8>,
    len: usize,
    seed: Seed,
    /// Full rebuilds done under new seeds; stops at [`MAX_RESEEDS`] so a list whose names collide
    /// under every seed costs a bounded number of them.
    reseeds: usize,
}

impl Default for KeyTable {
    fn default() -> Self {
        Self::with_seed(process_seed())
    }
}

/// Longest probe run an insert may leave behind before the table is rebuilt under a new seed.
/// A well-mixed hash at the table's load factor (at most one half) stays far below this.
const MAX_PROBE: usize = 128;

/// Rebuilds under new seeds a table may do in its life. When they are used up the table keeps
/// its last seed and accepts long runs: lookups on such a table are slower, but a hostile list
/// cannot make loading quadratic.
const MAX_RESEEDS: usize = 8;

/// A 128-bit `SipHash` key.
type Seed = (u64, u64);

/// A fresh random seed from the standard library's per-instance random keys.
fn random_seed() -> Seed {
    use std::hash::BuildHasher as _;
    let state = std::collections::hash_map::RandomState::new();
    (state.hash_one(0_u8), state.hash_one(1_u8))
}

/// The seed every table starts from: random, fixed for the life of the process.
fn process_seed() -> Seed {
    static SEED: std::sync::OnceLock<Seed> = std::sync::OnceLock::new();
    *SEED.get_or_init(random_seed)
}

/// Arena bytes per entry assumed when reserving: length byte, a typical name, list index.
const TYPICAL_RECORD: usize = 32;

/// SipHash-2-4 of `key` under the 128-bit `seed`: the seed keys every round, so names cannot be
/// chosen to collide without knowing it.
#[expect(
    deprecated,
    reason = "`SipHasher` is the only std SipHash that takes explicit keys; the seed must be injectable for tests"
)]
fn hash_key(key: &[u8], seed: Seed) -> u64 {
    use std::hash::{Hasher as _, SipHasher};
    #[cfg(test)]
    if tests::FORCE_COLLISIONS.with(std::cell::Cell::get) {
        return 0;
    }
    let mut hasher = SipHasher::new_with_keys(seed.0, seed.1);
    hasher.write(key);
    hasher.finish()
}

/// The home slot of `hash` in a table of `mask + 1` slots: its low bits.
#[expect(
    clippy::cast_possible_truncation,
    reason = "only the low bits that fit the mask are used"
)]
fn slot_of(hash: u64, mask: usize) -> usize {
    hash as usize & mask
}

impl KeyTable {
    fn with_seed(seed: Seed) -> Self {
        Self {
            slots: Vec::new(),
            arena: Vec::new(),
            len: 0,
            seed,
            reseeds: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    /// The record at arena offset `at`: the name and its list index.
    fn record(&self, at: usize) -> (&[u8], u16) {
        let n = usize::from(self.arena[at]);
        let key = &self.arena[at + 1..at + 1 + n];
        let list = u16::from_le_bytes([self.arena[at + 1 + n], self.arena[at + 2 + n]]);
        (key, list)
    }

    /// The list index stored for `key`.
    fn get(&self, key: &[u8]) -> Option<u16> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut i = slot_of(hash_key(key, self.seed), mask);
        loop {
            let slot = self.slots[i];
            if slot == 0 {
                return None;
            }
            let (k, list) = self.record(slot as usize - 1);
            if k == key {
                return Some(list);
            }
            i = (i + 1) & mask;
        }
    }

    /// Adds `key` (at most 255 bytes, not yet present).
    fn insert(&mut self, key: &[u8], list: u16) {
        if (self.len + 1) * 2 > self.slots.len() {
            self.rehash(((self.len + 1) * 2).next_power_of_two().max(16));
        }
        let at = u32::try_from(self.arena.len() + 1).expect("arena below 4 GiB");
        self.arena
            .push(u8::try_from(key.len()).expect("a wire name is at most 255 bytes"));
        self.arena.extend_from_slice(key);
        self.arena.extend_from_slice(&list.to_le_bytes());
        let probe = self.place(hash_key(key, self.seed), at);
        self.len += 1;
        if probe > MAX_PROBE && self.reseeds < MAX_RESEEDS {
            self.reseed();
        }
    }

    /// Stores `at` in the first free slot from the home slot of `hash` and returns how many
    /// slots were passed over.
    fn place(&mut self, hash: u64, at: u32) -> usize {
        let mask = self.slots.len() - 1;
        let mut i = slot_of(hash, mask);
        let mut probe = 0;
        while self.slots[i] != 0 {
            i = (i + 1) & mask;
            probe += 1;
        }
        self.slots[i] = at;
        probe
    }

    /// Rebuilds the slot table with `slots` slots by walking the arena; returns the longest probe.
    fn rehash(&mut self, slots: usize) -> usize {
        self.slots = vec![0; slots];
        let mut longest = 0;
        let mut at = 0;
        while at < self.arena.len() {
            let n = usize::from(self.arena[at]);
            let hash = hash_key(&self.arena[at + 1..at + 1 + n], self.seed);
            let probe = self.place(hash, u32::try_from(at + 1).expect("arena below 4 GiB"));
            longest = longest.max(probe);
            at += n + 3;
        }
        longest
    }

    /// Rebuilds under new seeds until no probe run exceeds [`MAX_PROBE`] or the table's reseeds
    /// run out.
    fn reseed(&mut self) {
        while self.reseeds < MAX_RESEEDS {
            self.reseeds += 1;
            self.seed = random_seed();
            if self.rehash(self.slots.len()) <= MAX_PROBE {
                break;
            }
        }
    }

    /// Makes room for `entries` more entries in one allocation each.
    fn reserve(&mut self, entries: usize) {
        let total = self.len + entries;
        if total * 2 > self.slots.len() {
            self.rehash((total * 2).next_power_of_two().max(16));
        }
        self.arena.reserve(entries * TYPICAL_RECORD);
    }

    /// Returns arena slack to the allocator when a reservation was far off.
    fn shrink(&mut self) {
        if self.arena.capacity() > self.arena.len() + self.arena.len() / 4 {
            self.arena.shrink_to_fit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local! {
        /// Makes every key hash alike: names that collide under any seed.
        pub(super) static FORCE_COLLISIONS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    fn key(i: usize) -> Vec<u8> {
        key_of(&format!("host{i}.example.com")).unwrap().into_vec()
    }

    #[test]
    fn key_table_grows_and_finds_every_key() {
        let mut table = KeyTable::default();
        assert_eq!(table.get(&key(0)), None);
        for i in 0..5000 {
            table.insert(&key(i), u16::try_from(i % 7).unwrap());
        }
        assert_eq!(table.len(), 5000);
        for i in 0..5000 {
            assert_eq!(
                table.get(&key(i)),
                Some(u16::try_from(i % 7).unwrap()),
                "{i}"
            );
        }
        assert_eq!(table.get(&key(5000)), None);
        // A suffix of a stored name is not the stored name.
        assert_eq!(table.get(&key(1)[1..]), None);
    }

    /// The longest distance between an entry and its home slot.
    fn longest_probe(table: &KeyTable) -> usize {
        let mask = table.slots.len() - 1;
        table
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| **s != 0)
            .map(|(i, s)| {
                let (k, _) = table.record(*s as usize - 1);
                i.wrapping_sub(slot_of(hash_key(k, table.seed), mask)) & mask
            })
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn colliding_keys_stay_within_the_probe_cap() {
        const SEED: Seed = (0x1234_5678_9abc_def1, 0x0fed_cba9_8765_4321);
        let mut table = KeyTable::with_seed(SEED);
        table.reserve(500);
        let mask = table.slots.len() - 1;
        // Names that all start in one home slot under the known seed: what a hostile list ships.
        let home = slot_of(hash_key(&key(0), SEED), mask);
        let colliding: Vec<Vec<u8>> = (0..)
            .map(key)
            .filter(|k| slot_of(hash_key(k, SEED), mask) == home)
            .take(MAX_PROBE + 72)
            .collect();
        for k in &colliding {
            table.insert(k, 3);
        }
        assert_ne!(table.seed, SEED, "the table was rebuilt under a new seed");
        assert!(
            longest_probe(&table) <= MAX_PROBE,
            "{}",
            longest_probe(&table)
        );
        for k in &colliding {
            assert_eq!(table.get(k), Some(3));
        }
        assert_eq!(table.len(), colliding.len());
    }

    #[test]
    fn keys_that_collide_under_every_seed_cost_a_bounded_number_of_rebuilds() {
        FORCE_COLLISIONS.with(|f| f.set(true));
        let mut table = KeyTable::default();
        for i in 0..3000 {
            table.insert(&key(i), 1);
        }
        assert_eq!(table.reseeds, MAX_RESEEDS);
        assert_eq!(table.len(), 3000);
        for i in 0..3000 {
            assert_eq!(table.get(&key(i)), Some(1));
        }
        FORCE_COLLISIONS.with(|f| f.set(false));
    }

    #[test]
    fn tables_start_from_the_process_seed_and_it_is_not_a_constant() {
        assert_eq!(KeyTable::default().seed, process_seed());
        assert_ne!(random_seed(), random_seed());
    }

    #[test]
    fn key_table_reserved_up_front_never_rehashes() {
        let mut table = KeyTable::default();
        table.reserve(1000);
        let slots = table.slots.len();
        let arena = table.arena.capacity();
        for i in 0..1000 {
            table.insert(&key(i), 0);
        }
        assert_eq!(table.slots.len(), slots);
        assert_eq!(table.arena.capacity(), arena);
        assert_eq!(table.len(), 1000);
    }

    #[test]
    fn lowercase_check_matches_the_cased_check() {
        let mut b = FilterSetBuilder::new(BlockMode::NxDomain, FilterLimits::default());
        b.add_block_rule("Ads.Example.com").unwrap();
        let set = b.build();
        let cased = Name::from_ascii("WWW.ADS.example.COM").unwrap();
        let verdict = set.check(&cased);
        assert_eq!(verdict, set.check_lowercase(&cased.to_lowercase()));
        let Verdict::Block { list, .. } = verdict else {
            panic!("expected a block");
        };
        assert_eq!(&*list, CUSTOM_LIST);
    }
}
