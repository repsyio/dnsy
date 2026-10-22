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
/// instead of a heap allocation and a 24-byte bucket apiece. The names come from the operator's
/// lists (queries only look entries up), so a plain multiply-rotate hash is enough.
#[derive(Debug, Default)]
struct KeyTable {
    /// Arena offset plus one per slot; zero is an empty slot. The length is zero or a power of two.
    slots: Vec<u32>,
    arena: Vec<u8>,
    len: usize,
}

/// Arena bytes per entry assumed when reserving: length byte, a typical name, list index.
const TYPICAL_RECORD: usize = 32;

fn hash_key(key: &[u8]) -> u64 {
    const SEED: u64 = 0xf135_7aea_2e62_a9c5;
    let mut state = key.len() as u64;
    let (words, rest) = key.as_chunks::<8>();
    for word in words {
        state = (state.rotate_left(5) ^ u64::from_le_bytes(*word)).wrapping_mul(SEED);
    }
    if !rest.is_empty() {
        let mut word = [0_u8; 8];
        word[..rest.len()].copy_from_slice(rest);
        state = (state.rotate_left(5) ^ u64::from_le_bytes(word)).wrapping_mul(SEED);
    }
    state.rotate_left(26)
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
        let mut i = slot_of(hash_key(key), mask);
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
        self.place(hash_key(key), at);
        self.len += 1;
    }

    fn place(&mut self, hash: u64, at: u32) {
        let mask = self.slots.len() - 1;
        let mut i = slot_of(hash, mask);
        while self.slots[i] != 0 {
            i = (i + 1) & mask;
        }
        self.slots[i] = at;
    }

    /// Rebuilds the slot table with `slots` slots by walking the arena.
    fn rehash(&mut self, slots: usize) {
        self.slots = vec![0; slots];
        let mut at = 0;
        while at < self.arena.len() {
            let n = usize::from(self.arena[at]);
            let hash = hash_key(&self.arena[at + 1..at + 1 + n]);
            self.place(hash, u32::try_from(at + 1).expect("arena below 4 GiB"));
            at += n + 3;
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
