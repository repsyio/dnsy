//! The compiled filter: hashed suffix sets with allowlist precedence.

use std::collections::{HashMap, HashSet};
use std::io::BufRead;
use std::net::{Ipv4Addr, Ipv6Addr};

use dnsy_proto::Name;

use crate::parse::{self, ListFormat, ParseStats, ReadStop};

/// Name reported for custom (operator) rules.
pub const CUSTOM_LIST: &str = "custom";

/// Default cap on block plus allow entries held in memory.
pub const DEFAULT_MAX_ENTRIES: usize = 5_000_000;

/// Default cap on the bytes read from one list source.
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

/// How a blocked query is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockMode {
    NxDomain,
    /// `0.0.0.0` for A and `::` for AAAA.
    NullIp,
    Refused,
    /// Operator chosen sinkhole addresses; a family without an address answers NODATA.
    CustomIp {
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
    },
}

/// The filter decision for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block { list: String, mode: BlockMode },
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
    lists: Vec<String>,
    block: HashMap<Box<[u8]>, u16>,
    allow: HashSet<Box<[u8]>>,
}

impl FilterSetBuilder {
    #[must_use]
    pub fn new(mode: BlockMode, limits: FilterLimits) -> Self {
        Self {
            mode,
            limits,
            lists: Vec::new(),
            block: HashMap::new(),
            allow: HashSet::new(),
        }
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
                if let Err(e) = self.insert(key, allow, list) {
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
        self.insert(key, false, list)
    }

    /// Adds a custom allow rule (suffix match); allow always beats block.
    ///
    /// # Errors
    /// An invalid domain or the entry limit.
    pub fn add_allow_rule(&mut self, domain: &str) -> Result<(), BlocklistError> {
        let key = key_of(domain).ok_or_else(|| BlocklistError::InvalidDomain(domain.to_owned()))?;
        self.insert(key, true, 0)
    }

    fn list_index(&mut self, name: &str) -> Result<u16, BlocklistError> {
        if let Some(i) = self.lists.iter().position(|l| l == name) {
            return u16::try_from(i).map_err(|_| BlocklistError::TooManyLists);
        }
        let i = u16::try_from(self.lists.len()).map_err(|_| BlocklistError::TooManyLists)?;
        self.lists.push(name.to_owned());
        Ok(i)
    }

    fn insert(&mut self, key: Box<[u8]>, allow: bool, list: u16) -> Result<(), BlocklistError> {
        let max = self.limits.max_entries;
        if allow {
            if !self.allow.contains(&key) && self.block.len() + self.allow.len() >= max {
                return Err(BlocklistError::TooManyEntries(max));
            }
            self.allow.insert(key);
        } else if !self.block.contains_key(&key) {
            if self.block.len() + self.allow.len() >= max {
                return Err(BlocklistError::TooManyEntries(max));
            }
            self.block.insert(key, list);
        }
        Ok(())
    }

    #[must_use]
    pub fn build(mut self) -> FilterSet {
        self.block.shrink_to_fit();
        self.allow.shrink_to_fit();
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
    lists: Vec<String>,
    block: HashMap<Box<[u8]>, u16>,
    allow: HashSet<Box<[u8]>>,
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
        let wire = qname.to_lowercase();
        let wire = wire.as_wire();
        let mut hit: Option<u16> = None;
        let mut pos = 0;
        while pos < wire.len() && wire[pos] != 0 {
            let suffix = &wire[pos..];
            if self.allow.contains(suffix) {
                return Verdict::Allow;
            }
            if hit.is_none() {
                hit = self.block.get(suffix).copied();
            }
            pos += usize::from(wire[pos]) + 1;
        }
        match hit.and_then(|i| self.lists.get(usize::from(i))) {
            Some(list) => Verdict::Block {
                list: list.clone(),
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
