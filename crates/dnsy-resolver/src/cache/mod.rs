//! The DNS cache: sharded, size-bounded, with RFC 2308 negative caching, TTL clamping and decay,
//! and DNSSEC security-state isolation.
//!
//! Time is injected: every operation takes the current [`Instant`], so tests control the clock.

use std::collections::HashMap;
use std::hash::{BuildHasher, BuildHasherDefault, Hash, Hasher, RandomState};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dnsy_core::DnssecStatus;
use dnsy_proto::{
    Class, Edns, EdnsOption, Header, Message, Name, Question, RData, Rcode, Record, RecordType,
};

mod options;
mod prefetch;
mod stale;

pub use options::{CacheOptions, PrefetchOptions, ServeStaleOptions};
pub use stale::{Joined, RefreshGuard, RefreshWait, Refreshes};

#[cfg(test)]
mod tests;

/// Fewest shards; the cache uses `max(MIN_SHARDS, 4 x cores)` so contention stays flat as cores grow.
const MIN_SHARDS: usize = 16;
/// Random positions examined in a shard when an eviction is needed; the least recently used of
/// them goes.
const EVICTION_SAMPLE: usize = 8;
/// QTYPE 0 is reserved and never cached.
const RESERVED_TYPE: RecordType = RecordType::Unknown(0);

/// What identifies a cached response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Query name (compared case-insensitively).
    pub name: Name,
    pub qtype: RecordType,
    pub qclass: Class,
    /// The client set DO.
    pub do_bit: bool,
    /// The client set CD; such entries are never shared with CD=0 queries.
    pub cd_bit: bool,
}

/// Result of [`Cache::get`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    /// A live entry; record TTLs are already decremented to the remaining lifetime.
    Fresh {
        msg: Message,
        dnssec: DnssecStatus,
    },
    /// An expired entry inside the serve-stale window (RFC 8767). Record TTLs are the configured
    /// `answer_ttl`; a `Secure` entry is reported as `Indeterminate`, because its validation does
    /// not extend past the lifetime the validator allowed. The caller refreshes, and answers from
    /// this only when the refresh fails or is too slow (EDE 3, or 19 for NXDOMAIN).
    Stale {
        msg: Message,
        dnssec: DnssecStatus,
        /// Time since the entry expired.
        stale_for: Duration,
    },
    Miss,
}

/// Cache counters, a snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: u64,
    pub capacity: u64,
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
    pub expired: u64,
    pub stale_served: u64,
    pub prefetches: u64,
}

/// How an entry is stored. A name-level NXDOMAIN answers every type; the flag keeps it apart from
/// per-type entries whatever the wire QTYPE is (stored as ANY). `hash` is the cache's keyed
/// (`RandomState`) hash of the rest, computed once: it picks the shard and indexes the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StoreKey {
    key: CacheKey,
    by_name: bool,
    hash: u64,
}

impl StoreKey {
    fn probe(&self) -> Probe<'_> {
        Probe {
            key: &self.key,
            by_name: self.by_name,
            hash: self.hash,
        }
    }
}

/// A lookup for a [`StoreKey`] that borrows the asked key instead of copying it.
#[derive(Clone, Copy)]
struct Probe<'a> {
    key: &'a CacheKey,
    by_name: bool,
    hash: u64,
}

impl Probe<'_> {
    fn matches(&self, stored: &StoreKey) -> bool {
        let (a, b) = (self.key, &stored.key);
        stored.hash == self.hash
            && stored.by_name == self.by_name
            && (self.by_name || a.qtype == b.qtype)
            && a.qclass == b.qclass
            && a.do_bit == b.do_bit
            && a.cd_bit == b.cd_bit
            && a.name == b.name
    }

    fn to_store_key(self) -> StoreKey {
        StoreKey {
            key: CacheKey {
                qtype: if self.by_name {
                    RecordType::Any
                } else {
                    self.key.qtype
                },
                ..self.key.clone()
            },
            by_name: self.by_name,
            hash: self.hash,
        }
    }
}

/// Passes a precomputed [`StoreKey::hash`] through.
#[derive(Default)]
struct PassThrough(u64);

impl Hasher for PassThrough {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

#[derive(Debug)]
struct Entry {
    /// Shared: a hit clones the `Arc` under the shard lock and copies the message outside it.
    msg: Arc<Message>,
    dnssec: DnssecStatus,
    stored_at: Instant,
    expires_at: Instant,
    /// End of the serve-stale window.
    stale_until: Instant,
    /// The shard's `clock` at the last use (only compared within one shard).
    last_used: u64,
    /// Fresh hits so far (prefetch popularity).
    hits: u32,
    /// A prefetch was already started for this entry.
    prefetch_started: bool,
}

struct Slot {
    key: StoreKey,
    entry: Entry,
}

/// Entries in a dense vector (so eviction can sample random positions), indexed by key hash. The
/// hash is keyed, so two live keys sharing one is an accident (about 1 in 2^64 per pair) that
/// costs a cache entry, never a wrong answer: the later key replaces the earlier one, and every
/// lookup compares the full key.
#[derive(Default)]
struct Shard {
    index: HashMap<u64, usize, BuildHasherDefault<PassThrough>>,
    slots: Vec<Slot>,
    /// Advances on each use under the shard lock; eviction only compares entries of one shard,
    /// so no global counter is needed.
    clock: u64,
}

/// A shard with its own counters, padded so neighbouring shards never share a cache line.
#[derive(Default)]
#[repr(align(128))]
struct ShardCell {
    shard: Mutex<Shard>,
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
}

impl Shard {
    fn len(&self) -> usize {
        self.slots.len()
    }

    /// Drops every entry (the clock keeps running).
    fn clear(&mut self) {
        self.index.clear();
        self.slots.clear();
    }

    fn touch(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn position(&self, probe: &Probe<'_>) -> Option<usize> {
        self.index
            .get(&probe.hash)
            .copied()
            .filter(|&i| probe.matches(&self.slots[i].key))
    }

    fn get(&self, probe: &Probe<'_>) -> Option<&Entry> {
        self.position(probe).map(|i| &self.slots[i].entry)
    }

    fn get_mut(&mut self, probe: &Probe<'_>) -> Option<&mut Entry> {
        self.position(probe).map(|i| &mut self.slots[i].entry)
    }

    /// Stores `entry`; true when the shard grew (false when it replaced an entry).
    fn insert(&mut self, key: StoreKey, entry: Entry) -> bool {
        if let Some(&i) = self.index.get(&key.hash) {
            self.slots[i] = Slot { key, entry };
            return false;
        }
        self.index.insert(key.hash, self.slots.len());
        self.slots.push(Slot { key, entry });
        true
    }

    fn remove(&mut self, probe: &Probe<'_>) -> bool {
        match self.position(probe) {
            Some(i) => {
                self.remove_at(i);
                true
            }
            None => false,
        }
    }

    fn remove_at(&mut self, i: usize) {
        let gone = self.slots.swap_remove(i);
        self.index.remove(&gone.key.hash);
        if let Some(moved) = self.slots.get(i) {
            self.index.insert(moved.key.hash, i);
        }
    }

    /// Keeps the entries whose key satisfies `keep`; returns how many were removed.
    fn retain(&mut self, keep: impl Fn(&StoreKey) -> bool) -> usize {
        let before = self.slots.len();
        self.slots.retain(|s| keep(&s.key));
        if self.slots.len() != before {
            self.index = self
                .slots
                .iter()
                .enumerate()
                .map(|(i, s)| (s.key.hash, i))
                .collect();
        }
        before - self.slots.len()
    }

    /// Position of the least recently used entry among [`EVICTION_SAMPLE`] random positions (all
    /// of them in a shard that small), never position `keep`.
    fn sample_victim(&self, keep: Option<usize>) -> Option<usize> {
        let candidates = self.slots.len().checked_sub(usize::from(keep.is_some()))?;
        let skip = |i: usize| match keep {
            Some(k) if i >= k => i + 1,
            _ => i,
        };
        let oldest = |i: &usize| self.slots[*i].entry.last_used;
        if candidates <= EVICTION_SAMPLE {
            // A small shard is examined whole.
            (0..candidates).map(skip).min_by_key(oldest)
        } else {
            (0..EVICTION_SAMPLE)
                .map(|_| skip(rand::random_range(0..candidates)))
                .min_by_key(oldest)
        }
    }
}

/// A sharded, bounded DNS cache.
pub struct Cache {
    shards: Vec<ShardCell>,
    hasher: RandomState,
    cfg: ArcSwap<CacheOptions>,
    /// Live entries across all shards: the bound applies to this, not to each shard.
    len: AtomicUsize,
    evictions: AtomicU64,
    expired: AtomicU64,
    stale_served: AtomicU64,
    prefetches: AtomicU64,
}

fn lock(shard: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    shard.lock().unwrap_or_else(PoisonError::into_inner)
}

fn secs(d: Duration) -> u32 {
    u32::try_from(d.as_secs()).unwrap_or(u32::MAX)
}

impl Cache {
    /// A cache sized and tuned by `[cache]`.
    #[must_use]
    pub fn new(cfg: CacheOptions) -> Cache {
        let cores = std::thread::available_parallelism().map_or(1, usize::from);
        // At least 16 shards (fewer only for a cache smaller than that), at most 4 per core, and
        // never so many that a shard holds fewer than about 64 entries (eviction samples inside one shard).
        let wanted = MIN_SHARDS.max(4 * cores);
        let count = wanted
            .min(cfg.max_entries / 64)
            .max(MIN_SHARDS.min(cfg.max_entries))
            .max(1);
        let shards = (0..count).map(|_| ShardCell::default()).collect();
        Cache {
            shards,
            hasher: RandomState::new(),
            cfg: ArcSwap::from_pointee(cfg),
            len: AtomicUsize::new(0),
            evictions: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            stale_served: AtomicU64::new(0),
            prefetches: AtomicU64::new(0),
        }
    }

    fn cfg(&self) -> arc_swap::Guard<Arc<CacheOptions>> {
        self.cfg.load()
    }

    /// Changes the live configuration. Applies to later lookups and inserts; `max_entries` is
    /// not meant to change at runtime (the shard count is fixed at construction).
    pub fn reconfigure(&self, update: impl FnOnce(&mut CacheOptions)) {
        let mut next = CacheOptions::clone(&self.cfg.load());
        update(&mut next);
        self.cfg.store(Arc::new(next));
    }

    /// The per-type entry for `key`.
    fn exact_key<'a>(&self, key: &'a CacheKey) -> Probe<'a> {
        self.probe(key, false)
    }

    /// The name-level NXDOMAIN entry for `key`'s name.
    fn name_key<'a>(&self, key: &'a CacheKey) -> Probe<'a> {
        self.probe(key, true)
    }

    fn probe<'a>(&self, key: &'a CacheKey, by_name: bool) -> Probe<'a> {
        let qtype = if by_name { RecordType::Any } else { key.qtype };
        let hash = self.hasher.hash_one((
            &key.name, qtype, key.qclass, key.do_bit, key.cd_bit, by_name,
        ));
        Probe { key, by_name, hash }
    }

    /// The shard for `hash`, from its high half (the shard index uses the low bits).
    fn shard_index(&self, hash: u64) -> usize {
        usize::try_from((hash >> 32) % self.shards.len() as u64).unwrap_or(0)
    }

    fn cell_for(&self, probe: &Probe<'_>) -> &ShardCell {
        &self.shards[self.shard_index(probe.hash)]
    }

    fn shard_for(&self, probe: &Probe<'_>) -> &Mutex<Shard> {
        &self.cell_for(probe).shard
    }

    /// Looks `key` up at `now`. An NXDOMAIN cached for the name answers any type. A Bogus entry
    /// is returned to a CD=0 query as SERVFAIL (carrying the entry's Extended DNS Errors).
    pub fn get(&self, key: &CacheKey, now: Instant) -> CacheLookup {
        self.get_for(key, now, false)
    }

    /// Like [`Cache::get`]; with `serve_bogus` (permissive validation) a Bogus entry comes back
    /// as its data, still labelled Bogus, so the caller can serve it without AD.
    pub fn get_for(&self, key: &CacheKey, now: Instant, serve_bogus: bool) -> CacheLookup {
        let exact = self.exact_key(key);
        if self.cfg().enabled && key.qtype != RESERVED_TYPE {
            let mut stale = None;
            match self.get_exact(&exact, key, now, serve_bogus) {
                Some(found @ CacheLookup::Fresh { .. }) => return found,
                other => stale = stale.or(other),
            }
            // The name-level NXDOMAIN is looked at only when the exact entry did not answer.
            match self.get_exact(&self.name_key(key), key, now, serve_bogus) {
                Some(found @ CacheLookup::Fresh { .. }) => return found,
                other => stale = stale.or(other),
            }
            if let Some(found) = stale {
                self.cell_for(&exact).misses.fetch_add(1, Ordering::Relaxed);
                return found;
            }
        }
        self.cell_for(&exact).misses.fetch_add(1, Ordering::Relaxed);
        CacheLookup::Miss
    }

    fn get_exact(
        &self,
        stored_key: &Probe<'_>,
        asked: &CacheKey,
        now: Instant,
        serve_bogus: bool,
    ) -> Option<CacheLookup> {
        let cell = self.cell_for(stored_key);
        let mut shard = lock(&cell.shard);
        let tick = shard.touch();
        let entry = shard.get_mut(stored_key)?;
        if now >= entry.expires_at {
            if let Some(stale) = self.stale_view(entry, stored_key.by_name, asked, now) {
                entry.last_used = tick;
                return Some(stale);
            }
            shard.remove(stored_key);
            self.len.fetch_sub(1, Ordering::Relaxed);
            self.expired.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        entry.last_used = tick;
        entry.hits = entry.hits.saturating_add(1);
        cell.hits.fetch_add(1, Ordering::Relaxed);
        // A Bogus result is only ever shown to a validating (CD=0) client as SERVFAIL.
        if entry.dnssec == DnssecStatus::Bogus && !asked.cd_bit && !serve_bogus {
            return Some(CacheLookup::Fresh {
                msg: servfail_for(&entry.msg),
                dnssec: DnssecStatus::Bogus,
            });
        }
        let (stored, dnssec) = (Arc::clone(&entry.msg), entry.dnssec);
        let elapsed = secs(now.saturating_duration_since(entry.stored_at));
        // The copy and the TTL decrement happen outside the shard lock.
        drop(shard);
        let mut msg = Message::clone(&stored);
        for r in section_records_mut(&mut msg) {
            r.ttl = r.ttl.saturating_sub(elapsed);
        }
        if stored_key.by_name
            && let Some(q) = msg.questions.first_mut()
        {
            q.qtype = asked.qtype;
        }
        Some(CacheLookup::Fresh { msg, dnssec })
    }

    /// Stores `msg` (a response to `key`) with its validation outcome, if cacheable. The message
    /// is moved into the cache, not copied.
    ///
    /// Not cached: truncated or authoritative messages, rcodes other than NOERROR, NXDOMAIN and
    /// SERVFAIL, negative answers without an SOA, and anything whose lifetime works out to zero.
    /// A Bogus message never replaces a live Secure entry.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "signature pinned by the plan"
    )]
    pub fn insert(&self, key: CacheKey, msg: Message, dnssec: DnssecStatus, now: Instant) {
        if let Ok((key, entry)) = self.entry_for(&key, msg, dnssec, now) {
            self.put(key, entry, now);
        }
    }

    /// Like [`Cache::insert`], and returns the message to serve for this answer: the stored
    /// copy (TTL clamps applied, exactly as a cache hit at age zero would serve it) when `msg`
    /// is cacheable, `msg` unchanged otherwise.
    pub fn store(
        &self,
        key: &CacheKey,
        msg: Message,
        dnssec: DnssecStatus,
        now: Instant,
    ) -> Message {
        match self.entry_for(key, msg, dnssec, now) {
            Ok((key, entry)) => {
                let served = Message::clone(&entry.msg);
                self.put(key, entry, now);
                served
            }
            Err(msg) => msg,
        }
    }

    /// The entry to store for `msg` (TTL clamps applied), or `msg` back when it is not cacheable.
    #[expect(
        clippy::result_large_err,
        reason = "the error hands the uncacheable message back; boxing it would allocate per answer"
    )]
    fn entry_for(
        &self,
        key: &CacheKey,
        msg: Message,
        dnssec: DnssecStatus,
        now: Instant,
    ) -> Result<(StoreKey, Entry), Message> {
        if !self.cfg().enabled || msg.header.tc || msg.header.aa || key.qtype == RESERVED_TYPE {
            return Err(msg);
        }
        let mut stored = msg;
        let Some(ttl) = self.prepare(&mut stored, dnssec) else {
            return Err(stored);
        };
        for r in section_records_mut(&mut stored) {
            r.ttl = r.ttl.min(ttl);
        }
        if ttl == 0 {
            return Err(stored);
        }
        let key = if stored.header.rcode == Rcode::NxDomain && stored.answers.is_empty() {
            self.name_key(key)
        } else {
            self.exact_key(key)
        }
        .to_store_key();
        let lifetime = Duration::from_secs(u64::from(ttl));
        let stale = if self.cfg().serve_stale.enabled {
            Duration::from_secs(u64::from(self.cfg().serve_stale.max_stale))
        } else {
            Duration::ZERO
        };
        Ok((
            key,
            Entry {
                msg: Arc::new(stored),
                dnssec,
                stored_at: now,
                expires_at: now + lifetime,
                stale_until: now + lifetime + stale,
                last_used: 0,
                hits: 0,
                prefetch_started: false,
            },
        ))
    }

    /// Stores a prepared entry and evicts down to the bound.
    fn put(&self, key: StoreKey, mut entry: Entry, now: Instant) {
        let (hash, idx) = (key.hash, self.shard_index(key.hash));
        let mut shard = lock(&self.shards[idx].shard);
        entry.last_used = shard.touch();
        if entry.dnssec == DnssecStatus::Bogus
            && shard
                .get(&key.probe())
                .is_some_and(|e| e.dnssec == DnssecStatus::Secure && now < e.expires_at)
        {
            return;
        }
        let added = shard.insert(key, entry);
        self.shards[idx].inserts.fetch_add(1, Ordering::Relaxed);
        if !added {
            return;
        }
        let max = self.cfg().max_entries;
        if self.len.fetch_add(1, Ordering::Relaxed) < max {
            return;
        }
        // Over the bound: evict in the inserting shard while it holds more than its share.
        let fair_share = (max / self.shards.len()).max(1);
        while shard.len() > fair_share && self.len.load(Ordering::Relaxed) > max {
            let Some(victim) = shard.sample_victim(shard.index.get(&hash).copied()) else {
                break;
            };
            shard.remove_at(victim);
            self.evicted();
        }
        drop(shard);
        // The bound is global: when this shard is within its share, another one is over it.
        while self.len.load(Ordering::Relaxed) > max {
            if !self.evict_elsewhere(idx, fair_share) {
                break;
            }
        }
    }

    fn evicted(&self) {
        self.len.fetch_sub(1, Ordering::Relaxed);
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    /// Evicts one sampled entry from the first shard over its `fair_share`, visiting the shards other
    /// than `skip` one at a time from a random start (never holding more than one lock).
    fn evict_elsewhere(&self, skip: usize, fair_share: usize) -> bool {
        let n = self.shards.len();
        let start = rand::random_range(0..n);
        for i in (0..n).map(|o| (start + o) % n).filter(|&i| i != skip) {
            let mut shard = lock(&self.shards[i].shard);
            if shard.len() > fair_share
                && let Some(victim) = shard.sample_victim(None)
            {
                shard.remove_at(victim);
                self.evicted();
                return true;
            }
        }
        false
    }

    /// Works out the entry lifetime, clamping the record TTLs of `msg` in place; `None` (and
    /// `msg` untouched) when it is not cacheable.
    fn prepare(&self, msg: &mut Message, dnssec: DnssecStatus) -> Option<u32> {
        let cfg = self.cfg();
        let ttl = match msg.header.rcode {
            Rcode::ServFail => cfg.servfail_ttl,
            Rcode::NxDomain | Rcode::NoError if is_negative(msg) => {
                let soa = msg.authority.iter().find_map(|r| match &r.data {
                    RData::Soa(s) => Some(r.ttl.min(s.minimum)),
                    _ => None,
                })?;
                soa.min(cfg.negative_max_ttl)
            }
            Rcode::NoError => {
                for r in section_records_mut(msg) {
                    r.ttl = r.ttl.clamp(cfg.min_ttl, cfg.max_ttl.max(cfg.min_ttl));
                }
                section_records_mut(msg).map(|r| r.ttl).min()?
            }
            _ => return None,
        };
        Some(if dnssec == DnssecStatus::Bogus {
            ttl.min(cfg.bogus_ttl)
        } else {
            ttl
        })
    }

    /// Removes everything; returns the number of entries dropped.
    pub fn flush_all(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                let mut shard = lock(&s.shard);
                let n = shard.len();
                shard.clear();
                self.len.fetch_sub(n, Ordering::Relaxed);
                n
            })
            .sum()
    }

    /// Removes the entries for `name` (and everything below it with `subtree`); returns the count.
    pub fn flush_name(&self, name: &Name, subtree: bool) -> usize {
        self.shards
            .iter()
            .map(|s| {
                let removed = lock(&s.shard).retain(|k| {
                    let hit = if subtree {
                        k.key.name.is_subdomain_of(name)
                    } else {
                        k.key.name == *name
                    };
                    !hit
                });
                self.len.fetch_sub(removed, Ordering::Relaxed);
                removed
            })
            .sum()
    }

    /// One per-shard counter summed over the shards.
    fn sum(&self, counter: impl Fn(&ShardCell) -> &AtomicU64) -> u64 {
        self.shards
            .iter()
            .map(|c| counter(c).load(Ordering::Relaxed))
            .sum()
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> CacheStats {
        let entries = self.len.load(Ordering::Relaxed) as u64;
        CacheStats {
            entries,
            capacity: self.cfg().max_entries as u64,
            hits: self.sum(|c| &c.hits),
            misses: self.sum(|c| &c.misses),
            inserts: self.sum(|c| &c.inserts),
            evictions: self.evictions.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            stale_served: self.stale_served.load(Ordering::Relaxed),
            prefetches: self.prefetches.load(Ordering::Relaxed),
        }
    }
}

/// NXDOMAIN, or NOERROR without answers (NODATA or a referral): RFC 2308 negative answers.
fn is_negative(msg: &Message) -> bool {
    msg.header.rcode == Rcode::NxDomain
        || (msg.header.rcode == Rcode::NoError && msg.answers.is_empty())
}

/// Every record in the message except the EDNS OPT pseudo-record.
fn section_records_mut(msg: &mut Message) -> impl Iterator<Item = &mut Record> {
    msg.answers
        .iter_mut()
        .chain(msg.authority.iter_mut())
        .chain(msg.additional.iter_mut())
        .filter(|r| r.rtype != RecordType::Opt)
}

fn servfail_for(msg: &Message) -> Message {
    Message {
        header: Header {
            rcode: Rcode::ServFail,
            ad: false,
            aa: false,
            ..msg.header
        },
        questions: msg
            .questions
            .iter()
            .map(|q| Question {
                name: q.name.clone(),
                qtype: q.qtype,
                qclass: q.qclass,
            })
            .collect(),
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        edns: msg.edns.as_ref().map(|e| Edns {
            options: e
                .options
                .iter()
                .filter(|o| matches!(o, EdnsOption::ExtendedError { .. }))
                .cloned()
                .collect(),
            ..Edns::default()
        }),
    }
}
