//! The DNS cache: sharded, size-bounded, with RFC 2308 negative caching, TTL clamping and decay,
//! and DNSSEC security-state isolation.
//!
//! Time is injected: every operation takes the current [`Instant`], so tests control the clock.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dnsy_config::Cache as CacheConfig;
use dnsy_core::DnssecStatus;
use dnsy_proto::{
    Class, Edns, EdnsOption, Header, Message, Name, Question, RData, Rcode, Record, RecordType,
};

mod prefetch;
mod stale;

pub use stale::{Joined, RefreshGuard, RefreshWait, Refreshes};

#[cfg(test)]
mod tests;

const MAX_SHARDS: usize = 16;
/// Entries examined per shard when an eviction is needed; the oldest of all samples goes.
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
/// per-type entries whatever the wire QTYPE is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StoreKey {
    key: CacheKey,
    by_name: bool,
}

impl StoreKey {
    fn exact(key: &CacheKey) -> Self {
        Self {
            key: key.clone(),
            by_name: false,
        }
    }

    fn by_name(key: &CacheKey) -> Self {
        Self {
            key: CacheKey {
                qtype: RecordType::Any,
                ..key.clone()
            },
            by_name: true,
        }
    }
}

#[derive(Debug)]
struct Entry {
    msg: Message,
    dnssec: DnssecStatus,
    stored_at: Instant,
    expires_at: Instant,
    /// End of the serve-stale window.
    stale_until: Instant,
    last_used: u64,
    /// Fresh hits so far (prefetch popularity).
    hits: u32,
    /// A prefetch was already started for this entry.
    prefetch_started: bool,
}

struct Shard {
    map: HashMap<StoreKey, Entry>,
}

/// A sharded, bounded DNS cache.
pub struct Cache {
    shards: Vec<Mutex<Shard>>,
    hasher: RandomState,
    cfg: ArcSwap<CacheConfig>,
    tick: AtomicU64,
    /// Live entries across all shards: the bound applies to this, not to each shard.
    len: AtomicUsize,
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
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
    pub fn new(cfg: &CacheConfig) -> Cache {
        let count = cfg.max_entries.clamp(1, MAX_SHARDS);
        let shards = (0..count)
            .map(|_| {
                Mutex::new(Shard {
                    map: HashMap::new(),
                })
            })
            .collect();
        Cache {
            shards,
            hasher: RandomState::new(),
            cfg: ArcSwap::from_pointee(cfg.clone()),
            tick: AtomicU64::new(0),
            len: AtomicUsize::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            stale_served: AtomicU64::new(0),
            prefetches: AtomicU64::new(0),
        }
    }

    fn cfg(&self) -> arc_swap::Guard<Arc<CacheConfig>> {
        self.cfg.load()
    }

    /// Changes the live configuration. Applies to later lookups and inserts; `max_entries` is
    /// not meant to change at runtime (the shard count is fixed at construction).
    pub fn reconfigure(&self, update: impl FnOnce(&mut CacheConfig)) {
        let mut next = CacheConfig::clone(&self.cfg.load());
        update(&mut next);
        self.cfg.store(Arc::new(next));
    }

    fn shard_for(&self, key: &StoreKey) -> &Mutex<Shard> {
        let h = self.hasher.hash_one(key);
        let idx = usize::try_from(h % self.shards.len() as u64).unwrap_or(0);
        &self.shards[idx]
    }

    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }

    /// Looks `key` up at `now`. An NXDOMAIN cached for the name answers any type. A Bogus entry
    /// is returned to a CD=0 query as SERVFAIL (carrying the entry's Extended DNS Errors).
    pub fn get(&self, key: &CacheKey, now: Instant) -> CacheLookup {
        self.get_for(key, now, false)
    }

    /// Like [`Cache::get`]; with `serve_bogus` (permissive validation) a Bogus entry comes back
    /// as its data, still labelled Bogus, so the caller can serve it without AD.
    pub fn get_for(&self, key: &CacheKey, now: Instant, serve_bogus: bool) -> CacheLookup {
        if self.cfg().enabled && key.qtype != RESERVED_TYPE {
            let mut stale = None;
            for k in [StoreKey::exact(key), StoreKey::by_name(key)] {
                match self.get_exact(&k, key, now, serve_bogus) {
                    Some(found @ CacheLookup::Fresh { .. }) => {
                        self.hits.fetch_add(1, Ordering::Relaxed);
                        return found;
                    }
                    Some(found) => stale = stale.or(Some(found)),
                    None => {}
                }
            }
            if let Some(found) = stale {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return found;
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        CacheLookup::Miss
    }

    fn get_exact(
        &self,
        stored_key: &StoreKey,
        asked: &CacheKey,
        now: Instant,
        serve_bogus: bool,
    ) -> Option<CacheLookup> {
        let tick = self.next_tick();
        let mut shard = lock(self.shard_for(stored_key));
        let entry = shard.map.get_mut(stored_key)?;
        if now >= entry.expires_at {
            if let Some(stale) = self.stale_view(entry, stored_key.by_name, asked, now) {
                entry.last_used = tick;
                return Some(stale);
            }
            shard.map.remove(stored_key);
            self.len.fetch_sub(1, Ordering::Relaxed);
            self.expired.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        entry.last_used = tick;
        entry.hits = entry.hits.saturating_add(1);
        // A Bogus result is only ever shown to a validating (CD=0) client as SERVFAIL.
        if entry.dnssec == DnssecStatus::Bogus && !asked.cd_bit && !serve_bogus {
            return Some(CacheLookup::Fresh {
                msg: servfail_for(&entry.msg),
                dnssec: DnssecStatus::Bogus,
            });
        }
        let elapsed = secs(now.saturating_duration_since(entry.stored_at));
        let mut msg = entry.msg.clone();
        for r in section_records_mut(&mut msg) {
            r.ttl = r.ttl.saturating_sub(elapsed);
        }
        if stored_key.by_name
            && let Some(q) = msg.questions.first_mut()
        {
            q.qtype = asked.qtype;
        }
        Some(CacheLookup::Fresh {
            msg,
            dnssec: entry.dnssec,
        })
    }

    /// Stores `msg` (a response to `key`) with its validation outcome, if cacheable.
    ///
    /// Not cached: truncated or authoritative messages, rcodes other than NOERROR, NXDOMAIN and
    /// SERVFAIL, negative answers without an SOA, and anything whose lifetime works out to zero.
    /// A Bogus message never replaces a live Secure entry.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "signature pinned by the plan"
    )]
    pub fn insert(&self, key: CacheKey, msg: &Message, dnssec: DnssecStatus, now: Instant) {
        self.store(&key, msg.clone(), dnssec, now);
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
        if !self.cfg().enabled || msg.header.tc || msg.header.aa || key.qtype == RESERVED_TYPE {
            return msg;
        }
        let mut stored = msg;
        let Some(ttl) = self.prepare(&mut stored, dnssec) else {
            return stored;
        };
        for r in section_records_mut(&mut stored) {
            r.ttl = r.ttl.min(ttl);
        }
        if ttl == 0 {
            return stored;
        }
        let key = if stored.header.rcode == Rcode::NxDomain && stored.answers.is_empty() {
            StoreKey::by_name(key)
        } else {
            StoreKey::exact(key)
        };
        let lifetime = Duration::from_secs(u64::from(ttl));
        let stale = if self.cfg().serve_stale.enabled {
            Duration::from_secs(u64::from(self.cfg().serve_stale.max_stale))
        } else {
            Duration::ZERO
        };
        let entry = Entry {
            msg: stored.clone(),
            dnssec,
            stored_at: now,
            expires_at: now + lifetime,
            stale_until: now + lifetime + stale,
            last_used: self.next_tick(),
            hits: 0,
            prefetch_started: false,
        };
        let mut shard = lock(self.shard_for(&key));
        if dnssec == DnssecStatus::Bogus
            && shard
                .map
                .get(&key)
                .is_some_and(|e| e.dnssec == DnssecStatus::Secure && now < e.expires_at)
        {
            return stored;
        }
        let added = shard.map.insert(key.clone(), entry).is_none();
        drop(shard);
        self.inserts.fetch_add(1, Ordering::Relaxed);
        if added {
            self.len.fetch_add(1, Ordering::Relaxed);
            while self.len.load(Ordering::Relaxed) > self.cfg().max_entries {
                if !self.evict_one(&key) {
                    break;
                }
            }
        }
        stored
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

    /// Evicts the least recently used entry among a per-shard sample, never `keep` (the entry
    /// just inserted). The bound is global, so the victim may live in any shard.
    fn evict_one(&self, keep: &StoreKey) -> bool {
        let mut best: Option<(u64, usize, StoreKey)> = None;
        for (i, s) in self.shards.iter().enumerate() {
            let shard = lock(s);
            let local = shard
                .map
                .iter()
                .filter(|(k, _)| *k != keep)
                .take(EVICTION_SAMPLE)
                .min_by_key(|(_, e)| e.last_used);
            if let Some((k, e)) = local
                && best.as_ref().is_none_or(|(t, _, _)| e.last_used < *t)
            {
                best = Some((e.last_used, i, k.clone()));
            }
        }
        let Some((_, i, k)) = best else {
            return false;
        };
        // Another thread may have removed it meanwhile; the caller's loop re-checks the length.
        if lock(&self.shards[i]).map.remove(&k).is_some() {
            self.len.fetch_sub(1, Ordering::Relaxed);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    /// Removes everything; returns the number of entries dropped.
    pub fn flush_all(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                let mut shard = lock(s);
                let n = shard.map.len();
                shard.map.clear();
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
                let mut shard = lock(s);
                let before = shard.map.len();
                shard.map.retain(|k, _| {
                    let hit = if subtree {
                        k.key.name.is_subdomain_of(name)
                    } else {
                        k.key.name == *name
                    };
                    !hit
                });
                let removed = before - shard.map.len();
                self.len.fetch_sub(removed, Ordering::Relaxed);
                removed
            })
            .sum()
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> CacheStats {
        let entries = self.len.load(Ordering::Relaxed) as u64;
        CacheStats {
            entries,
            capacity: self.cfg().max_entries as u64,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
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
