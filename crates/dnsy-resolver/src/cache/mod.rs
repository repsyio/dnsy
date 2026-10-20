//! The DNS cache: sharded, size-bounded, with RFC 2308 negative caching, TTL clamping and decay,
//! and DNSSEC security-state isolation.
//!
//! Time is injected: every operation takes the current [`Instant`], so tests control the clock.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use dnsy_config::Cache as CacheConfig;
use dnsy_core::DnssecStatus;
use dnsy_proto::{Class, Header, Message, Name, Question, RData, Rcode, Record, RecordType};

#[cfg(test)]
mod tests;

const MAX_SHARDS: usize = 16;
/// Entries examined when an eviction is needed; the oldest of the sample goes.
const EVICTION_SAMPLE: usize = 32;
/// Pseudo query type under which an NXDOMAIN is stored by name; it answers every type.
const ANY_TYPE: RecordType = RecordType::Unknown(0);

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

#[derive(Debug)]
struct Entry {
    msg: Message,
    dnssec: DnssecStatus,
    stored_at: Instant,
    expires_at: Instant,
    /// End of the serve-stale window (used by the stale lifecycle).
    #[expect(dead_code, reason = "read by serve-stale (DNSY-45)")]
    stale_until: Instant,
    last_used: u64,
}

struct Shard {
    map: HashMap<CacheKey, Entry>,
    capacity: usize,
}

/// A sharded, bounded DNS cache.
pub struct Cache {
    shards: Vec<Mutex<Shard>>,
    hasher: RandomState,
    cfg: CacheConfig,
    tick: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    inserts: AtomicU64,
    evictions: AtomicU64,
    expired: AtomicU64,
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
        let (base, extra) = (cfg.max_entries / count, cfg.max_entries % count);
        let shards = (0..count)
            .map(|i| {
                Mutex::new(Shard {
                    map: HashMap::new(),
                    capacity: base + usize::from(i < extra),
                })
            })
            .collect();
        Cache {
            shards,
            hasher: RandomState::new(),
            cfg: cfg.clone(),
            tick: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            inserts: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            expired: AtomicU64::new(0),
        }
    }

    fn shard_for(&self, key: &CacheKey) -> &Mutex<Shard> {
        let h = self.hasher.hash_one(key);
        let idx = usize::try_from(h % self.shards.len() as u64).unwrap_or(0);
        &self.shards[idx]
    }

    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed)
    }

    /// Looks `key` up at `now`. An NXDOMAIN cached for the name answers any type.
    pub fn get(&self, key: &CacheKey, now: Instant) -> CacheLookup {
        if self.cfg.enabled {
            let any_key = CacheKey {
                qtype: ANY_TYPE,
                ..key.clone()
            };
            for k in [key, &any_key] {
                if let Some(found) = self.get_exact(k, key, now) {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return found;
                }
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        CacheLookup::Miss
    }

    fn get_exact(
        &self,
        stored_key: &CacheKey,
        asked: &CacheKey,
        now: Instant,
    ) -> Option<CacheLookup> {
        let tick = self.next_tick();
        let mut shard = lock(self.shard_for(stored_key));
        let entry = shard.map.get_mut(stored_key)?;
        if now >= entry.expires_at {
            shard.map.remove(stored_key);
            self.expired.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        entry.last_used = tick;
        // A Bogus result is only ever shown to a validating (CD=0) client as SERVFAIL.
        if entry.dnssec == DnssecStatus::Bogus && !asked.cd_bit {
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
        if stored_key.qtype == ANY_TYPE
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
    pub fn insert(&self, key: CacheKey, msg: &Message, dnssec: DnssecStatus, now: Instant) {
        if !self.cfg.enabled || msg.header.tc || msg.header.aa {
            return;
        }
        let Some((ttl, mut stored)) = self.prepare(msg, dnssec) else {
            return;
        };
        if ttl == 0 {
            return;
        }
        let key = if stored.header.rcode == Rcode::NxDomain && stored.answers.is_empty() {
            CacheKey {
                qtype: ANY_TYPE,
                ..key
            }
        } else {
            key
        };
        for r in section_records_mut(&mut stored) {
            r.ttl = r.ttl.min(ttl);
        }
        let lifetime = Duration::from_secs(u64::from(ttl));
        let stale = if self.cfg.serve_stale.enabled {
            Duration::from_secs(u64::from(self.cfg.serve_stale.max_stale))
        } else {
            Duration::ZERO
        };
        let entry = Entry {
            msg: stored,
            dnssec,
            stored_at: now,
            expires_at: now + lifetime,
            stale_until: now + lifetime + stale,
            last_used: self.next_tick(),
        };
        let mut shard = lock(self.shard_for(&key));
        if dnssec == DnssecStatus::Bogus
            && shard
                .map
                .get(&key)
                .is_some_and(|e| e.dnssec == DnssecStatus::Secure && now < e.expires_at)
        {
            return;
        }
        if !shard.map.contains_key(&key) {
            while shard.map.len() >= shard.capacity.max(1) {
                if !self.evict_one(&mut shard) {
                    break;
                }
            }
        }
        shard.map.insert(key, entry);
        self.inserts.fetch_add(1, Ordering::Relaxed);
    }

    /// Works out the entry lifetime and the message to store (record TTLs clamped).
    fn prepare(&self, msg: &Message, dnssec: DnssecStatus) -> Option<(u32, Message)> {
        let cfg = &self.cfg;
        let mut stored = msg.clone();
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
                for r in section_records_mut(&mut stored) {
                    r.ttl = r.ttl.clamp(cfg.min_ttl, cfg.max_ttl.max(cfg.min_ttl));
                }
                section_records_mut(&mut stored).map(|r| r.ttl).min()?
            }
            _ => return None,
        };
        let ttl = if dnssec == DnssecStatus::Bogus {
            ttl.min(cfg.bogus_ttl)
        } else {
            ttl
        };
        Some((ttl, stored))
    }

    fn evict_one(&self, shard: &mut Shard) -> bool {
        let victim = shard
            .map
            .iter()
            .take(EVICTION_SAMPLE)
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                shard.map.remove(&k);
                self.evictions.fetch_add(1, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// Removes everything; returns the number of entries dropped.
    pub fn flush_all(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                let mut shard = lock(s);
                let n = shard.map.len();
                shard.map.clear();
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
                        k.name.is_subdomain_of(name)
                    } else {
                        k.name == *name
                    };
                    !hit
                });
                before - shard.map.len()
            })
            .sum()
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> CacheStats {
        let entries = self.shards.iter().map(|s| lock(s).map.len() as u64).sum();
        CacheStats {
            entries,
            capacity: self.cfg.max_entries as u64,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            inserts: self.inserts.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
            stale_served: 0,
            prefetches: 0,
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
    }
}
