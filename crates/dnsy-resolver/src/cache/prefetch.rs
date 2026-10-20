//! Prefetch of popular entries: an entry with at least `prefetch.min_hits` fresh hits whose
//! remaining lifetime has fallen to `prefetch.remaining_ttl_pct` percent is refreshed in the
//! background, once per entry. The caller owns the refresh itself (bounded queue, coalescing,
//! validation); the cache only says when an entry is due.

use std::sync::atomic::Ordering;
use std::time::Instant;

use dnsy_core::DnssecStatus;

use super::{Cache, CacheKey, StoreKey, lock};

impl Cache {
    /// True once, when the live entry for `key` qualifies for a prefetch at `now`.
    pub fn prefetch_due(&self, key: &CacheKey, now: Instant) -> bool {
        let live = self.cfg();
        let cfg = &live.prefetch;
        if !live.enabled || !cfg.enabled {
            return false;
        }
        for k in [StoreKey::exact(key), StoreKey::by_name(key)] {
            let mut shard = lock(self.shard_for(&k));
            let Some(e) = shard.map.get_mut(&k) else {
                continue;
            };
            if now >= e.expires_at {
                continue;
            }
            let remaining = e.expires_at.saturating_duration_since(now).as_millis();
            let lifetime = e
                .expires_at
                .saturating_duration_since(e.stored_at)
                .as_millis();
            let due = !e.prefetch_started
                && e.dnssec != DnssecStatus::Bogus
                && e.hits >= cfg.min_hits
                && remaining * 100 <= lifetime * u128::from(cfg.remaining_ttl_pct);
            if due {
                e.prefetch_started = true;
            }
            return due;
        }
        false
    }

    /// Counts one prefetch started.
    pub fn note_prefetch(&self) {
        self.prefetches.fetch_add(1, Ordering::Relaxed);
    }
}
