//! Serve-stale (RFC 8767): expired entries stay for `serve_stale.max_stale`, and a lookup inside
//! that window yields [`CacheLookup::Stale`] so the caller can refresh and fall back to it.
//!
//! [`Refreshes`] coalesces refreshes per key: the first caller to [`Refreshes::begin`] a key does
//! the upstream work, everyone else answers from what they have instead of querying again.

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use dnsy_core::DnssecStatus;
use dnsy_proto::Rcode;

use super::{Cache, CacheKey, CacheLookup, Entry, section_records_mut};

impl Cache {
    /// The stale view of an expired `entry`, if it may still be served: serve-stale is on, the
    /// window is open, and the entry is neither Bogus nor a cached SERVFAIL.
    pub(super) fn stale_view(
        &self,
        entry: &Entry,
        by_name: bool,
        asked: &CacheKey,
        now: Instant,
    ) -> Option<CacheLookup> {
        let live = self.cfg();
        let cfg = &live.serve_stale;
        if !cfg.enabled
            || now >= entry.stale_until
            || entry.dnssec == DnssecStatus::Bogus
            || entry.msg.header.rcode == Rcode::ServFail
        {
            return None;
        }
        let mut msg = entry.msg.clone();
        for r in section_records_mut(&mut msg) {
            r.ttl = cfg.answer_ttl;
        }
        if by_name && let Some(q) = msg.questions.first_mut() {
            q.qtype = asked.qtype;
        }
        let dnssec = match entry.dnssec {
            DnssecStatus::Secure => DnssecStatus::Indeterminate,
            other => other,
        };
        Some(CacheLookup::Stale {
            msg,
            dnssec,
            stale_for: now.saturating_duration_since(entry.expires_at),
        })
    }

    /// Counts one answer actually served from a stale entry.
    pub fn note_stale_served(&self) {
        self.stale_served.fetch_add(1, Ordering::Relaxed);
    }
}

/// The keys with a refresh in flight.
#[derive(Debug, Default)]
pub struct Refreshes {
    inflight: Mutex<HashSet<CacheKey>>,
}

/// Holds a key's refresh slot; dropping it frees the slot.
#[derive(Debug)]
pub struct RefreshGuard {
    owner: Arc<Refreshes>,
    key: CacheKey,
}

impl Refreshes {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Claims the refresh of `key`; `None` when one is already in flight.
    #[must_use]
    pub fn begin(self: &Arc<Self>, key: &CacheKey) -> Option<RefreshGuard> {
        let mut set = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        set.insert(key.clone()).then(|| RefreshGuard {
            owner: Arc::clone(self),
            key: key.clone(),
        })
    }

    /// Refreshes in flight.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inflight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.owner
            .inflight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
    }
}
