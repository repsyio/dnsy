//! Serve-stale (RFC 8767): expired entries stay for `serve_stale.max_stale`, and a lookup inside
//! that window yields [`CacheLookup::Stale`] so the caller can refresh and fall back to it.
//!
//! [`Refreshes`] coalesces upstream work per key: the first caller to [`Refreshes::begin`] or
//! [`Refreshes::join`] a key does the upstream work. Serve-stale and prefetch callers that lose
//! answer from what they have; cache misses [`Refreshes::join`] and wait for the leader's result.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use dnsy_core::DnssecStatus;
use dnsy_proto::{Message, Rcode};
use tokio::sync::watch;

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
        let mut msg = Message::clone(&entry.msg);
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

/// The keys with a refresh in flight, each with the channel its result is published on.
///
/// A refresh is a single flight: the first caller of [`Refreshes::begin`] or
/// [`Refreshes::join`] for a key leads it; later [`Refreshes::join`] callers wait for the value
/// the leader passes to [`RefreshGuard::finish`]. The entry is removed as soon as the leader
/// finishes or is dropped, so a result (or an error) is shared only with requests that arrived
/// while it was in flight. Memory is bounded by the leaders in flight and the waiters per key.
#[derive(Debug)]
pub struct Refreshes<T = ()> {
    inflight: Mutex<HashMap<CacheKey, Flight<T>>>,
}

#[derive(Debug)]
struct Flight<T> {
    result: watch::Receiver<Option<T>>,
    waiters: Arc<AtomicUsize>,
}

/// Holds a key's refresh slot; dropping it (or [`RefreshGuard::finish`]) frees the slot.
/// Dropped without finishing (the leader was cancelled), its waiters see `None`.
#[derive(Debug)]
pub struct RefreshGuard<T = ()> {
    owner: Arc<Refreshes<T>>,
    key: CacheKey,
    /// Identifies this flight's map entry (a later flight of the same key has its own).
    waiters: Arc<AtomicUsize>,
    result: watch::Sender<Option<T>>,
}

/// A request waiting for another request's refresh of the same key.
#[derive(Debug)]
pub struct RefreshWait<T> {
    result: watch::Receiver<Option<T>>,
    waiters: Arc<AtomicUsize>,
}

/// The outcome of [`Refreshes::join`].
#[derive(Debug)]
pub enum Joined<T> {
    /// No refresh of the key was in flight: this caller does it.
    Leader(RefreshGuard<T>),
    /// Another caller is refreshing the key: wait for its result.
    Waiter(RefreshWait<T>),
    /// The key already has the maximum number of waiters.
    Busy,
}

impl<T> Default for Refreshes<T> {
    fn default() -> Self {
        Self {
            inflight: Mutex::new(HashMap::new()),
        }
    }
}

impl<T: Clone> Refreshes<T> {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Claims the refresh of `key`; `None` when one is already in flight.
    #[must_use]
    pub fn begin(self: &Arc<Self>, key: &CacheKey) -> Option<RefreshGuard<T>> {
        let mut map = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        if map.contains_key(key) {
            return None;
        }
        Some(self.lead(&mut map, key))
    }

    /// Claims the refresh of `key`, or waits for the one in flight when it has fewer than
    /// `max_waiters` waiters.
    #[must_use]
    pub fn join(self: &Arc<Self>, key: &CacheKey, max_waiters: usize) -> Joined<T> {
        let mut map = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(flight) = map.get(key) else {
            return Joined::Leader(self.lead(&mut map, key));
        };
        if flight.waiters.load(Ordering::Relaxed) >= max_waiters {
            return Joined::Busy;
        }
        flight.waiters.fetch_add(1, Ordering::Relaxed);
        Joined::Waiter(RefreshWait {
            result: flight.result.clone(),
            waiters: Arc::clone(&flight.waiters),
        })
    }

    fn lead(
        self: &Arc<Self>,
        map: &mut HashMap<CacheKey, Flight<T>>,
        key: &CacheKey,
    ) -> RefreshGuard<T> {
        let (tx, rx) = watch::channel(None);
        let waiters = Arc::new(AtomicUsize::new(0));
        map.insert(
            key.clone(),
            Flight {
                result: rx,
                waiters: Arc::clone(&waiters),
            },
        );
        RefreshGuard {
            owner: Arc::clone(self),
            key: key.clone(),
            waiters,
            result: tx,
        }
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

impl<T> Refreshes<T> {
    /// Removes the flight `waiters` identifies, if it is still in the map; returns how many
    /// requests were waiting for it. Nobody can join it afterwards.
    fn release(&self, key: &CacheKey, waiters: &Arc<AtomicUsize>) -> usize {
        let mut map = self.inflight.lock().unwrap_or_else(PoisonError::into_inner);
        match map.get(key) {
            Some(flight) if Arc::ptr_eq(&flight.waiters, waiters) => {
                map.remove(key);
                waiters.load(Ordering::Relaxed)
            }
            _ => 0,
        }
    }
}

impl<T: Clone> RefreshGuard<T> {
    /// Frees the slot and publishes the refresh's result to its waiters; `value` is called
    /// only when someone is waiting.
    pub fn finish(self, value: impl FnOnce() -> T) {
        if self.owner.release(&self.key, &self.waiters) > 0 {
            self.result.send_replace(Some(value()));
        }
    }
}

impl<T> Drop for RefreshGuard<T> {
    fn drop(&mut self) {
        // Already released by `finish`, or a no-op for a newer flight of the same key.
        self.owner.release(&self.key, &self.waiters);
    }
}

impl<T: Clone> RefreshWait<T> {
    /// The leader's result; `None` when the leader was dropped without one (cancelled).
    pub async fn wait(mut self) -> Option<T> {
        self.result
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|v| v.clone())
    }
}

impl<T> Drop for RefreshWait<T> {
    fn drop(&mut self) {
        self.waiters.fetch_sub(1, Ordering::Relaxed);
    }
}
