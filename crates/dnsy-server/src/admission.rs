//! Admission control shared by the listeners: one global slot pool per transport plus a
//! per-client cap keyed by [`dnsy_core::net::client_key`]. Connection pools can also recycle:
//! when the pool is full, the oldest idle connection is closed to make room for a new one.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dnsy_core::net::{ClientKey, client_key};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

/// How long a new connection waits for the slot of a connection that was asked to close.
const RECYCLE_WAIT: Duration = Duration::from_millis(500);

/// Per-client counters. Entries exist only while a client holds at least one slot, so the map is
/// bounded by the global cap.
#[derive(Debug)]
struct ClientCounts {
    max: usize,
    held: Mutex<HashMap<ClientKey, usize>>,
}

/// What a connection task shares with its pool: when it was last active, whether it is serving a
/// request, and the signal asking it to close.
#[derive(Debug)]
pub struct Activity {
    last: Mutex<Instant>,
    busy: AtomicUsize,
    recycling: AtomicBool,
    recycle: Notify,
}

/// Marks a request in flight on a connection; the connection counts as active until it drops.
#[derive(Debug)]
pub struct Busy(Arc<Activity>);

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            last: Mutex::new(Instant::now()),
            busy: AtomicUsize::new(0),
            recycling: AtomicBool::new(false),
            recycle: Notify::new(),
        })
    }

    /// Records traffic on the connection.
    pub fn touch(&self) {
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
    }

    /// A request started: the connection is not idle until the guard drops.
    #[must_use]
    pub fn begin(self: &Arc<Self>) -> Busy {
        self.touch();
        self.busy.fetch_add(1, Ordering::AcqRel);
        Busy(Arc::clone(self))
    }

    /// Resolves once the pool asked this connection to close to make room.
    pub async fn recycled(&self) {
        self.recycle.notified().await;
    }

    fn last(&self) -> Instant {
        *self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.touch();
        self.0.busy.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The live connections of a recycling pool.
#[derive(Debug, Default)]
struct Registry {
    next: AtomicU64,
    live: Mutex<HashMap<u64, Arc<Activity>>>,
}

impl Registry {
    fn live(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<Activity>>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A global cap with a per-client cap on top. Clone-free: share it behind an [`Arc`].
#[derive(Debug)]
pub struct SlotLimit {
    total: Arc<Semaphore>,
    clients: Arc<ClientCounts>,
    registry: Option<Arc<Registry>>,
}

/// Holds one global slot and one per-client slot; both are released on drop.
#[derive(Debug)]
pub struct Slot {
    _total: OwnedSemaphorePermit,
    clients: Arc<ClientCounts>,
    key: ClientKey,
    activity: Arc<Activity>,
    registered: Option<(Arc<Registry>, u64)>,
}

/// Why no slot was granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Denied {
    /// The global pool is empty.
    Total,
    /// The client holds its whole share.
    Client,
}

impl SlotLimit {
    /// A pool of `total` slots of which one client (`client_key`) may hold `per_client`.
    #[must_use]
    pub fn new(total: usize, per_client: usize) -> Arc<Self> {
        Self::build(total, per_client, None)
    }

    /// Like [`SlotLimit::new`] for connections: [`SlotLimit::acquire_or_recycle`] may close the
    /// oldest idle connection when the pool is full.
    #[must_use]
    pub fn new_connections(total: usize, per_client: usize) -> Arc<Self> {
        Self::build(total, per_client, Some(Arc::new(Registry::default())))
    }

    fn build(total: usize, per_client: usize, registry: Option<Arc<Registry>>) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::new(Semaphore::new(total)),
            clients: Arc::new(ClientCounts {
                max: per_client,
                held: Mutex::new(HashMap::new()),
            }),
            registry,
        })
    }

    /// A slot for `ip`, or `None` when the global pool or the client's own share is exhausted.
    #[must_use]
    pub fn try_acquire(&self, ip: IpAddr) -> Option<Slot> {
        self.acquire_now(ip).ok()
    }

    fn acquire_now(&self, ip: IpAddr) -> Result<Slot, Denied> {
        let total = Arc::clone(&self.total)
            .try_acquire_owned()
            .map_err(|_| Denied::Total)?;
        self.claim(ip, total)
    }

    fn claim(&self, ip: IpAddr, total: OwnedSemaphorePermit) -> Result<Slot, Denied> {
        let key = client_key(ip);
        {
            let mut held = self
                .clients
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = held.entry(key).or_insert(0);
            if *count >= self.clients.max {
                return Err(Denied::Client);
            }
            *count += 1;
        }
        let activity = Activity::new();
        let registered = self.registry.as_ref().map(|registry| {
            let id = registry.next.fetch_add(1, Ordering::Relaxed);
            registry.live().insert(id, Arc::clone(&activity));
            (Arc::clone(registry), id)
        });
        Ok(Slot {
            _total: total,
            clients: Arc::clone(&self.clients),
            key,
            activity,
            registered,
        })
    }

    /// Like [`SlotLimit::try_acquire`], but when only the global pool is full, asks the oldest idle
    /// connection to close and waits briefly for its slot (the BIND `tcp-clients` model). A client
    /// that holds its whole share never evicts anyone, and nothing is evicted while every
    /// connection is serving a request.
    pub async fn acquire_or_recycle(&self, ip: IpAddr) -> Option<Slot> {
        match self.acquire_now(ip) {
            Ok(slot) => return Some(slot),
            Err(Denied::Client) => return None,
            Err(Denied::Total) => {}
        }
        if self.client_at_cap(ip) || !self.recycle_oldest_idle() {
            return None;
        }
        let permit = tokio::time::timeout(RECYCLE_WAIT, Arc::clone(&self.total).acquire_owned())
            .await
            .ok()?
            .ok()?;
        self.claim(ip, permit).ok()
    }

    fn client_at_cap(&self, ip: IpAddr) -> bool {
        let held = self
            .clients
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.get(&client_key(ip))
            .is_some_and(|n| *n >= self.clients.max)
    }

    /// Asks the connection idle the longest to close; false when there is none.
    fn recycle_oldest_idle(&self) -> bool {
        let Some(registry) = &self.registry else {
            return false;
        };
        let live = registry.live();
        let victim = live
            .values()
            .filter(|a| a.busy.load(Ordering::Acquire) == 0 && !a.recycling.load(Ordering::Acquire))
            .min_by_key(|a| a.last());
        victim.is_some_and(|a| {
            a.recycling.store(true, Ordering::Release);
            a.recycle.notify_one();
            true
        })
    }
}

impl Slot {
    /// The connection's activity record: touch it on traffic, wait on it for a recycle request.
    #[must_use]
    pub fn activity(&self) -> Arc<Activity> {
        Arc::clone(&self.activity)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some((registry, id)) = &self.registered {
            registry.live().remove(id);
        }
        let mut held = self
            .clients
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn per_client_cap_leaves_room_for_others() {
        let limit = SlotLimit::new(10, 2);
        let a = limit.try_acquire(ip("192.0.2.1")).unwrap();
        let _b = limit.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(limit.try_acquire(ip("192.0.2.1")).is_none());
        assert!(limit.try_acquire(ip("192.0.2.2")).is_some());
        drop(a);
        assert!(limit.try_acquire(ip("192.0.2.1")).is_some());
    }

    #[test]
    fn global_cap_applies_to_everyone_and_frees_on_drop() {
        let limit = SlotLimit::new(1, 5);
        let held = limit.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(limit.try_acquire(ip("192.0.2.2")).is_none());
        drop(held);
        assert!(limit.try_acquire(ip("192.0.2.2")).is_some());
        assert!(limit.clients.held.lock().unwrap().len() <= 1);
    }

    #[test]
    fn ipv6_clients_share_a_slash_64() {
        let limit = SlotLimit::new(10, 1);
        let _a = limit.try_acquire(ip("2001:db8::1")).unwrap();
        assert!(limit.try_acquire(ip("2001:db8::2")).is_none());
        assert!(limit.try_acquire(ip("2001:db8:0:1::1")).is_some());
    }

    #[test]
    fn rejected_client_does_not_leak_a_global_slot() {
        let limit = SlotLimit::new(2, 1);
        let _a = limit.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(limit.try_acquire(ip("192.0.2.1")).is_none());
        assert!(limit.try_acquire(ip("192.0.2.2")).is_some());
    }

    #[tokio::test]
    async fn full_pool_recycles_the_oldest_idle_connection() {
        let limit = SlotLimit::new_connections(2, 2);
        let oldest = limit.try_acquire(ip("192.0.2.1")).unwrap();
        let newer = limit.try_acquire(ip("192.0.2.2")).unwrap();
        newer.activity().touch();
        let (oldest_activity, newer_activity) = (oldest.activity(), newer.activity());
        let closer = tokio::spawn(async move {
            oldest_activity.recycled().await;
            drop(oldest);
        });
        let third = limit.acquire_or_recycle(ip("192.0.2.3")).await;
        assert!(third.is_some(), "the new connection takes the freed slot");
        closer.await.unwrap();
        // The newer connection was not asked to close.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), newer_activity.recycled())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn busy_connections_and_full_client_shares_are_never_recycled() {
        let limit = SlotLimit::new_connections(2, 1);
        let a = limit.try_acquire(ip("192.0.2.1")).unwrap();
        let _b = limit.try_acquire(ip("192.0.2.2")).unwrap();
        // The same client over its own share: refused, nobody evicted.
        assert!(limit.acquire_or_recycle(ip("192.0.2.1")).await.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), a.activity().recycled())
                .await
                .is_err()
        );
        // Everyone busy: refused instead of cutting a request short.
        let busy_a = a.activity().begin();
        let busy_b = _b.activity().begin();
        assert!(limit.acquire_or_recycle(ip("192.0.2.3")).await.is_none());
        drop((busy_a, busy_b));
        // A plain pool never recycles.
        let plain = SlotLimit::new(1, 1);
        let _held = plain.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(plain.acquire_or_recycle(ip("192.0.2.2")).await.is_none());
    }
}
