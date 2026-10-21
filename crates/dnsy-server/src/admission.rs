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
/// New connections that may wait for a recycled slot at once; further ones are closed at once.
const MAX_PENDING_RECYCLES: usize = 32;
/// One client may recycle at most one connection per interval.
const RECYCLE_INTERVAL: Duration = Duration::from_secs(1);
/// All clients together may recycle at most this many connections per [`RECYCLE_INTERVAL`].
const MAX_RECYCLES_PER_INTERVAL: u32 = 64;
/// Clients whose last recycle is remembered; when full, the oldest entry is forgotten.
const MAX_RECYCLE_CLIENTS: usize = 1024;
/// A connection that has not finished its handshake (or sent its first query) after this long is
/// fair game for recycling, ahead of established ones.
const ESTABLISH_GRACE: Duration = Duration::from_secs(5);

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
    created: Instant,
    last: Mutex<Instant>,
    established: AtomicBool,
    authenticated: AtomicBool,
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
            created: Instant::now(),
            last: Mutex::new(Instant::now()),
            established: AtomicBool::new(false),
            authenticated: AtomicBool::new(false),
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

    /// The connection finished its handshake (TLS for `DoT` and `DoH`) or sent its first complete
    /// query (plain TCP). Until then it is never chosen for recycling, so a flood of connections
    /// that never get that far cannot push out working ones.
    pub fn establish(&self) {
        self.established.store(true, Ordering::Release);
    }

    /// The peer proved an identity (mTLS client certificate, `DoH` token). Such a connection is
    /// never recycled: a new connection has no identity yet and so ranks below it.
    pub fn mark_authenticated(&self) {
        self.authenticated.store(true, Ordering::Release);
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
    /// Bounds the connections waiting for a recycled slot.
    pending: Arc<Semaphore>,
    /// When each client last recycled a connection.
    recycles: Mutex<RecycleLimits>,
    establish_grace: Duration,
}

/// Who recycled recently: per client (IPv6 by `/56`) and across all clients.
#[derive(Debug)]
struct RecycleLimits {
    per_client: HashMap<IpAddr, Instant>,
    window_start: Instant,
    in_window: u32,
}

/// The address a recycle is accounted to: IPv4 as is, IPv6 by `/56` (coarser than `client_key`).
fn recycle_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & (!0_u128 << 72))),
    }
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

    #[cfg(test)]
    fn with_establish_grace(self: Arc<Self>, grace: Duration) -> Arc<Self> {
        let mut inner = Arc::try_unwrap(self).expect("not shared yet");
        inner.establish_grace = grace;
        Arc::new(inner)
    }

    fn build(total: usize, per_client: usize, registry: Option<Arc<Registry>>) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::new(Semaphore::new(total)),
            clients: Arc::new(ClientCounts {
                max: per_client,
                held: Mutex::new(HashMap::new()),
            }),
            registry,
            pending: Arc::new(Semaphore::new(MAX_PENDING_RECYCLES)),
            recycles: Mutex::new(RecycleLimits {
                per_client: HashMap::new(),
                window_start: Instant::now(),
                in_window: 0,
            }),
            establish_grace: ESTABLISH_GRACE,
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
        if self.client_at_cap(ip) {
            return None;
        }
        // Never more than a few waiters, so a burst of connections cannot pile up tasks.
        let _waiting = Arc::clone(&self.pending).try_acquire_owned().ok()?;
        if !self.may_recycle(ip) || !self.recycle_oldest_idle() {
            return None;
        }
        let permit = tokio::time::timeout(RECYCLE_WAIT, Arc::clone(&self.total).acquire_owned())
            .await
            .ok()?
            .ok()?;
        self.claim(ip, permit).ok()
    }

    /// Whether `ip`'s client may recycle a connection now; counts it if so. Each client (IPv6 by
    /// `/56`) gets one per interval and all clients together at most
    /// [`MAX_RECYCLES_PER_INTERVAL`], so rotating addresses cannot mass-evict.
    fn may_recycle(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut limits = self
            .recycles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = recycle_key(ip);
        if limits
            .per_client
            .get(&key)
            .is_some_and(|t| now.saturating_duration_since(*t) < RECYCLE_INTERVAL)
        {
            return false;
        }
        if now.saturating_duration_since(limits.window_start) >= RECYCLE_INTERVAL {
            limits.window_start = now;
            limits.in_window = 0;
        }
        if limits.in_window >= MAX_RECYCLES_PER_INTERVAL {
            return false;
        }
        limits.in_window += 1;
        if limits.per_client.len() >= MAX_RECYCLE_CLIENTS && !limits.per_client.contains_key(&key) {
            // Forget the oldest client rather than refusing everyone new.
            let oldest = limits
                .per_client
                .iter()
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| *k);
            if let Some(oldest) = oldest {
                limits.per_client.remove(&oldest);
            }
        }
        limits.per_client.insert(key, now);
        true
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

    /// Asks one unauthenticated, idle connection to close; false when there is none. Connections
    /// that are still not established after [`ESTABLISH_GRACE`] go first, so silent connections
    /// cannot pin slots; younger unestablished ones are left alone (they may be mid-handshake).
    fn recycle_oldest_idle(&self) -> bool {
        let Some(registry) = &self.registry else {
            return false;
        };
        let live = registry.live();
        let victim = live
            .values()
            .filter(|a| {
                (a.established.load(Ordering::Acquire)
                    || a.created.elapsed() >= self.establish_grace)
                    && !a.authenticated.load(Ordering::Acquire)
                    && a.busy.load(Ordering::Acquire) == 0
                    && !a.recycling.load(Ordering::Acquire)
            })
            // Connections that never got going go first, then the longest idle.
            .min_by_key(|a| (a.established.load(Ordering::Acquire), a.last()));
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
        oldest.activity().establish();
        newer.activity().establish();
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
        let b = limit.try_acquire(ip("192.0.2.2")).unwrap();
        a.activity().establish();
        b.activity().establish();
        // The same client over its own share: refused, nobody evicted.
        assert!(limit.acquire_or_recycle(ip("192.0.2.1")).await.is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), a.activity().recycled())
                .await
                .is_err()
        );
        // Everyone busy: refused instead of cutting a request short.
        let busy_a = a.activity().begin();
        let busy_b = b.activity().begin();
        assert!(limit.acquire_or_recycle(ip("192.0.2.3")).await.is_none());
        drop((busy_a, busy_b));
        // A plain pool never recycles.
        let plain = SlotLimit::new(1, 1);
        let _held = plain.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(plain.acquire_or_recycle(ip("192.0.2.2")).await.is_none());
    }

    #[tokio::test]
    async fn unestablished_and_authenticated_connections_are_never_evicted() {
        let limit = SlotLimit::new_connections(3, 3);
        let authenticated = limit.try_acquire(ip("192.0.2.1")).unwrap();
        authenticated.activity().establish();
        authenticated.activity().mark_authenticated();
        let handshaking = limit.try_acquire(ip("192.0.2.2")).unwrap();
        let plain = limit.try_acquire(ip("192.0.2.3")).unwrap();
        plain.activity().establish();
        let (auth_activity, hs_activity) = (authenticated.activity(), handshaking.activity());
        let closer = tokio::spawn(async move {
            plain.activity().recycled().await;
            drop(plain);
        });
        // A flood from other addresses can only ever take the plain established connection.
        let flood_first = limit.acquire_or_recycle(ip("198.51.100.1")).await;
        assert!(flood_first.is_some());
        closer.await.unwrap();
        for n in 2..20 {
            let attacker = ip(&format!("198.51.100.{n}"));
            assert!(limit.acquire_or_recycle(attacker).await.is_none());
        }
        for activity in [auth_activity, hs_activity] {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), activity.recycled())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn one_client_recycles_at_most_one_connection_per_interval() {
        let limit = SlotLimit::new_connections(3, 3);
        let victims: Vec<_> = (1..=3)
            .map(|n| {
                let slot = limit.try_acquire(ip(&format!("192.0.2.{n}"))).unwrap();
                slot.activity().establish();
                slot
            })
            .collect();
        let activities: Vec<_> = victims.iter().map(Slot::activity).collect();
        let attacker = ip("198.51.100.1");
        let mut victims = victims.into_iter();
        let first = victims.next().unwrap();
        let closer = tokio::spawn(async move {
            activities[0].recycled().await;
            drop(first);
            activities
        });
        let taken = limit.acquire_or_recycle(attacker).await;
        assert!(taken.is_some());
        let activities = closer.await.unwrap();
        // Asking again at once is refused, however many idle connections remain.
        assert!(limit.acquire_or_recycle(attacker).await.is_none());
        for activity in &activities[1..] {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), activity.recycled())
                    .await
                    .is_err()
            );
        }
        drop(victims);
    }

    #[tokio::test]
    async fn silent_unestablished_connections_cannot_pin_slots() {
        let limit =
            SlotLimit::new_connections(2, 2).with_establish_grace(Duration::from_millis(30));
        let a = limit.try_acquire(ip("192.0.2.1")).unwrap();
        let b = limit.try_acquire(ip("192.0.2.1")).unwrap();
        // Fresh and silent: possibly mid-handshake, so left alone.
        assert!(limit.acquire_or_recycle(ip("198.51.100.1")).await.is_none());
        tokio::time::sleep(Duration::from_millis(40)).await;
        let (aa, ba) = (a.activity(), b.activity());
        let closers = tokio::spawn(async move {
            tokio::select! { () = aa.recycled() => drop(a), () = ba.recycled() => drop(b) }
        });
        // Past the grace period a silent connection is recycled for a newcomer.
        let taken = limit.acquire_or_recycle(ip("198.51.100.2")).await;
        assert!(taken.is_some());
        closers.await.unwrap();
    }

    #[tokio::test]
    async fn unestablished_newcomers_still_cannot_evict_authenticated_ones() {
        let limit = SlotLimit::new_connections(1, 1).with_establish_grace(Duration::ZERO);
        let auth = limit.try_acquire(ip("192.0.2.1")).unwrap();
        auth.activity().mark_authenticated();
        assert!(limit.acquire_or_recycle(ip("198.51.100.1")).await.is_none());
    }

    #[tokio::test]
    async fn rotating_ipv6_sources_cannot_exceed_the_global_recycle_rate() {
        let attackers = 3 * MAX_RECYCLES_PER_INTERVAL as usize;
        let limit = SlotLimit::new_connections(attackers, attackers);
        let mut closers = Vec::new();
        for n in 0..attackers {
            let slot = limit
                .try_acquire(ip(&format!("192.0.2.{}", n % 250 + 1)))
                .unwrap();
            slot.activity().establish();
            let activity = slot.activity();
            closers.push(tokio::spawn(async move {
                activity.recycled().await;
                drop(slot);
            }));
        }
        let mut granted = Vec::new();
        for n in 0..attackers {
            // Every source is in its own /56.
            let src = ip(&format!("2001:db8:{n:x}:ff00::1"));
            if let Some(slot) = limit.acquire_or_recycle(src).await {
                granted.push(slot);
            }
        }
        // At most one window boundary can fall inside the test.
        assert!(!granted.is_empty());
        assert!(
            granted.len() <= 2 * MAX_RECYCLES_PER_INTERVAL as usize,
            "granted {}",
            granted.len()
        );
        // The same /56 counts as one client.
        assert_eq!(
            recycle_key(ip("2001:db8:0:1::1")),
            recycle_key(ip("2001:db8:0:ff::2"))
        );
        assert_ne!(
            recycle_key(ip("2001:db8:0:1::1")),
            recycle_key(ip("2001:db8:1:1::1"))
        );
    }

    #[tokio::test]
    async fn a_full_recycle_table_still_allows_a_legitimate_recycle() {
        let limit = SlotLimit::new_connections(1, 1);
        let victim = limit.try_acquire(ip("192.0.2.1")).unwrap();
        victim.activity().establish();
        {
            let mut limits = limit.recycles.lock().unwrap();
            let now = Instant::now();
            for n in 0..MAX_RECYCLE_CLIENTS {
                let key = ip(&format!("10.{}.{}.1", n / 250, n % 250));
                limits.per_client.insert(key, now);
            }
        }
        let activity = victim.activity();
        let closer = tokio::spawn(async move {
            activity.recycled().await;
            drop(victim);
        });
        assert!(limit.acquire_or_recycle(ip("198.51.100.9")).await.is_some());
        closer.await.unwrap();
        assert!(limit.recycles.lock().unwrap().per_client.len() <= MAX_RECYCLE_CLIENTS);
    }
}
