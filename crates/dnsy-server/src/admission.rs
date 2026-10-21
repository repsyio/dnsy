//! Admission control shared by the listeners: one global slot pool per transport plus a
//! per-client cap keyed by [`dnsy_core::net::client_key`]. Connection pools can also recycle:
//! when the pool is full, an idle connection is closed to make room for a new one.
//!
//! Recycling model (see also the security chapter of the book). A connection is in one state:
//! handshaking (accepted, not established), established (handshake done, or first query sent for
//! plain TCP), authenticated (mTLS certificate or `DoH` token), busy (a request in flight) or
//! recycled (asked to close). Only a connection that is not authenticated, not busy, not already
//! asked, and either established or past [`ESTABLISH_GRACE`] can be chosen. Choosing and the
//! transitions to established, authenticated or busy happen under one lock, and each of those
//! transitions withdraws a pending request, so a stale request can never close a connection that
//! has since proved itself or started working. A recycle spends budget (per client and global)
//! only once a victim is chosen, and the budget is refunded when no slot is obtained.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
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
/// A client that recycled within this long is "recent": it may only use the first half of the
/// global budget, the second half is reserved for clients that did not.
const RECENT: Duration = Duration::from_secs(10);
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

#[derive(Debug)]
struct State {
    last: Instant,
    busy: usize,
    established: bool,
    authenticated: bool,
    /// The pool asked this connection to close.
    requested: bool,
}

/// What a connection task shares with its pool: its state and the wake-up asking it to close.
#[derive(Debug)]
pub struct Activity {
    created: Instant,
    state: Mutex<State>,
    wake: Notify,
}

/// Marks a request in flight on a connection; the connection counts as active until it drops.
#[derive(Debug)]
pub struct Busy(Arc<Activity>);

impl Activity {
    fn new() -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            created: now,
            state: Mutex::new(State {
                last: now,
                busy: 0,
                established: false,
                authenticated: false,
                requested: false,
            }),
            wake: Notify::new(),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records traffic on the connection.
    pub fn touch(&self) {
        self.state().last = Instant::now();
    }

    /// The connection finished its handshake (TLS for `DoT` and `DoH`) or sent its first complete
    /// query (plain TCP). Any pending request to close is withdrawn.
    pub fn establish(&self) {
        let mut state = self.state();
        state.established = true;
        state.requested = false;
    }

    /// The peer proved an identity (mTLS client certificate, `DoH` token). Such a connection is
    /// never recycled: a new connection has no identity yet and so ranks below it. Any pending
    /// request to close is withdrawn.
    pub fn mark_authenticated(&self) {
        let mut state = self.state();
        state.authenticated = true;
        state.requested = false;
    }

    /// A request started: the connection is not idle until the guard drops. Any pending request
    /// to close is withdrawn.
    #[must_use]
    pub fn begin(self: &Arc<Self>) -> Busy {
        {
            let mut state = self.state();
            state.busy += 1;
            state.last = Instant::now();
            state.requested = false;
        }
        Busy(Arc::clone(self))
    }

    /// Resolves once the pool asked this connection to close to make room (and has not withdrawn
    /// the request since).
    pub async fn recycled(&self) {
        loop {
            // Created before the check, so a notification in between is not lost.
            let woken = self.wake.notified();
            if self.state().requested {
                return;
            }
            woken.await;
        }
    }

    /// Eligible as a victim now? Returns its rank: connections that never got going first, then
    /// the one idle longest.
    fn rank(&self, grace: Duration) -> Option<(bool, Instant)> {
        let state = self.state();
        let eligible = !state.authenticated
            && state.busy == 0
            && !state.requested
            && (state.established || self.created.elapsed() >= grace);
        eligible.then_some((state.established, state.last))
    }

    /// Asks the connection to close if it is still eligible.
    fn request_close(&self, grace: Duration) -> bool {
        let mut state = self.state();
        let eligible = !state.authenticated
            && state.busy == 0
            && !state.requested
            && (state.established || self.created.elapsed() >= grace);
        if eligible {
            state.requested = true;
            drop(state);
            self.wake.notify_one();
        }
        eligible
    }

    /// Withdraws a request nobody is waiting for any more.
    fn cancel_close(&self) {
        self.state().requested = false;
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.busy -= 1;
        state.last = Instant::now();
    }
}

/// The live connections of a recycling pool.
#[derive(Debug, Default)]
struct Registry {
    next: AtomicU64,
    live: Mutex<HashMap<u64, Arc<Activity>>>,
}

impl Registry {
    fn live(&self) -> MutexGuard<'_, HashMap<u64, Arc<Activity>>> {
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
    /// Who recycled recently, and how many recycles this window.
    recycles: Mutex<RecycleLimits>,
    establish_grace: Duration,
}

/// Who recycled recently: per client (IPv6 by `/56`) and across all clients.
#[derive(Debug)]
struct RecycleLimits {
    per_client: HashMap<IpAddr, Instant>,
    window_start: Instant,
    window: u64,
    in_window: u32,
}

/// What a reserved recycle spent, to give back when no slot was obtained.
#[derive(Debug)]
struct Ticket {
    key: IpAddr,
    previous: Option<Instant>,
    window: u64,
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

    /// Like [`SlotLimit::new`] for connections: [`SlotLimit::acquire_or_recycle`] may close an
    /// idle connection when the pool is full.
    #[must_use]
    pub fn new_connections(total: usize, per_client: usize) -> Arc<Self> {
        Self::build(total, per_client, Some(Arc::new(Registry::default())))
    }

    #[cfg(test)]
    pub(crate) fn with_establish_grace(self: Arc<Self>, grace: Duration) -> Arc<Self> {
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
                window: 0,
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

    /// Like [`SlotLimit::try_acquire`], but when only the global pool is full, asks a victim (see
    /// the module docs) to close and waits briefly for its slot (the BIND `tcp-clients` model). A
    /// client that holds its whole share never evicts anyone, and nothing is evicted while every
    /// connection is serving a request or has proved an identity.
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
        let victim = self.choose_victim()?;
        let Some(ticket) = self.reserve(ip, Instant::now()) else {
            victim.cancel_close();
            return None;
        };
        let waited =
            tokio::time::timeout(RECYCLE_WAIT, Arc::clone(&self.total).acquire_owned()).await;
        let Ok(Ok(permit)) = waited else {
            victim.cancel_close();
            self.refund(&ticket);
            return None;
        };
        let slot = self.claim(ip, permit).ok();
        if slot.is_none() {
            self.refund(&ticket);
        }
        slot
    }

    /// Spends one recycle for `ip`'s client, if its own and the global budget allow. Clients that
    /// recycled within [`RECENT`] may only use the first half of the global budget.
    fn reserve(&self, ip: IpAddr, now: Instant) -> Option<Ticket> {
        let mut limits = self
            .recycles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = recycle_key(ip);
        let previous = limits.per_client.get(&key).copied();
        if previous.is_some_and(|t| now.saturating_duration_since(t) < RECYCLE_INTERVAL) {
            return None;
        }
        if now.saturating_duration_since(limits.window_start) >= RECYCLE_INTERVAL {
            limits.window_start = now;
            limits.window += 1;
            limits.in_window = 0;
        }
        let recent = previous.is_some_and(|t| now.saturating_duration_since(t) < RECENT);
        let budget = if recent {
            MAX_RECYCLES_PER_INTERVAL / 2
        } else {
            MAX_RECYCLES_PER_INTERVAL
        };
        if limits.in_window >= budget {
            return None;
        }
        limits.in_window += 1;
        if limits.per_client.len() >= MAX_RECYCLE_CLIENTS && previous.is_none() {
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
        Some(Ticket {
            key,
            previous,
            window: limits.window,
        })
    }

    /// Gives back what [`SlotLimit::reserve`] spent.
    fn refund(&self, ticket: &Ticket) {
        let mut limits = self
            .recycles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if limits.window == ticket.window {
            limits.in_window = limits.in_window.saturating_sub(1);
        }
        match ticket.previous {
            Some(t) => {
                limits.per_client.insert(ticket.key, t);
            }
            None => {
                limits.per_client.remove(&ticket.key);
            }
        }
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

    /// Asks one eligible connection to close and returns it; `None` when there is none.
    /// Connections that never got going (past [`ESTABLISH_GRACE`]) go first, so silent ones cannot
    /// pin slots; younger unestablished ones are left alone (they may be mid-handshake).
    fn choose_victim(&self) -> Option<Arc<Activity>> {
        let registry = self.registry.as_ref()?;
        let mut candidates: Vec<_> = registry
            .live()
            .values()
            .filter_map(|a| {
                a.rank(self.establish_grace)
                    .map(|rank| (rank, Arc::clone(a)))
            })
            .collect();
        candidates.sort_by_key(|(rank, _)| *rank);
        candidates
            .into_iter()
            .map(|(_, a)| a)
            .find(|a| a.request_close(self.establish_grace))
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

    fn requested(a: &Activity) -> bool {
        a.state().requested
    }

    #[tokio::test]
    async fn a_stale_request_cannot_close_a_connection_that_then_authenticates() {
        let limit = SlotLimit::new_connections(1, 1).with_establish_grace(Duration::ZERO);
        let slot = limit.try_acquire(ip("192.0.2.1")).unwrap();
        let activity = slot.activity();
        // A newcomer picks the silent connection while it is still handshaking ...
        let victim = limit
            .choose_victim()
            .expect("a handshaking connection past grace");
        assert!(requested(&activity));
        // ... but the handshake completes with a client certificate first.
        activity.mark_authenticated();
        assert!(!requested(&activity), "the request was withdrawn");
        assert!(
            tokio::time::timeout(Duration::from_millis(30), activity.recycled())
                .await
                .is_err(),
            "no stale wake-up closes it"
        );
        drop(victim);
        // Same for a connection that starts a request, and one that merely establishes.
        let other = SlotLimit::new_connections(1, 1).with_establish_grace(Duration::ZERO);
        let slot = other.try_acquire(ip("192.0.2.1")).unwrap();
        let activity = slot.activity();
        other.choose_victim().unwrap();
        let busy = activity.begin();
        assert!(!requested(&activity));
        drop(busy);
        other.choose_victim().unwrap();
        activity.establish();
        assert!(!requested(&activity));
    }

    #[tokio::test]
    async fn recycle_budget_is_refunded_when_no_slot_is_obtained() {
        let limit = SlotLimit::new_connections(1, 1);
        // An established victim that ignores the request: its slot never frees.
        let stubborn = limit.try_acquire(ip("192.0.2.1")).unwrap();
        stubborn.activity().establish();
        let newcomer = ip("198.51.100.1");
        assert!(limit.acquire_or_recycle(newcomer).await.is_none());
        {
            let limits = limit.recycles.lock().unwrap();
            assert_eq!(limits.in_window, 0, "the global budget was given back");
            assert!(
                limits.per_client.is_empty(),
                "the client's turn was given back"
            );
        }
        assert!(
            !requested(&stubborn.activity()),
            "the unanswered request was withdrawn"
        );
        // The same client may try again straight away.
        assert!(limit.choose_victim().is_some());
    }

    #[tokio::test]
    async fn recycle_budget_is_not_spent_without_a_victim() {
        let limit = SlotLimit::new_connections(2, 2);
        let authenticated = limit.try_acquire(ip("192.0.2.1")).unwrap();
        authenticated.activity().establish();
        authenticated.activity().mark_authenticated();
        let working = limit.try_acquire(ip("192.0.2.2")).unwrap();
        working.activity().establish();
        let _busy = working.activity().begin();
        for n in 1..=20 {
            let newcomer = ip(&format!("198.51.100.{n}"));
            assert!(limit.acquire_or_recycle(newcomer).await.is_none());
        }
        let limits = limit.recycles.lock().unwrap();
        assert_eq!((limits.in_window, limits.per_client.len()), (0, 0));
    }

    #[test]
    fn half_the_global_budget_is_reserved_for_clients_that_did_not_recycle_recently() {
        let limit = SlotLimit::new_connections(1, 1);
        let now = Instant::now();
        let half = MAX_RECYCLES_PER_INTERVAL / 2;
        let recent = |n: u32| ip(&format!("10.0.{}.{}", n / 200, n % 200 + 1));
        // 100 prefixes that each recycled 5 s ago (recent, but past their own 1 s wait).
        {
            let mut limits = limit.recycles.lock().unwrap();
            for n in 0..100 {
                limits.per_client.insert(
                    recycle_key(recent(n)),
                    now.checked_sub(Duration::from_secs(5)).unwrap(),
                );
            }
        }
        let granted = (0..100)
            .filter(|n| limit.reserve(recent(*n), now).is_some())
            .count();
        assert_eq!(
            granted, half as usize,
            "recent clients stop at half the budget"
        );
        // Fresh clients can still use the other half, and then nobody can.
        let fresh = (0..100)
            .filter(|n| {
                limit
                    .reserve(ip(&format!("203.0.113.{}", n + 1)), now)
                    .is_some()
            })
            .count();
        assert_eq!(fresh, (MAX_RECYCLES_PER_INTERVAL - half) as usize);
        // A new window starts from zero again.
        let later = now + Duration::from_secs(2);
        assert!(limit.reserve(ip("192.0.2.77"), later).is_some());
    }

    /// Every connection state against the victim rule: `(name, grace, setup, eligible)`.
    #[tokio::test]
    async fn threat_table_of_connection_states() {
        type Setup = fn(&Arc<Activity>) -> Option<Busy>;
        let rows: [(&str, Duration, Setup, bool); 7] = [
            (
                "handshaking, young",
                Duration::from_secs(60),
                |_| None,
                false,
            ),
            ("handshaking, past grace", Duration::ZERO, |_| None, true),
            (
                "established",
                Duration::from_secs(60),
                |a| {
                    a.establish();
                    None
                },
                true,
            ),
            (
                "authenticated",
                Duration::ZERO,
                |a| {
                    a.establish();
                    a.mark_authenticated();
                    None
                },
                false,
            ),
            (
                "authenticated before establish",
                Duration::ZERO,
                |a| {
                    a.mark_authenticated();
                    None
                },
                false,
            ),
            (
                "busy",
                Duration::ZERO,
                |a| {
                    a.establish();
                    Some(a.begin())
                },
                false,
            ),
            (
                "already asked to close",
                Duration::ZERO,
                |a| {
                    a.establish();
                    a.state().requested = true;
                    None
                },
                false,
            ),
        ];
        for (name, grace, setup, eligible) in rows {
            let limit = SlotLimit::new_connections(1, 1).with_establish_grace(grace);
            let slot = limit.try_acquire(ip("192.0.2.1")).unwrap();
            let guard = setup(&slot.activity());
            assert_eq!(limit.choose_victim().is_some(), eligible, "{name}");
            drop(guard);
        }
    }

    /// Randomised actors (many prefixes, repeats, one that is at its cap) against a full pool of
    /// connections in every state: nothing protected is ever asked to close, every recycle frees
    /// exactly one slot, and nothing leaks.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one scenario reads best top to bottom"
    )]
    async fn recycling_invariants_hold_under_random_actors() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};
        const CAP: usize = 24;
        let limit = SlotLimit::new_connections(CAP, 3);
        let fired = Arc::new(AtomicUsize::new(0));
        let protected_fired = Arc::new(AtomicBool::new(false));
        let mut guards = Vec::new();
        let mut protected = Vec::new();
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let watch = |slot: Slot, honour: Arc<AtomicUsize>, bad: Arc<AtomicBool>, protect: bool| {
            let activity = slot.activity();
            tokio::spawn(async move {
                activity.recycled().await;
                if protect {
                    bad.store(true, Ordering::SeqCst);
                }
                honour.fetch_add(1, Ordering::SeqCst);
                drop(slot);
            })
        };
        let mut watchers = Vec::new();
        for n in 0..CAP {
            let slot = limit
                .try_acquire(ip(&format!("192.0.2.{}", n + 1)))
                .unwrap();
            let activity = slot.activity();
            let kind = next() % 5;
            let protect = match kind {
                0 => false, // handshaking, young: not eligible but not "protected" either
                1 | 2 => {
                    activity.establish();
                    false
                }
                3 => {
                    activity.establish();
                    activity.mark_authenticated();
                    true
                }
                _ => {
                    activity.establish();
                    guards.push(activity.begin());
                    true
                }
            };
            if protect {
                protected.push(Arc::clone(&activity));
            }
            let unestablished = kind == 0;
            watchers.push(watch(
                slot,
                Arc::clone(&fired),
                Arc::clone(&protected_fired),
                protect || unestablished,
            ));
        }
        let mut granted = 0_usize;
        for step in 0..150_u64 {
            let r = next();
            let actor = match r % 4 {
                0 => ip(&format!("2001:db8:{:x}:{:x}::{:x}", step, r % 7, r % 99)), // many prefixes
                1 => ip(&format!("198.51.100.{}", r % 40 + 1)),                     // repeats
                2 => ip("2001:db8:ffff::1"), // one /56 hammering
                _ => ip(&format!("203.0.113.{}", r % 250 + 1)),
            };
            if let Some(slot) = limit.acquire_or_recycle(actor).await {
                granted += 1;
                slot.activity().establish();
                // Honoured and recyclable again later.
                watchers.push(watch(
                    slot,
                    Arc::clone(&fired),
                    Arc::clone(&protected_fired),
                    false,
                ));
            }
            assert!(limit.total.available_permits() <= CAP);
            {
                let limits = limit.recycles.lock().unwrap();
                assert!(limits.in_window <= MAX_RECYCLES_PER_INTERVAL);
                assert!(limits.per_client.len() <= MAX_RECYCLE_CLIENTS);
            }
        }
        tokio::task::yield_now().await;
        assert!(
            !protected_fired.load(Ordering::SeqCst),
            "a protected connection was closed"
        );
        for a in &protected {
            assert!(!requested(a));
        }
        // The pool was always full, so every grant needed exactly one connection to close.
        assert_eq!(granted, fired.load(Ordering::SeqCst));
        assert!(granted > 0 && granted <= 2 * MAX_RECYCLES_PER_INTERVAL as usize);
        drop(guards);
        for w in watchers {
            w.abort();
            let _ = w.await;
        }
        assert_eq!(limit.total.available_permits(), CAP, "no slot leaked");
        assert!(limit.clients.held.lock().unwrap().is_empty());
        assert!(limit.registry.as_ref().unwrap().live().is_empty());
        assert_eq!(limit.pending.available_permits(), MAX_PENDING_RECYCLES);
    }
}
