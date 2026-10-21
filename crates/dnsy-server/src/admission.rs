//! Admission control shared by the listeners: one global slot pool per transport plus a
//! per-client cap keyed by [`dnsy_core::net::client_key`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use dnsy_core::net::{ClientKey, client_key};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Per-client counters. Entries exist only while a client holds at least one slot, so the map is
/// bounded by the global cap.
#[derive(Debug)]
struct ClientCounts {
    max: usize,
    held: Mutex<HashMap<ClientKey, usize>>,
}

/// A global cap with a per-client cap on top. Clone-free: share it behind an [`Arc`].
#[derive(Debug)]
pub(crate) struct SlotLimit {
    total: Arc<Semaphore>,
    clients: Arc<ClientCounts>,
}

/// Holds one global slot and one per-client slot; both are released on drop.
#[derive(Debug)]
pub(crate) struct Slot {
    _total: OwnedSemaphorePermit,
    clients: Arc<ClientCounts>,
    key: ClientKey,
}

impl SlotLimit {
    pub(crate) fn new(total: usize, per_client: usize) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::new(Semaphore::new(total)),
            clients: Arc::new(ClientCounts {
                max: per_client,
                held: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// A slot for `ip`, or `None` when the global pool or the client's own share is exhausted.
    pub(crate) fn try_acquire(&self, ip: IpAddr) -> Option<Slot> {
        let key = client_key(ip);
        let total = Arc::clone(&self.total).try_acquire_owned().ok()?;
        {
            let mut held = self
                .clients
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let count = held.entry(key).or_insert(0);
            if *count >= self.clients.max {
                return None;
            }
            *count += 1;
        }
        Some(Slot {
            _total: total,
            clients: Arc::clone(&self.clients),
            key,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
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
}
