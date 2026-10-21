//! Failed-authentication throttle, keyed by client IP.
//!
//! Only rejected tokens count, and a blocked client gets 429 before any token is looked at, so
//! the answer never depends on whether a token exists.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tracked clients; beyond this, expired entries are purged and then the table is reset.
const MAX_TRACKED: usize = 10_000;

#[derive(Debug)]
pub(crate) struct Throttle {
    max_failures: u32,
    window: Duration,
    table: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Throttle {
    pub(crate) fn new(max_failures: u32, window: Duration) -> Self {
        Self {
            max_failures,
            window,
            table: Mutex::new(HashMap::new()),
        }
    }

    /// Seconds to wait if `ip` is currently blocked.
    pub(crate) fn blocked(&self, ip: IpAddr, now: Instant) -> Option<u64> {
        let table = self.table.lock().ok()?;
        let &(count, start) = table.get(&ip)?;
        let end = start + self.window;
        (count >= self.max_failures && now < end).then(|| (end - now).as_secs().max(1))
    }

    pub(crate) fn failure(&self, ip: IpAddr, now: Instant) {
        let Ok(mut table) = self.table.lock() else {
            return;
        };
        if table.len() >= MAX_TRACKED && !table.contains_key(&ip) {
            table.retain(|_, (_, start)| now < *start + self.window);
            if table.len() >= MAX_TRACKED {
                table.clear();
            }
        }
        let entry = table.entry(ip).or_insert((0, now));
        if now >= entry.1 + self.window {
            *entry = (0, now);
        }
        entry.0 = entry.0.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    #[test]
    fn blocks_after_max_failures_until_window_ends() {
        let t = Throttle::new(2, Duration::from_secs(60));
        let now = Instant::now();
        t.failure(IP, now);
        assert_eq!(t.blocked(IP, now), None);
        t.failure(IP, now);
        assert!(t.blocked(IP, now).is_some());
        assert_eq!(t.blocked(IP, now + Duration::from_secs(61)), None);
        // A new window starts counting from zero.
        t.failure(IP, now + Duration::from_secs(61));
        assert_eq!(t.blocked(IP, now + Duration::from_secs(61)), None);
    }

    #[test]
    fn other_clients_unaffected() {
        let t = Throttle::new(1, Duration::from_secs(60));
        let now = Instant::now();
        t.failure(IP, now);
        assert!(t.blocked(IP, now).is_some());
        assert_eq!(t.blocked("10.0.0.1".parse().unwrap(), now), None);
    }
}

#[cfg(test)]
mod eviction_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(n))
    }

    #[test]
    fn full_table_purges_expired_entries_and_keeps_live_ones() {
        let t = Throttle::new(1, Duration::from_secs(60));
        let start = Instant::now();
        for n in 0..u32::try_from(MAX_TRACKED).unwrap() {
            t.failure(ip(n), start);
        }
        // Every entry is expired by now, so a new client purges them all.
        let later = start + Duration::from_secs(61);
        t.failure(ip(u32::MAX), later);
        assert_eq!(t.table.lock().unwrap().len(), 1);
        assert!(t.blocked(ip(u32::MAX), later).is_some());
    }

    #[test]
    fn full_table_of_live_entries_is_reset_rather_than_grown() {
        let t = Throttle::new(1, Duration::from_secs(60));
        let now = Instant::now();
        for n in 0..u32::try_from(MAX_TRACKED).unwrap() {
            t.failure(ip(n), now);
        }
        t.failure(ip(u32::MAX), now);
        let table = t.table.lock().unwrap();
        assert_eq!(table.len(), 1, "memory stays bounded under an IP flood");
        assert!(table.contains_key(&ip(u32::MAX)));
    }

    #[test]
    fn failure_on_a_tracked_client_never_evicts_when_full() {
        let t = Throttle::new(2, Duration::from_secs(60));
        let now = Instant::now();
        for n in 0..u32::try_from(MAX_TRACKED).unwrap() {
            t.failure(ip(n), now);
        }
        t.failure(ip(0), now);
        assert_eq!(t.table.lock().unwrap().len(), MAX_TRACKED);
        assert!(t.blocked(ip(0), now).is_some());
    }
}
