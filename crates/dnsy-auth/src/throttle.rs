//! In-memory failed-authentication throttle shared by the DoH token check.
//!
//! Entries are keyed by [`ClientKey`] (IPv4 `/32`, IPv6 `/64`) and an optional secondary key,
//! counted in a fixed window and held in a bounded, sharded table. A client that reached the
//! failure limit is never evicted to make room, so flooding the table with other clients cannot
//! unblock it.

use std::collections::HashMap;
use std::hash::{BuildHasher as _, RandomState};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dnsy_core::net::ClientKey;

const SHARDS: usize = 16;
/// Default bound on tracked keys across all shards.
pub const DEFAULT_MAX_TRACKED: usize = 10_000;

type Key = (ClientKey, Option<Box<str>>);

#[derive(Debug, Clone, Copy)]
struct Entry {
    count: u32,
    start: Instant,
}

/// Bounded, sharded, fixed-window failure counter.
#[derive(Debug)]
pub struct FailureThrottle {
    max_failures: u32,
    window: Duration,
    shard_capacity: usize,
    hasher: RandomState,
    shards: [Mutex<HashMap<Key, Entry>>; SHARDS],
}

impl FailureThrottle {
    /// Blocks a key after `max_failures` failures inside `window`, tracking at most
    /// `max_tracked` keys.
    #[must_use]
    pub fn new(max_failures: u32, window: Duration, max_tracked: usize) -> FailureThrottle {
        FailureThrottle {
            max_failures,
            window,
            shard_capacity: max_tracked.div_ceil(SHARDS).max(1),
            hasher: RandomState::new(),
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    fn shard(&self, key: &Key) -> &Mutex<HashMap<Key, Entry>> {
        let index = usize::try_from(self.hasher.hash_one(key) % SHARDS as u64).unwrap_or(0);
        &self.shards[index]
    }

    fn is_blocked(&self, entry: &Entry, now: Instant) -> bool {
        entry.count >= self.max_failures && now < entry.start + self.window
    }

    /// Seconds to wait if the key is currently blocked.
    #[must_use]
    pub fn blocked(&self, client: ClientKey, secondary: Option<&str>, now: Instant) -> Option<u64> {
        let key = (client, secondary.map(Box::from));
        let table = self.shard(&key).lock().ok()?;
        let entry = table.get(&key)?;
        self.is_blocked(entry, now)
            .then(|| (entry.start + self.window - now).as_secs().max(1))
    }

    /// Counts one failure. When the shard is full of live entries, a key that is not yet tracked
    /// displaces an unblocked entry; if every entry is blocked the new failure is not recorded.
    pub fn failure(&self, client: ClientKey, secondary: Option<&str>, now: Instant) {
        let key = (client, secondary.map(Box::from));
        let Ok(mut table) = self.shard(&key).lock() else {
            return;
        };
        if !table.contains_key(&key) && table.len() >= self.shard_capacity {
            table.retain(|_, e| now < e.start + self.window);
            if table.len() >= self.shard_capacity {
                let victim = table
                    .iter()
                    .filter(|(_, e)| e.count < self.max_failures)
                    .min_by_key(|(_, e)| e.start)
                    .map(|(k, _)| k.clone());
                match victim {
                    Some(k) => {
                        table.remove(&k);
                    }
                    None => return,
                }
            }
        }
        let entry = table.entry(key).or_insert(Entry {
            count: 0,
            start: now,
        });
        if now >= entry.start + self.window {
            *entry = Entry {
                count: 0,
                start: now,
            };
        }
        entry.count = entry.count.saturating_add(1);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use dnsy_core::net::client_key;

    use super::*;

    fn key(s: &str) -> ClientKey {
        client_key(s.parse().unwrap())
    }

    fn v4(n: u32) -> ClientKey {
        client_key(IpAddr::V4(Ipv4Addr::from(n)))
    }

    #[test]
    fn blocks_after_max_failures_until_window_ends() {
        let t = FailureThrottle::new(2, Duration::from_secs(60), 100);
        let (ip, now) = (key("127.0.0.1"), Instant::now());
        t.failure(ip, None, now);
        assert_eq!(t.blocked(ip, None, now), None);
        t.failure(ip, None, now);
        assert!(t.blocked(ip, None, now).is_some());
        assert_eq!(t.blocked(ip, None, now + Duration::from_secs(61)), None);
        // A new window starts counting from zero.
        t.failure(ip, None, now + Duration::from_secs(61));
        assert_eq!(t.blocked(ip, None, now + Duration::from_secs(61)), None);
    }

    #[test]
    fn other_clients_and_secondary_keys_are_independent() {
        let t = FailureThrottle::new(1, Duration::from_secs(60), 100);
        let now = Instant::now();
        t.failure(key("127.0.0.1"), Some("alice"), now);
        assert!(t.blocked(key("127.0.0.1"), Some("alice"), now).is_some());
        assert_eq!(t.blocked(key("127.0.0.1"), Some("bob"), now), None);
        assert_eq!(t.blocked(key("127.0.0.1"), None, now), None);
        assert_eq!(t.blocked(key("10.0.0.1"), Some("alice"), now), None);
    }

    #[test]
    fn throttle_counts_ipv6_rotation_within_slash64() {
        let t = FailureThrottle::new(3, Duration::from_secs(60), 100);
        let now = Instant::now();
        for host in 1..=3 {
            t.failure(key(&format!("2001:db8:0:1::{host:x}")), None, now);
        }
        // Another address of the same /64 is blocked; a different /64 is not.
        assert!(t.blocked(key("2001:db8:0:1:aaaa::9"), None, now).is_some());
        assert_eq!(t.blocked(key("2001:db8:0:2::1"), None, now), None);
    }

    #[test]
    fn full_table_purges_expired_entries() {
        let t = FailureThrottle::new(1, Duration::from_secs(60), 32);
        let start = Instant::now();
        for n in 0..64 {
            t.failure(v4(n), None, start);
        }
        let later = start + Duration::from_secs(61);
        t.failure(v4(1000), None, later);
        assert!(t.blocked(v4(1000), None, later).is_some());
        assert!(t.len() <= 33);
    }

    #[test]
    fn doh_throttle_saturation_keeps_blocked_ip_blocked() {
        let t = FailureThrottle::new(3, Duration::from_secs(60), 32);
        let now = Instant::now();
        let attacker = key("192.0.2.1");
        for _ in 0..3 {
            t.failure(attacker, None, now);
        }
        assert!(t.blocked(attacker, None, now).is_some());
        // A flood of other clients far beyond the table size must not push the attacker out.
        for n in 0..10_000 {
            t.failure(v4(0x0a00_0000 + n), None, now);
        }
        assert!(t.blocked(attacker, None, now).is_some());
        assert!(t.len() <= 32 + SHARDS, "table stays bounded");
    }

    #[test]
    fn table_of_blocked_entries_ignores_new_clients_instead_of_growing() {
        let t = FailureThrottle::new(1, Duration::from_secs(60), 16);
        let now = Instant::now();
        for n in 0..1000 {
            t.failure(v4(n), None, now);
        }
        assert!(t.len() <= 16);
        let tracked = (0..1000).filter(|&n| t.blocked(v4(n), None, now).is_some());
        assert_eq!(tracked.count(), t.len(), "every survivor is still blocked");
    }
}
