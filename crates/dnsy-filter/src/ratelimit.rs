use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dnsy_core::Transport;
use dnsy_core::net::ClientKey;
pub use dnsy_core::net::client_key;

const SHARDS: usize = 16;

/// Outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateVerdict {
    Allow,
    /// Over the limit on a stream/HTTP transport: answer REFUSED.
    Refuse,
    /// Over the limit on UDP: send nothing (a reply to a spoofed source would amplify).
    Drop,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token-bucket limiter keyed by [`client_key`]. Each check refills and takes
/// a token under one shard lock, so concurrent queries cannot overspend.
/// Memory is bounded: at most `max_keys` buckets are held.
#[derive(Debug)]
pub struct RateLimiter {
    qps: f64,
    burst: f64,
    shard_cap: usize,
    hasher: RandomState,
    shards: Vec<Mutex<HashMap<ClientKey, Bucket>>>,
}

impl RateLimiter {
    /// `qps` tokens per second per client, burst `2 * qps`. `qps == 0` disables
    /// limiting. `max_keys` bounds tracked clients (at least one per shard).
    #[must_use]
    pub fn new(qps: u32, max_keys: usize) -> RateLimiter {
        RateLimiter {
            qps: f64::from(qps),
            burst: 2.0 * f64::from(qps),
            shard_cap: (max_keys / SHARDS).max(1),
            hasher: RandomState::new(),
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    /// Take one token for `ip`.
    #[must_use]
    pub fn check(&self, ip: IpAddr, transport: Transport, now: Instant) -> RateVerdict {
        if self.qps <= 0.0 {
            return RateVerdict::Allow;
        }
        let key = client_key(ip);
        let shard = usize::try_from(self.hasher.hash_one(key) % SHARDS as u64).unwrap_or(0);
        let mut map = self.shards[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !map.contains_key(&key) && map.len() >= self.shard_cap {
            self.make_room(&mut map, now);
        }
        let bucket = map.entry(key).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.qps).min(self.burst);
        bucket.last = bucket.last.max(now);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateVerdict::Allow
        } else if transport == Transport::Udp {
            RateVerdict::Drop
        } else {
            RateVerdict::Refuse
        }
    }

    /// Drop buckets that have refilled to full (equivalent to absent); if none,
    /// evict the least recently used one.
    fn make_room(&self, map: &mut HashMap<ClientKey, Bucket>, now: Instant) {
        let full_after = Duration::from_secs_f64(self.burst / self.qps);
        map.retain(|_, b| now.saturating_duration_since(b.last) < full_after);
        if map.len() >= self.shard_cap
            && let Some(oldest) = map.iter().min_by_key(|(_, b)| b.last).map(|(k, _)| *k)
        {
            map.remove(&oldest);
        }
    }

    /// Number of tracked clients.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn burst_is_twice_qps_then_limited() {
        let rl = RateLimiter::new(5, 1000);
        let t = Instant::now();
        for _ in 0..10 {
            assert_eq!(
                rl.check(ip("192.0.2.1"), Transport::Tcp, t),
                RateVerdict::Allow
            );
        }
        assert_eq!(
            rl.check(ip("192.0.2.1"), Transport::Tcp, t),
            RateVerdict::Refuse
        );
        assert_eq!(
            rl.check(ip("192.0.2.2"), Transport::Tcp, t),
            RateVerdict::Allow
        );
    }

    #[test]
    fn rate_limit_refills() {
        let rl = RateLimiter::new(10, 1000);
        let t = Instant::now();
        for _ in 0..20 {
            let _ = rl.check(ip("192.0.2.1"), Transport::Dot, t);
        }
        assert_eq!(
            rl.check(ip("192.0.2.1"), Transport::Dot, t),
            RateVerdict::Refuse
        );
        let later = t + Duration::from_millis(250); // 2.5 tokens
        assert_eq!(
            rl.check(ip("192.0.2.1"), Transport::Dot, later),
            RateVerdict::Allow
        );
        assert_eq!(
            rl.check(ip("192.0.2.1"), Transport::Dot, later),
            RateVerdict::Allow
        );
        assert_eq!(
            rl.check(ip("192.0.2.1"), Transport::Dot, later),
            RateVerdict::Refuse
        );
        // Never exceeds the burst however long the pause.
        let much_later = t + Duration::from_secs(3600);
        let allowed = (0..30)
            .filter(|_| rl.check(ip("192.0.2.1"), Transport::Doh, much_later) == RateVerdict::Allow)
            .count();
        assert_eq!(allowed, 20);
    }

    #[test]
    fn udp_over_limit_drops() {
        let rl = RateLimiter::new(1, 1000);
        let t = Instant::now();
        assert_eq!(
            rl.check(ip("192.0.2.1"), Transport::Udp, t),
            RateVerdict::Allow
        );
        assert_eq!(
            rl.check(ip("192.0.2.1"), Transport::Udp, t),
            RateVerdict::Allow
        );
        assert_eq!(
            rl.check(ip("192.0.2.1"), Transport::Udp, t),
            RateVerdict::Drop
        );
        assert_eq!(
            rl.check(ip("192.0.2.1"), Transport::Doh, t),
            RateVerdict::Refuse
        );
    }

    #[test]
    fn ipv6_clients_share_a_64_bucket() {
        let rl = RateLimiter::new(1, 1000);
        let t = Instant::now();
        assert_eq!(
            rl.check(ip("2001:db8:0:1::1"), Transport::Tcp, t),
            RateVerdict::Allow
        );
        assert_eq!(
            rl.check(ip("2001:db8:0:1::2"), Transport::Tcp, t),
            RateVerdict::Allow
        );
        assert_eq!(
            rl.check(ip("2001:db8:0:1:ffff::3"), Transport::Tcp, t),
            RateVerdict::Refuse
        );
        assert_eq!(
            rl.check(ip("2001:db8:0:2::1"), Transport::Tcp, t),
            RateVerdict::Allow
        );
    }

    #[test]
    fn zero_qps_disables() {
        let rl = RateLimiter::new(0, 10);
        let t = Instant::now();
        for _ in 0..100 {
            assert_eq!(
                rl.check(ip("192.0.2.1"), Transport::Udp, t),
                RateVerdict::Allow
            );
        }
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn keys_are_bounded() {
        let rl = RateLimiter::new(1, 32);
        let t = Instant::now();
        for i in 0..10_000u32 {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(i + 0x0a00_0000));
            let _ = rl.check(ip, Transport::Udp, t);
        }
        assert!(rl.tracked() <= 32, "tracked {}", rl.tracked());
    }

    #[test]
    fn concurrent_checks_never_overspend() {
        let rl = Arc::new(RateLimiter::new(50, 1000)); // burst 100
        let t = Instant::now();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let rl = Arc::clone(&rl);
                std::thread::spawn(move || {
                    (0..100)
                        .filter(|_| {
                            rl.check(ip("192.0.2.1"), Transport::Tcp, t) == RateVerdict::Allow
                        })
                        .count()
                })
            })
            .collect();
        let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 100);
    }
}
