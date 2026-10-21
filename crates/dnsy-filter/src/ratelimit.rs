use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use dnsy_core::Transport;
use dnsy_core::net::ClientKey;
pub use dnsy_core::net::client_key;

const SHARDS: usize = 16;
/// Buckets examined when a full shard needs room; the least recently used of them is evicted.
const EVICTION_SAMPLE: usize = 8;

/// Outcome of a rate-limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateVerdict {
    Allow,
    /// Over the limit on a stream/HTTP transport: answer REFUSED.
    Refuse,
    /// Over the limit on UDP: send nothing (a reply to a spoofed source would amplify).
    Drop,
    /// Over the limit on UDP, one query in `slip`: send a minimal truncated (TC=1) reply, no
    /// larger than the query, so a real client behind a spoofed address retries over TCP.
    Slip,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
    /// Over-limit UDP queries seen since the bucket was created; every `slip`-th one slips.
    over: u32,
}

/// One shard: a hash index over a dense slot vector, so a random bucket can be picked in O(1).
#[derive(Debug, Default)]
struct Shard {
    index: HashMap<ClientKey, usize>,
    slots: Vec<(ClientKey, Bucket)>,
}

impl Shard {
    fn remove(&mut self, pos: usize) {
        let (key, _) = self.slots.swap_remove(pos);
        self.index.remove(&key);
        if let Some((moved, _)) = self.slots.get(pos) {
            self.index.insert(*moved, pos);
        }
    }

    /// Evicts the least recently used of [`EVICTION_SAMPLE`] random buckets (all of them in a
    /// shard that small): constant work under the shard lock however full the shard is.
    fn evict_sampled(&mut self) {
        let len = self.slots.len();
        let last = |i: &usize| self.slots[*i].1.last;
        let victim = if len <= EVICTION_SAMPLE {
            (0..len).min_by_key(last)
        } else {
            (0..EVICTION_SAMPLE)
                .map(|_| rand::random_range(0..len))
                .min_by_key(last)
        };
        if let Some(pos) = victim {
            self.remove(pos);
        }
    }
}

/// Token-bucket limiter keyed by [`client_key`]. Each check refills and takes
/// a token under one shard lock, so concurrent queries cannot overspend.
/// Memory is bounded: at most `max_keys` buckets are held.
#[derive(Debug)]
pub struct RateLimiter {
    qps: f64,
    burst: f64,
    slip: u32,
    shard_cap: usize,
    hasher: RandomState,
    shards: Vec<Mutex<Shard>>,
}

impl RateLimiter {
    /// `qps` tokens per second per client, burst `2 * qps`. `qps == 0` disables
    /// limiting. `max_keys` bounds tracked clients (at least one per shard). No slip replies
    /// (see [`RateLimiter::with_slip`]).
    #[must_use]
    pub fn new(qps: u32, max_keys: usize) -> RateLimiter {
        RateLimiter {
            qps: f64::from(qps),
            burst: 2.0 * f64::from(qps),
            slip: 0,
            shard_cap: (max_keys / SHARDS).max(1),
            hasher: RandomState::new(),
            shards: (0..SHARDS).map(|_| Mutex::new(Shard::default())).collect(),
        }
    }

    /// Answers one over-limit UDP query in `slip` with [`RateVerdict::Slip`] instead of dropping
    /// it (`0` never does; `1` always does).
    #[must_use]
    pub fn with_slip(mut self, slip: u32) -> RateLimiter {
        self.slip = slip;
        self
    }

    /// The configured slip interval.
    #[must_use]
    pub fn slip(&self) -> u32 {
        self.slip
    }

    /// Take one token for `ip`.
    #[must_use]
    pub fn check(&self, ip: IpAddr, transport: Transport, now: Instant) -> RateVerdict {
        if self.qps <= 0.0 {
            return RateVerdict::Allow;
        }
        let key = client_key(ip);
        let shard = usize::try_from(self.hasher.hash_one(key) % SHARDS as u64).unwrap_or(0);
        let mut shard = self.shards[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pos = if let Some(&pos) = shard.index.get(&key) {
            pos
        } else {
            if shard.slots.len() >= self.shard_cap {
                shard.evict_sampled();
            }
            let pos = shard.slots.len();
            shard.slots.push((
                key,
                Bucket {
                    tokens: self.burst,
                    last: now,
                    over: 0,
                },
            ));
            shard.index.insert(key, pos);
            pos
        };
        let bucket = &mut shard.slots[pos].1;
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.qps).min(self.burst);
        bucket.last = bucket.last.max(now);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateVerdict::Allow
        } else if transport == Transport::Udp {
            bucket.over = bucket.over.wrapping_add(1);
            if self.slip > 0 && bucket.over.is_multiple_of(self.slip) {
                RateVerdict::Slip
            } else {
                RateVerdict::Drop
            }
        } else {
            RateVerdict::Refuse
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
                    .slots
                    .len()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use std::time::Duration;

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

    #[test]
    fn udp_over_limit_slips_one_in_n() {
        let rl = RateLimiter::new(1, 1000).with_slip(3);
        assert_eq!(rl.slip(), 3);
        let t = Instant::now();
        let client = ip("192.0.2.1");
        for _ in 0..2 {
            assert_eq!(rl.check(client, Transport::Udp, t), RateVerdict::Allow);
        }
        let verdicts: Vec<_> = (0..9)
            .map(|_| rl.check(client, Transport::Udp, t))
            .collect();
        let slips = verdicts.iter().filter(|v| **v == RateVerdict::Slip).count();
        assert_eq!(slips, 3, "{verdicts:?}");
        assert_eq!(verdicts[2], RateVerdict::Slip);
        assert!(
            verdicts
                .iter()
                .all(|v| matches!(v, RateVerdict::Slip | RateVerdict::Drop))
        );
        // Streams are still refused, and another client has its own count.
        assert_eq!(rl.check(client, Transport::Tcp, t), RateVerdict::Refuse);
        assert_eq!(
            rl.check(ip("192.0.2.2"), Transport::Udp, t),
            RateVerdict::Allow
        );
        // Slip 1 truncates every over-limit query; slip 0 (the default) never does.
        let every = RateLimiter::new(1, 1000).with_slip(1);
        let never = RateLimiter::new(1, 1000);
        for rl in [&every, &never] {
            for _ in 0..2 {
                let _ = rl.check(client, Transport::Udp, t);
            }
        }
        assert_eq!(every.check(client, Transport::Udp, t), RateVerdict::Slip);
        assert_eq!(never.check(client, Transport::Udp, t), RateVerdict::Drop);
    }

    #[test]
    fn eviction_stays_cheap_with_a_full_shard() {
        // 16 shards of 6250 buckets: the size the production limiter uses.
        let rl = RateLimiter::new(1, 100_000);
        let t = Instant::now();
        let spoofed = |i: u32| IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i));
        for i in 0..100_000 {
            let _ = rl.check(spoofed(i), Transport::Udp, t);
        }
        assert!(rl.tracked() > 90_000, "tracked {}", rl.tracked());
        let start = Instant::now();
        for i in 100_000..110_000 {
            let _ = rl.check(spoofed(i), Transport::Udp, t);
        }
        let took = start.elapsed();
        eprintln!("10k inserts into full shards: {took:?}");
        assert!(rl.tracked() <= 100_000);
        assert!(
            took < Duration::from_millis(250),
            "10k inserts took {took:?}"
        );
    }

    #[test]
    fn eviction_keeps_the_index_consistent() {
        let rl = RateLimiter::new(1, 32); // two buckets per shard: constant swap-removes
        let t = Instant::now();
        for i in 0..2_000u32 {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i % 97));
            let _ = rl.check(ip, Transport::Udp, t);
        }
        for shard in &rl.shards {
            let shard = shard.lock().unwrap();
            assert_eq!(shard.index.len(), shard.slots.len());
            for (key, pos) in &shard.index {
                assert_eq!(&shard.slots[*pos].0, key);
            }
        }
    }
}
