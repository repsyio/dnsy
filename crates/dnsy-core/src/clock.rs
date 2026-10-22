//! The one time source of the workspace: wall-clock Unix time, a monotonic instant and a
//! sleep, behind a trait so tests drive time by hand.

use std::future::Future;
use std::pin::Pin;
#[cfg(feature = "test-util")]
use std::sync::Arc;
#[cfg(feature = "test-util")]
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Source of time. Production code uses [`SystemClock`]; tests use `ManualClock` (feature
/// `test-util`).
pub trait Clock: Send + Sync + 'static {
    /// Unix seconds, 0 for a clock before 1970.
    fn unix_secs(&self) -> i64;
    /// Unix milliseconds, 0 for a clock before 1970.
    fn unix_millis(&self) -> i64;
    /// A monotonic instant.
    fn instant(&self) -> Instant;
    /// Completes after `d` on this clock.
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }

    fn unix_millis(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
    }

    fn instant(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// A clock that only moves when told to; clones share the same time. `sleep` completes at once.
#[cfg(feature = "test-util")]
#[derive(Debug, Clone)]
pub struct ManualClock(Arc<ManualInner>);

#[cfg(feature = "test-util")]
#[derive(Debug)]
struct ManualInner {
    /// Unix nanoseconds.
    nanos: AtomicI64,
    start_nanos: i64,
    base: Instant,
}

#[cfg(feature = "test-util")]
impl ManualClock {
    /// A clock at `unix_secs` seconds since the epoch.
    #[must_use]
    pub fn new(unix_secs: i64) -> ManualClock {
        let nanos = unix_secs.saturating_mul(1_000_000_000);
        ManualClock(Arc::new(ManualInner {
            nanos: AtomicI64::new(nanos),
            start_nanos: nanos,
            base: Instant::now(),
        }))
    }

    /// Jumps to `unix_secs` seconds since the epoch.
    pub fn set(&self, unix_secs: i64) {
        self.0
            .nanos
            .store(unix_secs.saturating_mul(1_000_000_000), Ordering::SeqCst);
    }

    /// Moves forward (or back, when negative) by `secs` seconds.
    pub fn advance(&self, secs: i64) {
        self.0
            .nanos
            .fetch_add(secs.saturating_mul(1_000_000_000), Ordering::SeqCst);
    }

    /// Moves forward by `d`.
    pub fn advance_by(&self, d: Duration) {
        self.0.nanos.fetch_add(
            i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
            Ordering::SeqCst,
        );
    }
}

#[cfg(feature = "test-util")]
impl Default for ManualClock {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(feature = "test-util")]
impl Clock for ManualClock {
    fn unix_secs(&self) -> i64 {
        self.0
            .nanos
            .load(Ordering::SeqCst)
            .div_euclid(1_000_000_000)
    }

    fn unix_millis(&self) -> i64 {
        self.0.nanos.load(Ordering::SeqCst).div_euclid(1_000_000)
    }

    fn instant(&self) -> Instant {
        let elapsed = self.0.nanos.load(Ordering::SeqCst) - self.0.start_nanos;
        if elapsed >= 0 {
            self.0.base + Duration::from_nanos(elapsed.unsigned_abs())
        } else {
            self.0.base - Duration::from_nanos(elapsed.unsigned_abs())
        }
    }

    fn sleep(&self, _: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(std::future::ready(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_plausible_and_monotonic() {
        let c = SystemClock;
        assert!(c.unix_secs() > 1_700_000_000);
        assert!(c.unix_millis() / 1000 >= c.unix_secs() - 1);
        let a = c.instant();
        assert!(c.instant() >= a);
    }

    #[tokio::test]
    async fn system_clock_sleeps() {
        let t = Instant::now();
        SystemClock.sleep(Duration::from_millis(10)).await;
        assert!(t.elapsed() >= Duration::from_millis(9));
    }

    #[cfg(feature = "test-util")]
    #[tokio::test]
    async fn manual_clock_moves_only_when_told_and_clones_share_time() {
        let c = ManualClock::new(1_000);
        let twin = c.clone();
        let t0 = c.instant();
        assert_eq!((c.unix_secs(), c.unix_millis()), (1_000, 1_000_000));
        twin.advance(5);
        assert_eq!(c.unix_secs(), 1_005);
        assert_eq!(c.instant() - t0, Duration::from_secs(5));
        c.advance_by(Duration::from_millis(1_500));
        assert_eq!(twin.unix_millis(), 1_006_500);
        assert_eq!(twin.unix_secs(), 1_006);
        c.set(10);
        assert_eq!(twin.unix_secs(), 10);
        assert!(c.instant() < t0);
        c.sleep(Duration::from_secs(3600)).await;
        assert_eq!(ManualClock::default().unix_secs(), 0);
    }
}
