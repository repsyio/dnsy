//! Per-upstream health: passive failure counting, circuit-breaker backoff and EWMA latency.

use std::time::Duration;

/// Consecutive failures that eject an upstream.
pub const EJECT_AFTER_FAILURES: u32 = 3;
/// First ejection lasts this long.
pub const MIN_BACKOFF: Duration = Duration::from_secs(5);
/// Ejections never last longer than this.
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// Backoff for the `n`-th consecutive ejection (1-based): 5 s doubling up to 5 min.
pub(crate) fn backoff(n: u32) -> Duration {
    let shift = n.saturating_sub(1).min(16);
    (MIN_BACKOFF * (1u32 << shift)).min(MAX_BACKOFF)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Health {
    failures: u32,
    ejections: u32,
    /// Monotonic time at which the ejection ends and a probe may run.
    ejected_until: Option<Duration>,
    probing: bool,
    ewma_micros: Option<u64>,
}

impl Health {
    pub(crate) fn is_available(&self) -> bool {
        self.ejected_until.is_none()
    }

    pub(crate) fn failures(&self) -> u32 {
        self.failures
    }

    pub(crate) fn ewma(&self) -> Option<Duration> {
        self.ewma_micros.map(Duration::from_micros)
    }

    /// Ejected, backoff elapsed and no probe in flight.
    pub(crate) fn probe_due(&self, now: Duration) -> bool {
        self.ejected_until.is_some_and(|t| t <= now) && !self.probing
    }

    /// Claim the probe slot; returns false if there is nothing to probe.
    pub(crate) fn begin_probe(&mut self, now: Duration) -> bool {
        if self.probe_due(now) {
            self.probing = true;
            true
        } else {
            false
        }
    }

    /// Success (query or probe): re-admits the upstream and folds the latency into the EWMA
    /// (alpha 0.3).
    pub(crate) fn record_success(&mut self, latency: Duration) {
        let sample = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        self.ewma_micros = Some(match self.ewma_micros {
            None => sample,
            Some(old) => {
                (old.saturating_mul(7)
                    .saturating_add(sample.saturating_mul(3)))
                    / 10
            }
        });
        self.failures = 0;
        self.ejections = 0;
        self.ejected_until = None;
        self.probing = false;
    }

    /// Failure (query or probe). While an ejection is still running, stragglers are ignored.
    pub(crate) fn record_failure(&mut self, now: Duration) {
        match self.ejected_until {
            Some(until) if now < until => {}
            Some(_) => self.eject(now),
            None => {
                self.failures += 1;
                if self.failures >= EJECT_AFTER_FAILURES {
                    self.eject(now);
                }
            }
        }
    }

    fn eject(&mut self, now: Duration) {
        self.ejections = self.ejections.saturating_add(1);
        self.ejected_until = Some(now + backoff(self.ejections));
        self.probing = false;
    }
}
