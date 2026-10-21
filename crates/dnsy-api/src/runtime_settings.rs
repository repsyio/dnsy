//! The running configuration as far as the API can change it.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use dnsy_config::Config;
use tokio::sync::watch;

const SECS_PER_DAY: u64 = 86_400;

/// The running configuration; only the settings below are exposed.
pub struct RuntimeSettings {
    config: Mutex<Config>,
    pub(crate) retention: watch::Sender<Duration>,
}

impl RuntimeSettings {
    #[must_use]
    pub fn new(config: &Config) -> RuntimeSettings {
        RuntimeSettings {
            retention: watch::Sender::new(retention_of(config.querylog.retention_days)),
            config: Mutex::new(config.clone()),
        }
    }

    pub(crate) fn snapshot(&self) -> Config {
        self.config
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn store(&self, config: Config) {
        *self.config.lock().unwrap_or_else(PoisonError::into_inner) = config;
    }

    pub(crate) fn per_client_qps(&self) -> u32 {
        self.snapshot().limits.per_client_qps
    }

    pub(crate) fn set_per_client_qps(&self, qps: u32) {
        self.config
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .limits
            .per_client_qps = qps;
    }

    /// How long the query log is kept; follows `querylog.retention_days` as it is patched. The
    /// retention task (`dnsy_observe::spawn_retention_watch`) reads it.
    #[must_use]
    pub fn retention_updates(&self) -> watch::Receiver<Duration> {
        self.retention.subscribe()
    }
}

pub(crate) fn retention_of(days: u32) -> Duration {
    Duration::from_secs(u64::from(days) * SECS_PER_DAY)
}
