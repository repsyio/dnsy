//! Shared state handed to every handler.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnsy_auth::{BootstrapCode, SessionService, TokenService, UserService};
use dnsy_resolver::Cache;
use dnsy_store::Store;
use dnsy_zone::ZoneStore;
use tokio::sync::Semaphore;

/// Services the API needs. Cheap to clone. Later stories add their service handles here.
#[derive(Clone)]
pub struct ApiState {
    pub store: Store,
    pub users: UserService,
    pub tokens: TokenService,
    pub sessions: SessionService,
    /// One-time first-admin code; `None` when users already exist.
    pub bootstrap: Option<Arc<BootstrapCode>>,
    /// Mark auth cookies `Secure` (the API is served over TLS). Set from `ApiConfig`.
    pub cookie_secure: bool,
    /// The zones directory; zone routes answer 503 without it.
    pub zones: Option<Arc<ZoneStore>>,
    /// Serialises zone read-modify-write cycles.
    pub zone_lock: Arc<Mutex<()>>,
    /// The resolver cache; `None` answers cache endpoints with 503.
    pub cache: Option<Arc<Cache>>,
    /// Show client addresses truncated to /24 (IPv4) or /48 (IPv6) (`querylog.redact_client_ip`).
    pub redact_client_ip: bool,
    /// Concurrent live-tail (SSE) connections.
    pub live_tail: Arc<Semaphore>,
    /// How often a live-tail connection looks for new rows.
    pub live_tail_poll: Duration,
    /// Set by the engine while the system clock is before the build time (DNSSEC validation
    /// suspended); `/readyz` reports it as the `dnssec_clock_untrusted` warning.
    pub dnssec_clock_untrusted: Arc<AtomicBool>,
}

/// Default cap on concurrent live-tail connections.
pub const MAX_LIVE_TAILS: usize = 16;

impl ApiState {
    #[must_use]
    pub fn new(store: Store) -> ApiState {
        ApiState {
            users: UserService::new(store.clone()),
            tokens: TokenService::new(store.clone()),
            sessions: SessionService::new(store.clone()),
            store,
            bootstrap: None,
            cookie_secure: false,
            zones: None,
            zone_lock: Arc::new(Mutex::new(())),
            cache: None,
            redact_client_ip: false,
            live_tail: Arc::new(Semaphore::new(MAX_LIVE_TAILS)),
            live_tail_poll: Duration::from_millis(500),
            dnssec_clock_untrusted: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Enable `POST /auth/bootstrap` with the code handed out by `UserService::start_bootstrap`.
    #[must_use]
    pub fn with_bootstrap(mut self, code: Arc<BootstrapCode>) -> ApiState {
        self.bootstrap = Some(code);
        self
    }

    /// Serve the zone routes from `zones`.
    #[must_use]
    pub fn with_zones(mut self, zones: Arc<ZoneStore>) -> ApiState {
        self.zones = Some(zones);
        self
    }

    /// Share the engine's clock-sanity flag (`Engine::dnssec_clock_flag`) with `/readyz`.
    #[must_use]
    pub fn with_dnssec_clock_flag(mut self, flag: Arc<AtomicBool>) -> ApiState {
        self.dnssec_clock_untrusted = flag;
        self
    }
}

impl ApiState {
    /// Serve `GET/DELETE /cache` from this cache.
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<Cache>) -> ApiState {
        self.cache = Some(cache);
        self
    }

    /// Truncate client addresses in query-log and stats responses.
    #[must_use]
    pub fn with_redact_client_ip(mut self, redact: bool) -> ApiState {
        self.redact_client_ip = redact;
        self
    }

    /// Cap concurrent live-tail connections at `max`.
    #[must_use]
    pub fn with_max_live_tails(mut self, max: usize) -> ApiState {
        self.live_tail = Arc::new(Semaphore::new(max));
        self
    }
}
