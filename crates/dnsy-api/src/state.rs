//! Shared state handed to every handler.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnsy_auth::{BootstrapCode, ClientCertService, SessionService, TokenService, UserService};
use dnsy_engine::Engine;
use dnsy_filter::{RuleStore, SourceStore};
use dnsy_resolver::Cache;
use dnsy_resolver::groups::GroupStore;
use dnsy_store::Store;
use dnsy_zone::ZoneStore;
use tokio::sync::Semaphore;

use crate::routes::RuntimeSettings;

/// Reloads the `DoT` client-certificate fingerprint allowlist from the database, which bumps its
/// generation so open connections are re-checked. The binary builds it from the server's
/// allowlist (the API never depends on the server crate).
pub type CertReload =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync>;

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
    /// The running pipeline; ACL, upstream, blocklist and settings changes are applied to it
    /// live. Without it they are only persisted.
    pub engine: Option<Arc<Engine>>,
    pub rules: RuleStore,
    pub sources: SourceStore,
    pub groups: GroupStore,
    pub client_certs: ClientCertService,
    /// Reloads the mTLS allowlist after a client-certificate change.
    pub cert_reload: Option<CertReload>,
    /// The runtime-changeable subset of the configuration.
    pub settings: Arc<RuntimeSettings>,
    /// Serialises changes that rebuild and swap live policy.
    pub apply_lock: Arc<tokio::sync::Mutex<()>>,
}

/// Default cap on concurrent live-tail connections.
pub const MAX_LIVE_TAILS: usize = 16;

impl ApiState {
    #[must_use]
    pub fn new(store: Store) -> ApiState {
        ApiState {
            rules: RuleStore::new(store.clone()),
            sources: SourceStore::new(store.clone()),
            groups: GroupStore::new(store.clone()),
            client_certs: ClientCertService::new(store.clone()),
            engine: None,
            cert_reload: None,
            settings: Arc::new(RuntimeSettings::new(&dnsy_config::Config::default())),
            apply_lock: Arc::new(tokio::sync::Mutex::new(())),
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

    /// Apply policy changes to `engine` while it serves.
    #[must_use]
    pub fn with_engine(mut self, engine: Arc<Engine>) -> ApiState {
        self.engine = Some(engine);
        self
    }

    /// Start the settings routes from the loaded `config`.
    #[must_use]
    pub fn with_config(mut self, config: &dnsy_config::Config) -> ApiState {
        self.settings = Arc::new(RuntimeSettings::new(config));
        self
    }

    /// Call `reload` after every client-certificate change.
    #[must_use]
    pub fn with_cert_reload(mut self, reload: CertReload) -> ApiState {
        self.cert_reload = Some(reload);
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
