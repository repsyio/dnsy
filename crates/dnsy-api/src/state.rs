//! Shared state handed to every handler.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnsy_auth::{BootstrapCode, ClientCertService, SessionService, TokenService, UserService};
use dnsy_core::{Role, UserId};
use dnsy_dnssec::{Clock, SystemClock};
use dnsy_engine::Engine;
use dnsy_filter::{RuleStore, SourceStore};
use dnsy_resolver::Cache;
use dnsy_resolver::groups::GroupStore;
use dnsy_store::Store;
use dnsy_zone::{ZoneSigning, ZoneStore};

use crate::routes::RuntimeSettings;
use crate::validation::ValidationControl;

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
    /// Concurrent live-tail (SSE) connections, capped in total and per principal.
    pub live_tail: Arc<LiveTails>,
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
    /// Zone signing and its key store; the DNSSEC zone routes answer 503 without it.
    pub signing: Option<ZoneSigning>,
    /// Run-time validation settings (the engine); the settings routes answer 503 without it.
    pub validation: Option<Arc<dyn ValidationControl>>,
    /// Time source for negative-trust-anchor expiry; tests inject a manual clock.
    pub clock: Arc<dyn Clock>,
}

/// Default cap on concurrent live-tail connections.
pub const MAX_LIVE_TAILS: usize = 16;
/// Default cap on live-tail connections per user.
pub const MAX_LIVE_TAILS_PER_PRINCIPAL: usize = 4;
/// Live-tail slots only admins may take, so a flood of operator streams cannot lock them out.
pub const LIVE_TAIL_ADMIN_RESERVE: usize = 2;

/// Counts open live-tail streams: a total cap, a cap per user and slots kept for admins.
#[derive(Debug)]
pub struct LiveTails {
    total: usize,
    per_principal: usize,
    admin_reserve: usize,
    open: Mutex<LiveTailCounts>,
}

#[derive(Debug, Default)]
struct LiveTailCounts {
    total: usize,
    per_user: HashMap<UserId, usize>,
}

/// One open live-tail stream; dropping it frees the slot.
#[derive(Debug)]
pub struct LiveTailPermit {
    tails: Arc<LiveTails>,
    user: UserId,
}

impl LiveTails {
    #[must_use]
    pub fn new(total: usize, per_principal: usize, admin_reserve: usize) -> LiveTails {
        LiveTails {
            total,
            per_principal,
            admin_reserve,
            open: Mutex::new(LiveTailCounts::default()),
        }
    }

    /// Takes a slot for `user`, or `None` when the user, or the shared pool for their role, is
    /// full.
    #[must_use]
    pub fn acquire(self: &Arc<Self>, user: UserId, role: Role) -> Option<LiveTailPermit> {
        let limit = if role == Role::Admin {
            self.total
        } else {
            self.total.saturating_sub(self.admin_reserve)
        };
        let mut open = self
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mine = open.per_user.get(&user).copied().unwrap_or(0);
        if open.total >= limit || mine >= self.per_principal {
            return None;
        }
        open.total += 1;
        open.per_user.insert(user, mine + 1);
        Some(LiveTailPermit {
            tails: Arc::clone(self),
            user,
        })
    }
}

impl Drop for LiveTailPermit {
    fn drop(&mut self) {
        let mut open = self
            .tails
            .open
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        open.total -= 1;
        if let Some(n) = open.per_user.get_mut(&self.user) {
            *n -= 1;
            if *n == 0 {
                open.per_user.remove(&self.user);
            }
        }
    }
}

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
            live_tail: Arc::new(LiveTails::new(
                MAX_LIVE_TAILS,
                MAX_LIVE_TAILS_PER_PRINCIPAL,
                LIVE_TAIL_ADMIN_RESERVE,
            )),
            live_tail_poll: Duration::from_millis(500),
            dnssec_clock_untrusted: Arc::new(AtomicBool::new(false)),
            signing: None,
            validation: None,
            clock: Arc::new(SystemClock),
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
        self.users = self.users.with_login_limits(
            config.api.login_hash_per_client,
            std::time::Duration::from_millis(config.api.login_hash_wait_ms),
        );
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

    /// Cap live-tail connections: `total` overall, `per_principal` per user, `admin_reserve`
    /// of the total only for admins.
    #[must_use]
    pub fn with_live_tail_limits(
        mut self,
        total: usize,
        per_principal: usize,
        admin_reserve: usize,
    ) -> ApiState {
        self.live_tail = Arc::new(LiveTails::new(total, per_principal, admin_reserve));
        self
    }

    /// Serve the DNSSEC zone routes from this signer.
    #[must_use]
    pub fn with_signing(mut self, signing: ZoneSigning) -> ApiState {
        self.signing = Some(signing);
        self
    }

    /// Use `clock` for negative-trust-anchor expiry instead of the system clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> ApiState {
        self.clock = clock;
        self
    }

    /// Serve `/settings/dnssec` from this validation control (the engine).
    #[must_use]
    pub fn with_validation(mut self, validation: Arc<dyn ValidationControl>) -> ApiState {
        self.validation = Some(validation);
        self
    }
}
