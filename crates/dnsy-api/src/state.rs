//! Shared state handed to every handler.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use dnsy_auth::{BootstrapCode, ClientCertService, SessionService, TokenService, UserService};
use dnsy_core::{Clock, SystemClock};
use dnsy_core::{Role, UserId};
use dnsy_engine::{GroupsHandle, LivePolicy, Services};
use dnsy_filter::{ListManager, RuleStore, SourceStore};
use dnsy_resolver::Cache;
use dnsy_resolver::groups::GroupStore;
use dnsy_store::Store;
use dnsy_zone::{ZoneSigning, ZoneStore};

use crate::runtime_settings::RuntimeSettings;

/// Reloads the `DoT` client-certificate fingerprint allowlist from the database, which bumps its
/// generation so open connections are re-checked. The binary builds it from the server's
/// allowlist (the API never depends on the server crate).
pub type CertReload =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync>;

/// Users, tokens, sessions and client certificates.
#[derive(Clone)]
pub struct AuthServices {
    pub users: UserService,
    pub tokens: TokenService,
    pub sessions: SessionService,
    pub client_certs: ClientCertService,
    /// One-time first-admin code; `None` when users already exist.
    pub bootstrap: Option<Arc<BootstrapCode>>,
    /// Reloads the mTLS allowlist after a client-certificate change.
    pub cert_reload: Option<CertReload>,
    /// Mark auth cookies `Secure` (the API is served over TLS). Set from `ApiConfig`.
    pub cookie_secure: bool,
}

/// The persisted policy: ACL and rate-limit rules, blocklist sources, upstream groups.
#[derive(Clone)]
pub struct PolicyStores {
    pub rules: RuleStore,
    pub sources: SourceStore,
    pub groups: GroupStore,
}

/// The local zones and their signer; the zone routes answer 503 without them.
#[derive(Clone, Default)]
pub struct Zones {
    pub store: Option<Arc<ZoneStore>>,
    pub signing: Option<ZoneSigning>,
}

/// Query log, stats and live-tail settings.
#[derive(Clone)]
pub struct Observe {
    pub store: Store,
    /// Show client addresses truncated to /24 (IPv4) or /48 (IPv6) (`querylog.redact_client_ip`).
    pub redact_client_ip: bool,
    /// Concurrent live-tail (SSE) connections, capped in total and per principal.
    pub live_tail: Arc<LiveTails>,
    /// How often a live-tail connection looks for new rows.
    pub live_tail_poll: Duration,
}

/// Services the API needs. Cheap to clone.
#[derive(Clone)]
pub struct ApiState {
    pub auth: AuthServices,
    pub stores: PolicyStores,
    pub zones: Zones,
    pub observe: Observe,
    /// The resolver cache; `None` answers cache endpoints with 503.
    pub cache: Option<Arc<Cache>>,
    /// The blocklist manager; list routes fetch sources only with it.
    pub lists: Option<ListManager>,
    /// The live upstream groups the engine forwards through; the upstream routes read them.
    pub live_groups: GroupsHandle,
    /// The running pipeline's changeable policy; ACL, upstream, blocklist, settings and DNSSEC
    /// changes are applied through it live. Without it they are only persisted.
    pub policy: Option<Arc<dyn LivePolicy>>,
    /// The runtime-changeable subset of the configuration.
    pub settings: Arc<RuntimeSettings>,
    /// Serialises changes that rebuild and swap live policy.
    pub apply_lock: Arc<tokio::sync::Mutex<()>>,
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
            auth: AuthServices {
                users: UserService::new(store.clone()),
                tokens: TokenService::new(store.clone()),
                sessions: SessionService::new(store.clone()),
                client_certs: ClientCertService::new(store.clone()),
                bootstrap: None,
                cert_reload: None,
                cookie_secure: false,
            },
            stores: PolicyStores {
                rules: RuleStore::new(store.clone()),
                sources: SourceStore::new(store.clone()),
                groups: GroupStore::new(store.clone()),
            },
            zones: Zones::default(),
            observe: Observe {
                store,
                redact_client_ip: false,
                live_tail: Arc::new(LiveTails::new(
                    MAX_LIVE_TAILS,
                    MAX_LIVE_TAILS_PER_PRINCIPAL,
                    LIVE_TAIL_ADMIN_RESERVE,
                )),
                live_tail_poll: Duration::from_millis(500),
            },
            cache: None,
            lists: None,
            live_groups: Arc::new(ArcSwapOption::empty()),
            policy: None,
            settings: Arc::new(RuntimeSettings::new(&dnsy_config::Config::default())),
            apply_lock: Arc::new(tokio::sync::Mutex::new(())),
            clock: Arc::new(SystemClock),
        }
    }

    /// Enable `POST /auth/bootstrap` with the code handed out by `UserService::start_bootstrap`.
    #[must_use]
    pub fn with_bootstrap(mut self, code: Arc<BootstrapCode>) -> ApiState {
        self.auth.bootstrap = Some(code);
        self
    }

    /// Apply policy changes to the running engine (`policy`) while it serves.
    #[must_use]
    pub fn with_policy(mut self, policy: Arc<dyn LivePolicy>) -> ApiState {
        self.policy = Some(policy);
        self
    }

    /// Start the settings routes from the loaded `config`.
    #[must_use]
    pub fn with_config(mut self, config: &dnsy_config::Config) -> ApiState {
        self.settings = Arc::new(RuntimeSettings::new(config));
        self.auth.users = self.auth.users.with_login_limits(
            config.api.login_hash_per_client,
            std::time::Duration::from_millis(config.api.login_hash_wait_ms),
        );
        self
    }

    /// Call `reload` after every client-certificate change.
    #[must_use]
    pub fn with_cert_reload(mut self, reload: CertReload) -> ApiState {
        self.auth.cert_reload = Some(reload);
        self
    }

    /// Serve `GET/DELETE /cache` from this cache.
    #[must_use]
    pub fn with_cache(mut self, cache: Arc<Cache>) -> ApiState {
        self.cache = Some(cache);
        self
    }

    /// Truncate client addresses in query-log and stats responses.
    #[must_use]
    pub fn with_redact_client_ip(mut self, redact: bool) -> ApiState {
        self.observe.redact_client_ip = redact;
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
        self.observe.live_tail = Arc::new(LiveTails::new(total, per_principal, admin_reserve));
        self
    }

    /// Takes the cache, zones, signer, blocklist manager and live upstream groups from
    /// `services`, the same handles the engine was built with.
    #[must_use]
    pub fn with_services(mut self, services: &Services) -> ApiState {
        self.cache = Some(Arc::clone(&services.cache));
        self.zones.store.clone_from(&services.zones);
        self.zones.signing.clone_from(&services.signing);
        self.lists.clone_from(&services.lists);
        self.live_groups = Arc::clone(&services.groups);
        self
    }

    /// Use `clock` for negative-trust-anchor expiry instead of the system clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> ApiState {
        self.clock = clock;
        self
    }
}
