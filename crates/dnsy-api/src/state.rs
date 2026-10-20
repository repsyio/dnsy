//! Shared state handed to every handler.

use std::sync::{Arc, Mutex};

use dnsy_auth::{BootstrapCode, SessionService, TokenService, UserService};
use dnsy_store::Store;
use dnsy_zone::ZoneStore;

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
}

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
}
