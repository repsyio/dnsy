//! Shared state handed to every handler.

use std::sync::Arc;

use dnsy_auth::{BootstrapCode, SessionService, TokenService, UserService};
use dnsy_store::Store;

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
        }
    }

    /// Enable `POST /auth/bootstrap` with the code handed out by `UserService::start_bootstrap`.
    #[must_use]
    pub fn with_bootstrap(mut self, code: Arc<BootstrapCode>) -> ApiState {
        self.bootstrap = Some(code);
        self
    }
}
