//! Shared state handed to every handler.

use dnsy_auth::{SessionService, TokenService, UserService};
use dnsy_store::Store;

/// Services the API needs. Cheap to clone. Later stories add their service handles here.
#[derive(Clone)]
pub struct ApiState {
    pub store: Store,
    pub users: UserService,
    pub tokens: TokenService,
    pub sessions: SessionService,
}

impl ApiState {
    #[must_use]
    pub fn new(store: Store) -> ApiState {
        ApiState {
            users: UserService::new(store.clone()),
            tokens: TokenService::new(store.clone()),
            sessions: SessionService::new(store.clone()),
            store,
        }
    }
}
