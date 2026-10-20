//! Users, roles, API tokens, sessions and login throttling.
//!
//! [`UserService`] stores users in SQLite with argon2id password hashes (OWASP
//! parameters). [`BootstrapCode`] is the one-time, in-memory code that creates the
//! first admin when the database has no users. [`TokenService`] issues scoped API
//! tokens (stored as SHA-256 only, shown once). [`SessionService`] manages UI
//! sessions and throttles failed logins.

mod bootstrap;
mod client_certs;
mod error;
mod password;
mod sessions;
mod tokens;
mod users;

pub use bootstrap::BootstrapCode;
pub use client_certs::{ClientCert, ClientCertService};
pub use error::{AuthError, UserError};
pub use sessions::{
    ABSOLUTE_TIMEOUT_SECS, IDLE_TIMEOUT_SECS, MAX_FAILURES, Session, SessionService,
    THROTTLE_WINDOW_SECS,
};
pub use tokens::{TokenMeta, TokenService, TokenVerifier};
pub use users::{User, UserService};

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
