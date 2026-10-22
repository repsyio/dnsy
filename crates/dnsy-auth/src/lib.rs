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
mod throttle;
mod tokens;
mod users;

pub use bootstrap::BootstrapCode;
pub use client_certs::{ClientCert, ClientCertService};
pub use error::{AuthError, UserError};
pub use sessions::{
    ABSOLUTE_TIMEOUT_SECS, IDLE_TIMEOUT_SECS, MAX_FAILURES, Session, SessionService,
    THROTTLE_WINDOW_SECS, USERNAME_BACKOFF_CAP_SECS, USERNAME_FREE_ATTEMPTS,
};
pub use throttle::{DEFAULT_MAX_TRACKED, FailureThrottle};
pub use tokens::{TokenMeta, TokenService, TokenVerifier};
pub use users::{User, UserService};
