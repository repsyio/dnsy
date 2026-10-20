//! Users, roles and first-admin bootstrap.
//!
//! [`UserService`] stores users in SQLite with argon2id password hashes (OWASP
//! parameters). [`BootstrapCode`] is the one-time, in-memory code that creates the
//! first admin when the database has no users.

mod bootstrap;
mod error;
mod password;
mod users;

pub use bootstrap::BootstrapCode;
pub use error::UserError;
pub use users::{User, UserService};
