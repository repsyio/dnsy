//! SQLite handle and in-house migration runner.
//!
//! [`Store`] owns one writer connection and a small pool of read-only
//! connections (WAL mode, so reads proceed during a write). Migrations are
//! numbered SQL files in `migrations/`, registered in [`MIGRATIONS`] and applied
//! set-based in version order, each in its own transaction.

mod maintenance;
mod migrate;
mod store;

pub use maintenance::{Vacuumed, backup, check, vacuum};
pub use migrate::{MIGRATIONS, Migration, MigrationStatus};
pub use store::{Epoch, Store, StoreError, migration_status_at};
