//! dnsy: the binary's command line and wiring.
//!
//! [`run`] dispatches a parsed [`cli::Cli`]. `serve` assembles config -> store -> services ->
//! [`dnsy_engine::EngineBuilder::from_config`] -> listeners and API; the other subcommands are
//! offline administration against the same database and zones directory, except `cache flush`,
//! which talks to a running server's API.

mod admin;
mod cacheflush;
pub mod cli;
mod http;
pub mod logging;
mod serve;

use std::fmt;
use std::path::Path;

use dnsy_config::Config;
use dnsy_store::Store;

use crate::cli::{Cli, Command, ConfigCommand};

/// Unix time this binary was built; the DNSSEC clock-sanity check (DNSY-37) treats a system
/// clock earlier than this as untrusted.
#[must_use]
pub fn build_time() -> u64 {
    env!("DNSY_BUILD_TIME").parse().unwrap_or(0)
}

/// A command failure, printed as `dnsy: <message>`.
#[derive(Debug)]
pub struct Error(String);

impl Error {
    #[must_use]
    pub fn msg(message: impl Into<String>) -> Error {
        Error(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<E: std::error::Error> From<E> for Error {
    fn from(e: E) -> Error {
        Error(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Runs one command.
///
/// # Errors
/// Whatever the command reports; the caller prints it and exits non-zero.
pub async fn run(cli: Cli) -> Result<()> {
    let mut out = std::io::stdout().lock();
    match cli.command {
        Command::Version => {
            use std::io::Write as _;
            writeln!(
                out,
                "dnsy {} (built {})",
                env!("CARGO_PKG_VERSION"),
                build_time()
            )?;
            Ok(())
        }
        Command::Openapi => admin::openapi(&mut out),
        Command::Config(ConfigCommand::Check) => admin::config_check(&cli.config, &mut out),
        Command::Migrate { status } => {
            let config = load_config(&cli.config)?;
            admin::migrate(&config, status, &mut out)
        }
        Command::Serve(args) => {
            let config = load_config(&cli.config)?;
            logging::init(config.logging.level, config.logging.format);
            serve::serve(config, &cli.config, args).await
        }
        Command::User(cmd) => admin::user(&load_quiet(&cli.config)?, cmd, &mut out).await,
        Command::Token(cmd) => admin::token(&load_quiet(&cli.config)?, cmd, &mut out).await,
        Command::Zone(cmd) => admin::zone(&load_quiet(&cli.config)?, cmd, &mut out).await,
        Command::Dnssec(cmd) => admin::dnssec(&load_quiet(&cli.config)?, cmd, &mut out).await,
        Command::Cache(cmd) => cacheflush::run(&load_quiet(&cli.config)?, cmd, &mut out).await,
    }
}

/// Loads and validates the configuration (with `DNSY_*` environment overrides).
///
/// # Errors
/// Unreadable or invalid configuration.
pub fn load_config(path: &Path) -> Result<Config> {
    Ok(Config::load(path)?)
}

/// [`load_config`] for administration commands: logs only warnings.
fn load_quiet(path: &Path) -> Result<Config> {
    let config = load_config(path)?;
    logging::init(dnsy_config::LogLevel::Warn, config.logging.format);
    Ok(config)
}

/// Opens (creating and migrating) `<data_dir>/dnsy.db`. A missing data directory is created with
/// mode 0700 and the database with 0600; existing ones keep their modes.
pub(crate) fn open_store(config: &Config) -> Result<Store> {
    create_private_dir(&config.server.data_dir)?;
    Ok(Store::open(&db_path(config))?)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

pub(crate) fn db_path(config: &Config) -> std::path::PathBuf {
    config.server.data_dir.join("dnsy.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn fresh_data_dir_and_database_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.server.data_dir = tmp.path().join("state").join("dnsy");
        let store = open_store(&config).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&config.server.data_dir), 0o700);
        assert_eq!(mode(&db_path(&config)), 0o600);
        drop(store);
        // Reopening never loosens or tightens what the operator set.
        std::fs::set_permissions(
            &config.server.data_dir,
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        open_store(&config).unwrap();
        assert_eq!(mode(&config.server.data_dir), 0o750);
    }
}
