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
            serve::serve(config, args).await
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

/// Opens (creating and migrating) `<data_dir>/dnsy.db`.
pub(crate) fn open_store(config: &Config) -> Result<Store> {
    std::fs::create_dir_all(&config.server.data_dir)?;
    Ok(Store::open(&db_path(config))?)
}

pub(crate) fn db_path(config: &Config) -> std::path::PathBuf {
    config.server.data_dir.join("dnsy.db")
}
