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

/// The async runtime for `cli`'s command. `serve` sizes it from `[server] worker_threads`; every
/// other command, and a configuration that cannot be read (the command reports that itself),
/// gets the default.
///
/// # Errors
/// The runtime could not be created.
pub fn runtime(cli: &Cli) -> std::io::Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if matches!(cli.command, Command::Serve(_))
        && let Ok(config) = Config::load(&cli.config)
    {
        builder.worker_threads(config.server.worker_threads);
    }
    builder.build()
}

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
        Command::Db(cmd) => admin::db(&load_quiet(&cli.config)?, cmd, &mut out),
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
    let dir = &config.server.data_dir;
    create_private_dir(dir)
        .map_err(|e| path_error("create the data directory", dir, &e, "server.data_dir"))?;
    let db = db_path(config);
    Store::open(&db).map_err(|e| path_error("open the database", &db, &e, "server.data_dir"))
}

/// A data directory, zones directory or database failure that names the path and, since this is almost always
/// permissions (an unprivileged run against the default `/var/lib/dnsy`), the way out.
pub(crate) fn path_error(
    action: &str,
    path: &Path,
    err: &dyn std::error::Error,
    key: &str,
) -> Error {
    let env = format!("DNSY_{}", key.to_ascii_uppercase().replace('.', "__"));
    Error::msg(format!(
        "cannot {action} {}: {err} (set `{key}` in the config file or {env} to a directory \
         this user can write)",
        path.display()
    ))
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
    use clap::Parser as _;

    use super::*;

    fn workers(args: &[&str]) -> usize {
        let cli = Cli::parse_from(args);
        runtime(&cli).unwrap().handle().metrics().num_workers()
    }

    #[test]
    fn serve_sizes_the_runtime_from_worker_threads() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("dnsy.toml");
        std::fs::write(&path, "[server]\nworker_threads = 3\n").unwrap();
        let path = path.to_str().unwrap();
        assert_eq!(workers(&["dnsy", "-c", path, "serve"]), 3);
        // Other commands do not read the key; a missing file leaves the default.
        let default = tokio::runtime::Runtime::new()
            .unwrap()
            .handle()
            .metrics()
            .num_workers();
        assert_eq!(workers(&["dnsy", "-c", path, "version"]), default);
        assert_eq!(
            workers(&["dnsy", "-c", "/nonexistent/dnsy.toml", "serve"]),
            default
        );
    }

    #[test]
    fn data_dir_failure_names_the_path_and_the_fix() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("file");
        std::fs::write(&blocker, "x").unwrap();
        let mut config = Config::default();
        config.server.data_dir = blocker.join("dnsy");
        let msg = open_store(&config).err().expect("fails").to_string();
        assert!(msg.contains("create the data directory"), "{msg}");
        assert!(
            msg.contains(&blocker.join("dnsy").display().to_string()),
            "{msg}"
        );
        assert!(
            msg.contains("server.data_dir") && msg.contains("DNSY_SERVER__DATA_DIR"),
            "{msg}"
        );
    }

    #[test]
    fn path_error_derives_the_env_var_from_the_key() {
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let msg = path_error("create", Path::new("/x/zones"), &e, "zones.dir").to_string();
        assert!(
            msg.contains("/x/zones") && msg.contains("DNSY_ZONES__DIR"),
            "{msg}"
        );
    }

    #[test]
    fn unopenable_database_names_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.server.data_dir = tmp.path().to_path_buf();
        std::fs::create_dir(db_path(&config)).unwrap();
        let msg = open_store(&config).err().expect("fails").to_string();
        assert!(msg.contains("open the database"), "{msg}");
        assert!(
            msg.contains("dnsy.db") && msg.contains("DNSY_SERVER__DATA_DIR"),
            "{msg}"
        );
    }

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
