//! Command line definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// DNSY: a single-binary DNS server.
#[derive(Debug, Parser)]
#[command(name = "dnsy", version, about)]
pub struct Cli {
    /// Configuration file (TOML).
    #[arg(
        short,
        long,
        global = true,
        env = "DNSY_CONFIG",
        default_value = "/etc/dnsy/dnsy.toml"
    )]
    pub config: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the DNS server and the API.
    Serve(ServeArgs),
    /// Inspect the configuration.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Apply database migrations (`--status` only reports them).
    Migrate {
        /// Report applied and pending migrations without applying any.
        #[arg(long)]
        status: bool,
    },
    /// Check, vacuum or back up the database.
    #[command(subcommand)]
    Db(DbCommand),
    /// Manage users.
    #[command(subcommand)]
    User(UserCommand),
    /// Manage API tokens.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Work with zones.
    #[command(subcommand)]
    Zone(ZoneCommand),
    /// Manage DNSSEC keys.
    #[command(subcommand)]
    Dnssec(DnssecCommand),
    /// Manage the resolver cache of a running server.
    #[command(subcommand)]
    Cache(CacheCommand),
    /// Print the `OpenAPI` document.
    Openapi,
    /// Print the version and build time.
    Version,
}

#[derive(Debug, Subcommand)]
pub enum DbCommand {
    /// Verify the database (`quick_check`; `--full` runs `integrity_check`). Read-only, safe
    /// while the server runs. Exits non-zero when a problem is found.
    Check {
        /// Run the slower, complete `integrity_check`.
        #[arg(long)]
        full: bool,
    },
    /// Rebuild the database file to give free space back. Refuses while the server (or any
    /// other process) has the database open; needs up to twice its size in free disk space.
    Vacuum,
    /// Write a consistent copy of the database to a new file (mode 0600). Safe while the
    /// server runs; the copy includes everything in the WAL.
    Backup {
        /// File to create; it must not exist.
        file: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Write the bound listener addresses as JSON to this file once everything listens
    /// (for supervisors and tests using port 0).
    #[arg(long)]
    pub ready_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration file and report every problem.
    Check,
}

#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// Create a user. The password comes from stdin with `--password-stdin`, else
    /// `DNSY_PASSWORD`, else a random one is generated and printed once.
    Create {
        username: String,
        /// admin, operator or viewer.
        #[arg(long, default_value = "admin")]
        role: String,
        /// Read the password from the first line of stdin.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Set a new password (sources as for `create`).
    ResetPassword {
        username: String,
        /// Read the password from the first line of stdin.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Disable a user: no login, sessions end, tokens are refused. The last active admin
    /// cannot be disabled.
    Disable { username: String },
    /// Enable a disabled user again.
    Enable { username: String },
    /// List users.
    List,
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Create an API or `DoH` token; the secret is printed once.
    Create {
        /// Owner.
        #[arg(long)]
        user: String,
        /// Label.
        #[arg(long)]
        name: String,
        /// dns:query, api:read, api:write or admin (repeatable).
        #[arg(long = "scope", required = true)]
        scopes: Vec<String>,
        /// Expire after this many days.
        #[arg(long)]
        expires_days: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ZoneCommand {
    /// Print a zone in BIND format.
    Export {
        /// Zone origin.
        name: String,
        /// Include DNSKEY, RRSIG and NSEC/NSEC3 records (signs the zone with its stored keys).
        #[arg(long)]
        signed: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DnssecCommand {
    /// Manage the keys of a zone.
    #[command(subcommand)]
    Keys(KeysCommand),
    /// Work with a rollover in progress.
    #[command(subcommand)]
    Rollover(RolloverCommand),
    /// Record that the registrar published a key's DS (lets a KSK or CSK rollover continue).
    DsConfirmed {
        zone: String,
        /// The published KSK or CSK; needed only when the zone has several.
        #[arg(long)]
        key: Option<i64>,
    },
    /// The passphrase that encrypts the private keys.
    #[command(subcommand)]
    Passphrase(PassphraseCommand),
}

#[derive(Debug, Subcommand)]
pub enum RolloverCommand {
    /// Abort the rollover of a zone: the incoming key is withdrawn and the active key stays.
    Abort {
        zone: String,
        /// csk, ksk or zsk; omitted aborts every rollover of the zone.
        #[arg(long)]
        role: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PassphraseCommand {
    /// Re-encrypt every private key under a new passphrase (all or none). The new passphrase
    /// comes from the first line of stdin with `--new-passphrase-stdin`, else from
    /// `DNSY_DNSSEC_NEW_PASSPHRASE`. Restart a running server afterwards with the new
    /// passphrase configured (or use the API, which switches it live).
    Change {
        /// Read the new passphrase from the first line of stdin.
        #[arg(long)]
        new_passphrase_stdin: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum KeysCommand {
    /// List the keys of a zone.
    List { zone: String },
    /// Generate a key (state `generated`).
    Generate {
        zone: String,
        /// csk, ksk or zsk.
        #[arg(long, default_value = "csk")]
        role: String,
        /// 13 (ECDSAP256SHA256) or 15 (Ed25519).
        #[arg(long, default_value_t = 13)]
        algorithm: u8,
    },
    /// Start a rollover of the active key of a role.
    Rollover {
        zone: String,
        /// csk, ksk or zsk.
        #[arg(long, default_value = "csk")]
        role: String,
        /// Algorithm of the new key.
        #[arg(long, default_value_t = 13)]
        algorithm: u8,
    },
    /// Print the DS records (SHA-256 and SHA-384) to give the registrar.
    Ds { zone: String },
    /// Write an encrypted backup of the keys to a new file (mode 0600). The bundle
    /// passphrase comes from the first line of stdin with `--passphrase-stdin`, else from
    /// `DNSY_DNSSEC_BACKUP_PASSPHRASE`.
    Export {
        /// File to create; it must not exist.
        file: PathBuf,
        /// Only this zone's keys.
        #[arg(long)]
        zone: Option<String>,
        /// Read the bundle passphrase from the first line of stdin.
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Restore keys from a backup made by `export`; keys already present are skipped.
    Import {
        file: PathBuf,
        /// Read the bundle passphrase from the first line of stdin.
        #[arg(long)]
        passphrase_stdin: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum CacheCommand {
    /// Flush the whole cache, or the entries of one name, through the API.
    Flush {
        /// Only this name.
        name: Option<String>,
        /// With a name: include everything below it.
        #[arg(long)]
        subtree: bool,
        /// API base URL; default derived from `[api]` in the configuration.
        #[arg(long)]
        url: Option<String>,
        /// API token with `api:write`.
        #[arg(long, env = "DNSY_TOKEN", hide_env_values = true)]
        token: String,
    },
}
