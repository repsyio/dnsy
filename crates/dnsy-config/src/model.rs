//! The configuration schema and its defaults.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// Root KSK-2017 (key tag 20326) as a DS record.
pub const ROOT_KSK_2017_DS: &str =
    "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
/// Root KSK-2024 (key tag 38696) as a DS record.
pub const ROOT_KSK_2024_DS: &str =
    "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";

/// Complete DNSY configuration. Unknown keys are rejected at every level.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Process-wide settings.
    pub server: Server,
    /// Plain DNS listeners.
    pub dns: Dns,
    /// DNS-over-TLS listener.
    pub dot: Dot,
    /// DNS-over-HTTPS listener.
    pub doh: Doh,
    /// REST API and UI listener.
    pub api: Api,
    /// Zone files.
    pub zones: Zones,
    /// Upstream resolution.
    pub resolver: Resolver,
    /// Answer cache.
    pub cache: Cache,
    /// DNSSEC validation and signing.
    pub dnssec: Dnssec,
    /// Filtering seed settings.
    pub filter: Filter,
    /// Connection and rate limits.
    pub limits: Limits,
    /// Query log.
    pub querylog: QueryLog,
    /// Process logging.
    pub logging: Logging,
}

/// `[server]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    /// Directory holding `dnsy.db` and other runtime state.
    pub data_dir: PathBuf,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/dnsy"),
        }
    }
}

/// `[dns]`: empty lists disable the transport.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    /// UDP listen addresses.
    pub udp: Vec<SocketAddr>,
    /// TCP listen addresses.
    pub tcp: Vec<SocketAddr>,
}

impl Default for Dns {
    fn default() -> Self {
        let any: SocketAddr = ([0, 0, 0, 0], 53).into();
        Self {
            udp: vec![any],
            tcp: vec![any],
        }
    }
}

/// Client certificate policy for `DoT`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mtls {
    /// No client certificates.
    #[default]
    Off,
    /// Client certificates are verified when presented.
    Optional,
    /// Connections without a valid client certificate are refused.
    Required,
}

/// `[dot]`: an empty `listen` disables the listener.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dot {
    /// Listen addresses.
    pub listen: Vec<SocketAddr>,
    /// Certificate chain (PEM).
    pub cert: Option<PathBuf>,
    /// Private key (PEM).
    pub key: Option<PathBuf>,
    /// CA bundle used to verify client certificates.
    pub client_ca: Option<PathBuf>,
    /// Client certificate policy.
    pub mtls: Mtls,
}

/// `[doh]`: an empty `listen` disables the listener.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Doh {
    /// Listen addresses.
    pub listen: Vec<SocketAddr>,
    /// Certificate chain (PEM).
    pub cert: Option<PathBuf>,
    /// Private key (PEM).
    pub key: Option<PathBuf>,
    /// Request path.
    pub path: String,
    /// Whether a token is required to query.
    pub require_token: bool,
}

impl Default for Doh {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            cert: None,
            key: None,
            path: "/dns-query".to_owned(),
            require_token: true,
        }
    }
}

/// `[api]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Api {
    /// Listen addresses; empty disables the API and UI.
    pub listen: Vec<SocketAddr>,
    /// Optional TLS certificate chain (PEM); requires `tls_key`.
    pub tls_cert: Option<PathBuf>,
    /// Optional TLS private key (PEM); requires `tls_cert`.
    pub tls_key: Option<PathBuf>,
    /// Externally visible base URL.
    pub public_url: Option<String>,
    /// `Secure` cookie attribute and HSTS: `auto` follows DNSY's own TLS, `true` forces them
    /// (TLS terminated by a reverse proxy), `false` disables them.
    pub secure_cookies: SecureCookies,
    /// Login requests per client address (IPv6 `/64`) that may be queued or hashing at once;
    /// more are refused with 503 immediately (default 16).
    pub login_hash_per_client: usize,
    /// How long a login queues for a password-hashing slot before it is refused with 503
    /// (default 5000 ms).
    pub login_hash_wait_ms: u64,
}

/// `[api] secure_cookies`: the string `"auto"` or a boolean.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SecureCookies {
    /// Follow `tls_cert` / `tls_key`.
    #[default]
    Auto,
    Always,
    Never,
}

impl From<SecureCookies> for Option<bool> {
    fn from(v: SecureCookies) -> Self {
        match v {
            SecureCookies::Auto => None,
            SecureCookies::Always => Some(true),
            SecureCookies::Never => Some(false),
        }
    }
}

impl<'de> Deserialize<'de> for SecureCookies {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Flag(bool),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Flag(true) => Ok(Self::Always),
            Raw::Flag(false) => Ok(Self::Never),
            Raw::Text(t) if t == "auto" => Ok(Self::Auto),
            Raw::Text(t) => Err(serde::de::Error::custom(format!(
                "invalid secure_cookies {t:?}: expected \"auto\", true or false"
            ))),
        }
    }
}

impl Default for Api {
    fn default() -> Self {
        Self {
            listen: vec![([127, 0, 0, 1], 5380).into()],
            tls_cert: None,
            tls_key: None,
            public_url: None,
            secure_cookies: SecureCookies::Auto,
            login_hash_per_client: 16,
            login_hash_wait_ms: 5000,
        }
    }
}

/// `[zones]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Zones {
    /// Directory of `<zone>.json` files.
    pub dir: PathBuf,
}

impl Default for Zones {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/var/lib/dnsy/zones"),
        }
    }
}

/// `[resolver]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Resolver {
    /// Per-attempt upstream timeout.
    pub timeout_ms: u64,
    /// Attempts per query.
    pub attempts: u32,
    /// Upstreams applied on first start.
    pub upstreams: Vec<SocketAddr>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            timeout_ms: 2000,
            attempts: 2,
            upstreams: Vec::new(),
        }
    }
}

/// `[cache]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Cache {
    /// Master switch.
    pub enabled: bool,
    /// Entry bound.
    pub max_entries: usize,
    /// TTL floor, seconds.
    pub min_ttl: u32,
    /// TTL ceiling, seconds.
    pub max_ttl: u32,
    /// Ceiling for negative answers, seconds.
    pub negative_max_ttl: u32,
    /// How long SERVFAIL is cached, seconds.
    pub servfail_ttl: u32,
    /// How long Bogus results are cached, seconds.
    pub bogus_ttl: u32,
    /// Serve-stale (RFC 8767).
    pub serve_stale: ServeStale,
    /// Prefetch of popular entries.
    pub prefetch: Prefetch,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 100_000,
            min_ttl: 0,
            max_ttl: 86_400,
            negative_max_ttl: 3600,
            servfail_ttl: 5,
            bogus_ttl: 60,
            serve_stale: ServeStale::default(),
            prefetch: Prefetch::default(),
        }
    }
}

/// `[cache.serve_stale]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServeStale {
    /// Enable serving stale answers.
    pub enabled: bool,
    /// How long stale entries are kept, seconds.
    pub max_stale: u32,
    /// TTL placed on stale answers, seconds.
    pub answer_ttl: u32,
    /// Wait for the refresh this long before answering stale.
    pub client_timeout_ms: u64,
}

impl Default for ServeStale {
    fn default() -> Self {
        Self {
            enabled: true,
            max_stale: 86_400,
            answer_ttl: 30,
            client_timeout_ms: 1800,
        }
    }
}

/// `[cache.prefetch]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Prefetch {
    /// Enable prefetch.
    pub enabled: bool,
    /// Hits an entry needs to qualify.
    pub min_hits: u32,
    /// Prefetch when this percentage of the TTL remains.
    pub remaining_ttl_pct: u8,
}

impl Default for Prefetch {
    fn default() -> Self {
        Self {
            enabled: true,
            min_hits: 5,
            remaining_ttl_pct: 10,
        }
    }
}

/// DNSSEC validation mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Validation {
    /// No validation.
    Off,
    /// Validate; Bogus answers are returned without AD.
    Permissive,
    /// Validate; Bogus answers become SERVFAIL.
    #[default]
    Strict,
}

/// `[dnssec]`. The key passphrase may also come from `DNSY_DNSSEC_PASSPHRASE`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dnssec {
    /// Validation mode.
    pub validation: Validation,
    /// Trust anchors as DS records (`keytag algorithm digest-type digest-hex`).
    pub trust_anchors: Vec<String>,
    /// File with additional trust anchors, one DS per line.
    pub trust_anchor_file: Option<PathBuf>,
    /// Domains below which validation is skipped.
    pub negative_trust_anchors: Vec<String>,
    /// Allowed clock skew when checking signature times, seconds.
    pub clock_skew_s: u32,
    /// File holding the key-encryption passphrase.
    pub key_passphrase_file: Option<PathBuf>,
}

impl Default for Dnssec {
    fn default() -> Self {
        Self {
            validation: Validation::default(),
            trust_anchors: vec![ROOT_KSK_2017_DS.to_owned(), ROOT_KSK_2024_DS.to_owned()],
            trust_anchor_file: None,
            negative_trust_anchors: Vec::new(),
            clock_skew_s: 300,
            key_passphrase_file: None,
        }
    }
}

/// How blocked names are answered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockMode {
    /// `0.0.0.0` / `::`.
    #[default]
    NullIp,
    /// NXDOMAIN.
    Nxdomain,
    /// REFUSED.
    Refused,
}

/// `[filter]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Filter {
    /// Block response style.
    pub block_mode: BlockMode,
    /// Blocklist URLs or paths applied on first start.
    pub blocklists: Vec<String>,
    /// Blocklist refresh interval, seconds.
    pub refresh_interval: u64,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            block_mode: BlockMode::default(),
            blocklists: Vec::new(),
            refresh_interval: 86_400,
        }
    }
}

/// `[limits]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Queries per second per client; 0 disables the limit.
    pub per_client_qps: u32,
    /// Answer clients from any address. When false (the default) only loopback, RFC 1918,
    /// 100.64/10, ULA and link-local clients are served, plus whatever ACL rules allow.
    pub open_resolver: bool,
    /// Idle timeout for TCP connections.
    pub tcp_idle_ms: u64,
    /// Maximum concurrent TCP connections.
    pub max_tcp_conns: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            per_client_qps: 50,
            open_resolver: false,
            tcp_idle_ms: 10_000,
            max_tcp_conns: 1024,
        }
    }
}

/// `[querylog]`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QueryLog {
    /// Record queries.
    pub enabled: bool,
    /// Days to keep rows.
    pub retention_days: u32,
    /// Store client addresses truncated to /24 (IPv4) or /48 (IPv6).
    pub redact_client_ip: bool,
}

impl Default for QueryLog {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
            redact_client_ip: false,
        }
    }
}

/// Log verbosity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Most verbose.
    Trace,
    /// Debug.
    Debug,
    /// Info.
    #[default]
    Info,
    /// Warnings.
    Warn,
    /// Errors only.
    Error,
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human readable.
    #[default]
    Pretty,
    /// One JSON object per line.
    Json,
}

/// `[logging]`
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Logging {
    /// Verbosity.
    pub level: LogLevel,
    /// Format.
    pub format: LogFormat,
}
