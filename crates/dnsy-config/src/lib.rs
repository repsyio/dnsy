//! dnsy-config: TOML schema, defaults, validation and `DNSY_SECTION__KEY` environment overrides.

mod model;
mod validate;

use std::path::{Path, PathBuf};

pub use model::{
    Api, BlockMode, Cache, Config, Dns, Dnssec, Doh, Dot, Filter, Limits, LogFormat, LogLevel,
    Logging, Mtls, Prefetch, QueryLog, ROOT_KSK_2017_DS, ROOT_KSK_2024_DS, Resolver, ServeStale,
    Server, Validation, Zones,
};
pub use validate::TrustAnchor;

/// Environment variable carrying the DNSSEC key passphrase (read by the key store, never logged).
pub const PASSPHRASE_ENV: &str = "DNSY_DNSSEC_PASSPHRASE";

/// Errors from loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read config {}: {source}", path.display())]
    Io {
        /// File path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The TOML is malformed or does not match the schema (including unknown keys).
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
    /// An environment override cannot be applied.
    #[error("invalid environment override {name}: {reason}")]
    Env {
        /// Variable name.
        name: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A value or combination of values is not acceptable.
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl Config {
    /// Load, apply `DNSY_*` environment overrides from the process environment, and validate.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] when the file is unreadable, malformed, or invalid.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml_with_env(&text, std::env::vars())
    }

    /// Parse TOML text with no environment overrides, then validate.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] when the text is malformed or invalid.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        Self::from_toml_with_env(text, std::iter::empty())
    }

    /// Parse TOML text, apply overrides from `env` (`DNSY_SECTION__KEY=value`), then validate.
    ///
    /// Segments are lower-cased and split on `__`, so `DNSY_CACHE__SERVE_STALE__ENABLED=false`
    /// sets `cache.serve_stale.enabled`. Values are read as TOML scalars or arrays and fall back
    /// to plain strings. Variables without `__` (such as [`PASSPHRASE_ENV`]) are ignored.
    ///
    /// # Errors
    /// Returns a [`ConfigError`] when the text, an override, or the result is invalid.
    pub fn from_toml_with_env(
        text: &str,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let mut table: toml::Table = text.parse()?;
        let mut overrides: Vec<_> = env
            .into_iter()
            .filter_map(|(name, value)| {
                let rest = name.strip_prefix("DNSY_")?;
                rest.contains("__")
                    .then_some((name.clone(), rest.to_lowercase(), value))
            })
            .collect();
        overrides.sort();
        for (name, key, value) in overrides {
            apply_override(&mut table, &name, &key, &value)?;
        }
        let config: Self = table.try_into()?;
        config.validate()?;
        Ok(config)
    }

    /// Cross-field validation, as run by every loader. Use it after changing a loaded config.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] naming the offending key.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate::validate(self)
    }

    /// Non-fatal problems worth telling the operator about (an open, unlimited resolver on a
    /// non-loopback listener).
    #[must_use]
    pub fn warnings(&self) -> Vec<String> {
        validate::warnings(self)
    }
}

fn apply_override(
    root: &mut toml::Table,
    name: &str,
    key: &str,
    raw: &str,
) -> Result<(), ConfigError> {
    let err = |reason: &str| ConfigError::Env {
        name: name.to_owned(),
        reason: reason.to_owned(),
    };
    let value = format!("v = {raw}")
        .parse::<toml::Table>()
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| toml::Value::String(raw.to_owned()));
    let mut segments: Vec<&str> = key.split("__").collect();
    let last = segments
        .pop()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| err("empty key"))?;
    let mut table = root;
    for segment in segments {
        if segment.is_empty() {
            return Err(err("empty key segment"));
        }
        table = table
            .entry(segment)
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
            .ok_or_else(|| err("parent is not a section"))?;
    }
    table.insert(last.to_owned(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_warns_for_open_unlimited_listener() {
        let mut c = Config::default();
        assert!(c.warnings().is_empty(), "safe defaults do not warn");
        c.limits.open_resolver = true;
        assert!(c.warnings().is_empty(), "qps 50 does not warn");
        c.limits.per_client_qps = 0;
        let w = c.warnings();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("0.0.0.0:53"), "{w:?}");
        c.dns.udp = vec!["127.0.0.1:53".parse().unwrap()];
        c.dns.tcp = vec!["[::1]:53".parse().unwrap()];
        assert!(c.warnings().is_empty(), "loopback only does not warn");
        c.doh.listen = vec!["10.0.0.1:443".parse().unwrap()];
        assert_eq!(c.warnings().len(), 1);
    }

    #[test]
    fn limits_defaults_are_safe() {
        let l = Config::default().limits;
        assert_eq!(l.per_client_qps, 50);
        assert!(!l.open_resolver);
        let c = Config::from_toml("[limits]\nopen_resolver = true\n").unwrap();
        assert!(c.limits.open_resolver);
    }

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn err(text: &str) -> String {
        Config::from_toml(text).unwrap_err().to_string()
    }

    #[test]
    fn defaults_are_valid() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c, Config::default());
        assert_eq!(c.dnssec.validation, Validation::Strict);
        assert_eq!(c.cache.max_entries, 100_000);
        assert_eq!(c.cache.serve_stale.client_timeout_ms, 1800);
        assert_eq!(c.cache.prefetch.remaining_ttl_pct, 10);
        assert!(c.doh.require_token);
        assert_eq!(c.logging.format, LogFormat::Pretty);
    }

    #[test]
    fn unknown_key_rejected() {
        assert!(err("bogus = 1").contains("bogus"));
        assert!(err("[cache]\nnope = 1").contains("nope"));
        assert!(err("[cache.prefetch]\nnope = 1").contains("nope"));
    }

    #[test]
    fn env_override_applies() {
        let c = Config::from_toml_with_env(
            "[cache]\nmax_ttl = 100",
            env(&[
                ("DNSY_CACHE__MAX_TTL", "200"),
                ("DNSY_CACHE__SERVE_STALE__ENABLED", "false"),
                ("DNSY_DNS__UDP", r#"["127.0.0.1:5353"]"#),
                ("DNSY_LOGGING__LEVEL", "debug"),
                ("DNSY_DNSSEC_PASSPHRASE", "ignored"),
                ("OTHER__THING", "ignored"),
            ]),
        )
        .unwrap();
        assert_eq!(c.cache.max_ttl, 200);
        assert!(!c.cache.serve_stale.enabled);
        assert_eq!(c.dns.udp, vec!["127.0.0.1:5353".parse().unwrap()]);
        assert_eq!(c.logging.level, LogLevel::Debug);
    }

    #[test]
    fn env_override_errors() {
        let bad = |k: &str| {
            Config::from_toml_with_env("", env(&[(k, "1")]))
                .unwrap_err()
                .to_string()
        };
        assert!(bad("DNSY_NOPE__KEY").contains("nope"));
        assert!(bad("DNSY___X").contains("DNSY___X"));
        assert!(bad("DNSY_CACHE__").contains("empty key"));
        assert!(
            Config::from_toml_with_env(
                "[cache]\nmax_ttl = 1",
                env(&[("DNSY_CACHE__MAX_TTL__X", "1")])
            )
            .unwrap_err()
            .to_string()
            .contains("not a section")
        );
    }

    #[test]
    fn tls_required_when_dot_enabled() {
        assert!(err("[dot]\nlisten = [\"0.0.0.0:853\"]").contains("dot.cert"));
        let ok = "[dot]\nlisten = [\"0.0.0.0:853\"]\ncert = \"c.pem\"\nkey = \"k.pem\"";
        assert!(Config::from_toml(ok).is_ok());
        assert!(err(&format!("{ok}\nmtls = \"required\"")).contains("client_ca"));
        assert!(
            Config::from_toml(&format!(
                "{ok}\nmtls = \"optional\"\nclient_ca = \"ca.pem\""
            ))
            .is_ok()
        );
        assert!(err("[doh]\nlisten = [\"0.0.0.0:443\"]").contains("doh.cert"));
        assert!(err("[doh]\npath = \"dns\"").contains("doh.path"));
        assert!(err("[api]\ntls_cert = \"c.pem\"").contains("together"));
    }

    #[test]
    fn cache_min_ttl_le_max_ttl() {
        assert!(err("[cache]\nmin_ttl = 10\nmax_ttl = 5").contains("min_ttl"));
        assert!(err("[cache]\nmax_entries = 0").contains("max_entries"));
        assert!(err("[cache.prefetch]\nremaining_ttl_pct = 0").contains("remaining_ttl_pct"));
        assert!(err("[cache.prefetch]\nremaining_ttl_pct = 101").contains("remaining_ttl_pct"));
    }

    #[test]
    fn other_validation_errors() {
        assert!(err("[resolver]\nattempts = 0").contains("resolver"));
        assert!(err("[filter]\nrefresh_interval = 0").contains("refresh_interval"));
        assert!(err("[dnssec]\ntrust_anchors = []").contains("trust_anchors"));
        assert!(Config::from_toml("[dnssec]\nvalidation = \"off\"\ntrust_anchors = []").is_ok());
        assert!(err("[dnssec]\nvalidation = \"loose\"").contains("loose"));
        assert!(err("dns = ").contains("invalid config"));
    }

    #[test]
    fn trust_anchor_ds_parses() {
        let c = Config::default();
        let tags: Vec<u16> = c
            .dnssec
            .trust_anchors
            .iter()
            .map(|s| TrustAnchor::parse(s).unwrap().key_tag)
            .collect();
        assert_eq!(tags, [20326, 38696]);
        let ta = TrustAnchor::parse(ROOT_KSK_2024_DS).unwrap();
        assert_eq!((ta.algorithm, ta.digest_type, ta.digest.len()), (8, 2, 32));
        for bad in [
            "",
            "1",
            "x 8 2 aa",
            "1 x 2 aa",
            "1 8 x aa",
            "1 8 2",
            "1 8 2 zz",
            "1 8 2 abc",
            "1 8 9 aa",
            "1 8 1 aabb",
            &format!("{ROOT_KSK_2017_DS} extra"),
            "1 8 2 éé",
        ] {
            assert!(TrustAnchor::parse(bad).is_err(), "{bad}");
        }
        assert!(TrustAnchor::parse(&format!("1 8 1 {}", "ab".repeat(20))).is_ok());
        assert!(TrustAnchor::parse(&format!("1 8 4 {}", "ab".repeat(48))).is_ok());
        assert!(err("[dnssec]\ntrust_anchors = [\"nonsense\"]").contains("trust anchor"));
    }

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../examples/dnsy.toml");
        assert!(Config::from_toml(text).is_ok());
    }

    #[test]
    fn load_reads_file_and_reports_missing() {
        let dir = std::env::temp_dir().join(format!("dnsy-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dnsy.toml");
        std::fs::write(&path, "[server]\ndata_dir = \"/tmp/x\"").unwrap();
        let c = Config::load(&path).unwrap();
        assert_eq!(c.server.data_dir, PathBuf::from("/tmp/x"));
        let missing = Config::load(dir.join("absent.toml")).unwrap_err();
        assert!(matches!(missing, ConfigError::Io { .. }));
        assert!(missing.to_string().contains("absent.toml"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
