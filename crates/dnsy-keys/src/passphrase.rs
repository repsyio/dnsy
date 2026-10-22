//! The key-encryption passphrase and where it comes from.

use std::fmt;
use std::path::Path;

use zeroize::Zeroizing;

use crate::KeyStoreError;

/// A key-encryption passphrase. Zeroized on drop, redacted in `Debug`.
#[derive(Clone)]
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    pub fn new(secret: impl Into<String>) -> Passphrase {
        Passphrase(Zeroizing::new(secret.into()))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

/// Resolves the passphrase from `env` (the value of `DNSY_DNSSEC_PASSPHRASE`, empty counts as
/// unset), else from the first line of `file`. `None` means keys are stored unencrypted.
///
/// # Errors
/// The file cannot be read or is empty.
pub fn resolve_passphrase(
    env: Option<String>,
    file: Option<&Path>,
) -> Result<Option<Passphrase>, KeyStoreError> {
    if let Some(v) = env.filter(|v| !v.is_empty()) {
        return Ok(Some(Passphrase::new(v)));
    }
    let Some(path) = file else { return Ok(None) };
    let fail = |reason: &str| KeyStoreError::PassphraseFile {
        path: path.display().to_string(),
        reason: reason.to_owned(),
    };
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| fail(&e.to_string()))?);
    let line = text.lines().next().unwrap_or_default();
    if line.is_empty() {
        return Err(fail("file is empty"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .map_err(|e| fail(&e.to_string()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            tracing::warn!(path = %path.display(), "passphrase file is accessible to other users; use mode 0600");
        }
    }
    Ok(Some(Passphrase::new(line)))
}

/// [`resolve_passphrase`] reading the environment variable named `env_name`
/// (`DNSY_DNSSEC_PASSPHRASE` in the binary).
///
/// # Errors
/// See [`resolve_passphrase`].
pub fn passphrase_from_environment(
    env_name: &str,
    file: Option<&Path>,
) -> Result<Option<Passphrase>, KeyStoreError> {
    resolve_passphrase(std::env::var(env_name).ok(), file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("pass");
        std::fs::write(&file, "from-file\nsecond line\n").unwrap();
        let get = |env: Option<&str>, f: Option<&Path>| {
            resolve_passphrase(env.map(str::to_owned), f)
                .unwrap()
                .map(|p| p.0.to_string())
        };
        assert_eq!(
            get(Some("from-env"), Some(&file)).as_deref(),
            Some("from-env")
        );
        assert_eq!(get(Some(""), Some(&file)).as_deref(), Some("from-file"));
        assert_eq!(get(None, Some(&file)).as_deref(), Some("from-file"));
        assert_eq!(get(None, None), None);
        assert_eq!(get(Some(""), None), None);
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        for bad in [empty.as_path(), dir.path().join("nope").as_path()] {
            let err = resolve_passphrase(None, Some(bad)).unwrap_err();
            assert!(matches!(err, KeyStoreError::PassphraseFile { .. }));
        }
        // The process environment is not set in tests, so this only checks the wiring.
        assert!(passphrase_from_environment("DNSY_TEST_UNSET_PASSPHRASE", None).is_ok());
    }
}
