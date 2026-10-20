use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// How long a bootstrap code stays valid.
pub(crate) const TTL: Duration = Duration::from_hours(1);

struct State {
    digest: [u8; 32],
    expires_at: Instant,
}

/// One-time code that authorises creating the first admin.
///
/// Only a digest is kept in memory; the plaintext code is returned once by
/// [`BootstrapCode::generate`] and printed once to stderr by the caller.
pub struct BootstrapCode {
    state: Mutex<Option<State>>,
}

fn digest(code: &str) -> [u8; 32] {
    Sha256::digest(code.trim().as_bytes()).into()
}

impl BootstrapCode {
    /// Create a code valid for `ttl`. Returns the handle and the plaintext code.
    #[must_use]
    pub fn generate(ttl: Duration) -> (BootstrapCode, String) {
        let mut raw = [0u8; 16];
        rand::fill(&mut raw[..]);
        let code = raw.iter().fold(String::with_capacity(32), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let state = State {
            digest: digest(&code),
            expires_at: Instant::now() + ttl,
        };
        (
            BootstrapCode {
                state: Mutex::new(Some(state)),
            },
            code,
        )
    }

    fn lock(&self) -> MutexGuard<'_, Option<State>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether `code` is the live, unused code. An expired code is discarded.
    pub(crate) fn is_valid(&self, code: &str) -> bool {
        let mut guard = self.lock();
        let Some(state) = guard.as_ref() else {
            return false;
        };
        if Instant::now() >= state.expires_at {
            *guard = None;
            return false;
        }
        state.digest.ct_eq(&digest(code)).into()
    }

    /// Invalidate the code for good.
    pub(crate) fn consume(&self) {
        *self.lock() = None;
    }
}
