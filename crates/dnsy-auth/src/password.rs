use std::sync::Arc;

use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use argon2::{Algorithm, Argon2, Params, Version};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::UserError;

/// OWASP minimum for argon2id: 19 MiB memory, 2 iterations, 1 lane.
fn argon2() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("static argon2 parameters are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash `password` into a PHC string with a fresh random salt.
pub(crate) fn hash(password: &str) -> Result<String, UserError> {
    argon2()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|_| UserError::Hash)
}

/// Whether `password` matches the PHC string `phc`. A malformed hash never matches.
pub(crate) fn verify(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|parsed| {
        argon2()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// Longest password accepted anywhere, checked before any hashing.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Bounds concurrent argon2 work (each run holds 19 MiB and a core).
#[derive(Clone, Debug)]
pub(crate) struct HashGate(pub(crate) Arc<Semaphore>);

impl HashGate {
    /// One permit per available CPU.
    pub(crate) fn new() -> HashGate {
        HashGate::with_permits(std::thread::available_parallelism().map_or(1, usize::from))
    }

    pub(crate) fn with_permits(n: usize) -> HashGate {
        HashGate(Arc::new(Semaphore::new(n)))
    }

    /// Run a CPU-heavy closure off the async executor, waiting for a free permit.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, UserError> {
        let permit = Arc::clone(&self.0)
            .acquire_owned()
            .await
            .map_err(|_| UserError::Hash)?;
        Self::spawn(permit, f).await
    }

    /// Like [`HashGate::run`] but fails with [`UserError::Busy`] instead of waiting.
    pub(crate) async fn try_run<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, UserError> {
        let permit = Arc::clone(&self.0)
            .try_acquire_owned()
            .map_err(|_| UserError::Busy)?;
        Self::spawn(permit, f).await
    }

    async fn spawn<T: Send + 'static>(
        permit: OwnedSemaphorePermit,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, UserError> {
        tokio::task::spawn_blocking(move || {
            let out = f();
            drop(permit);
            out
        })
        .await
        .map_err(|_| UserError::Hash)
    }
}
