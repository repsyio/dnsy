use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use argon2::{Algorithm, Argon2, Params, Version};

use dnsy_core::net::ClientKey;
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

/// Concurrent argon2 runs one client key may hold, so one address cannot take every slot.
pub(crate) const PER_CLIENT_HASHES: usize = 2;

type KeyCounts = Arc<Mutex<HashMap<ClientKey, usize>>>;

/// Bounds concurrent argon2 work (each run holds 19 MiB and a core), globally and per client.
#[derive(Clone, Debug)]
pub(crate) struct HashGate {
    pub(crate) sem: Arc<Semaphore>,
    keys: KeyCounts,
}

/// Capacity for one argon2 run, held from admission until the hash finishes.
#[derive(Debug)]
pub(crate) struct HashSlot {
    _permit: OwnedSemaphorePermit,
    _key: Option<KeyGuard>,
}

#[derive(Debug)]
struct KeyGuard {
    keys: KeyCounts,
    key: ClientKey,
}

impl Drop for KeyGuard {
    fn drop(&mut self) {
        if let Ok(mut keys) = self.keys.lock()
            && let Some(n) = keys.get_mut(&self.key)
        {
            *n -= 1;
            if *n == 0 {
                keys.remove(&self.key);
            }
        }
    }
}

impl HashGate {
    /// One permit per available CPU.
    pub(crate) fn new() -> HashGate {
        HashGate::with_permits(std::thread::available_parallelism().map_or(1, usize::from))
    }

    pub(crate) fn with_permits(n: usize) -> HashGate {
        HashGate {
            sem: Arc::new(Semaphore::new(n)),
            keys: KeyCounts::default(),
        }
    }

    /// Takes a slot without waiting, also bounded per `client` when one is given.
    ///
    /// # Errors
    /// [`UserError::Busy`] when the global or the per-client limit is reached.
    pub(crate) fn try_slot(&self, client: Option<ClientKey>) -> Result<HashSlot, UserError> {
        let permit = Arc::clone(&self.sem)
            .try_acquire_owned()
            .map_err(|_| UserError::Busy)?;
        let key = match client {
            Some(key) => {
                let mut keys = self.keys.lock().map_err(|_| UserError::Hash)?;
                let n = keys.entry(key).or_insert(0);
                if *n >= PER_CLIENT_HASHES {
                    return Err(UserError::Busy);
                }
                *n += 1;
                Some(KeyGuard {
                    keys: Arc::clone(&self.keys),
                    key,
                })
            }
            None => None,
        };
        Ok(HashSlot {
            _permit: permit,
            _key: key,
        })
    }

    /// Run a CPU-heavy closure off the async executor, waiting for a free permit.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, UserError> {
        let permit = Arc::clone(&self.sem)
            .acquire_owned()
            .await
            .map_err(|_| UserError::Hash)?;
        Self::spawn(
            HashSlot {
                _permit: permit,
                _key: None,
            },
            f,
        )
        .await
    }

    /// Run a closure holding an already admitted `slot`.
    pub(crate) async fn run_in<T: Send + 'static>(
        slot: HashSlot,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, UserError> {
        Self::spawn(slot, f).await
    }

    async fn spawn<T: Send + 'static>(
        slot: HashSlot,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, UserError> {
        tokio::task::spawn_blocking(move || {
            let out = f();
            drop(slot);
            out
        })
        .await
        .map_err(|_| UserError::Hash)
    }
}
