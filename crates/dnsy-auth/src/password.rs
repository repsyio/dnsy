use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

/// Requests (waiting or hashing) one client key may have in flight, so one address can neither
/// take every slot nor park an unbounded number of waiting tasks.
pub(crate) const PER_CLIENT_HASHES: usize = 4;

type KeyCounts = Arc<Mutex<HashMap<ClientKey, usize>>>;

/// Bounds concurrent argon2 work (each run holds 19 MiB and a core), globally and per client.
#[derive(Clone, Debug)]
pub(crate) struct HashGate {
    pub(crate) sem: Arc<Semaphore>,
    keys: KeyCounts,
    waiters: Arc<AtomicUsize>,
}

/// Requests allowed to wait for a slot at once, across all clients.
pub(crate) const MAX_WAITERS: usize = 64;

#[derive(Debug)]
struct WaitGuard(Arc<AtomicUsize>);

impl WaitGuard {
    fn enter(waiters: &Arc<AtomicUsize>) -> Result<WaitGuard, UserError> {
        if waiters.fetch_add(1, Ordering::AcqRel) >= MAX_WAITERS {
            waiters.fetch_sub(1, Ordering::AcqRel);
            return Err(UserError::Busy);
        }
        Ok(WaitGuard(Arc::clone(waiters)))
    }
}

impl Drop for WaitGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
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
            waiters: Arc::default(),
        }
    }

    /// Counts one in-flight request (waiting or hashing) for `client`; checked before any global
    /// capacity is touched, so a capped client cannot consume or queue for global slots.
    fn claim(&self, client: Option<ClientKey>) -> Result<Option<KeyGuard>, UserError> {
        let Some(key) = client else {
            return Ok(None);
        };
        let mut keys = self.keys.lock().map_err(|_| UserError::Hash)?;
        let n = keys.entry(key).or_insert(0);
        if *n >= PER_CLIENT_HASHES {
            return Err(UserError::Busy);
        }
        *n += 1;
        Ok(Some(KeyGuard {
            keys: Arc::clone(&self.keys),
            key,
        }))
    }

    /// Takes a slot without waiting, also bounded per `client` when one is given.
    ///
    /// # Errors
    /// [`UserError::Busy`] when the global or the per-client limit is reached.
    pub(crate) fn try_slot(&self, client: Option<ClientKey>) -> Result<HashSlot, UserError> {
        let key = self.claim(client)?;
        let permit = Arc::clone(&self.sem)
            .try_acquire_owned()
            .map_err(|_| UserError::Busy)?;
        Ok(HashSlot {
            _permit: permit,
            _key: key,
        })
    }

    /// Like [`HashGate::try_slot`] but queues on the (fair) semaphore for up to `wait`. At most
    /// [`PER_CLIENT_HASHES`] requests per client and [`MAX_WAITERS`] in total are ever parked;
    /// beyond that the answer is an immediate [`UserError::Busy`].
    ///
    /// # Errors
    /// [`UserError::Busy`] when a cap is hit or no slot became free in time.
    pub(crate) async fn slot(
        &self,
        client: ClientKey,
        wait: Duration,
    ) -> Result<HashSlot, UserError> {
        let key = self.claim(Some(client))?;
        let _waiting = WaitGuard::enter(&self.waiters)?;
        let permit = tokio::time::timeout(wait, Arc::clone(&self.sem).acquire_owned())
            .await
            .map_err(|_| UserError::Busy)?
            .map_err(|_| UserError::Hash)?;
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;

    fn key(s: &str) -> ClientKey {
        dnsy_core::net::client_key(s.parse().unwrap())
    }

    #[tokio::test]
    async fn one_client_flooding_logins_parks_a_bounded_number_of_waiters() {
        let gate = HashGate::with_permits(1);
        let held = gate.try_slot(None).unwrap();
        let (a, b) = (key("192.0.2.1"), key("192.0.2.2"));
        let wait = Duration::from_secs(30);
        let tasks: Vec<_> = (0..200)
            .map(|_| {
                let gate = gate.clone();
                tokio::spawn(async move { gate.slot(a, wait).await })
            })
            .collect();
        // Everything beyond the client's cap is refused at once, without waiting out `wait`.
        let mut refused = 0;
        let mut parked = Vec::new();
        for t in tasks {
            if t.is_finished()
                || tokio::time::timeout(Duration::from_millis(200), async {
                    while !t.is_finished() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .is_ok()
            {
                assert!(matches!(t.await.unwrap(), Err(UserError::Busy)));
                refused += 1;
            } else {
                parked.push(t);
            }
        }
        assert_eq!(
            parked.len(),
            PER_CLIENT_HASHES,
            "waiters are capped per client"
        );
        assert_eq!(refused, 200 - PER_CLIENT_HASHES);
        assert!(gate.waiters.load(Ordering::Acquire) <= PER_CLIENT_HASHES);
        // Another client queues and is served once capacity frees up; the flood did not use up
        // the global waiter budget.
        let other = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.slot(b, wait).await })
        };
        drop(held);
        // The flooder's parked requests give up (dropping a finished handle drops its slot).
        for t in parked {
            t.abort();
            drop(t);
        }
        let slot = tokio::time::timeout(Duration::from_secs(5), other)
            .await
            .expect("the other client is served")
            .unwrap();
        assert!(slot.is_ok());
    }

    #[tokio::test]
    async fn global_waiters_are_bounded() {
        let gate = HashGate::with_permits(1);
        let _held = gate.try_slot(None).unwrap();
        let mut parked = Vec::new();
        for n in 0..u32::try_from(MAX_WAITERS).unwrap() {
            let (gate, who) = (gate.clone(), key(&format!("198.51.100.{}", n + 1)));
            parked.push(tokio::spawn(async move {
                gate.slot(who, Duration::from_secs(30)).await
            }));
        }
        while gate.waiters.load(Ordering::Acquire) < MAX_WAITERS {
            tokio::task::yield_now().await;
        }
        let r = gate.slot(key("203.0.113.1"), Duration::from_secs(30)).await;
        assert!(matches!(r, Err(UserError::Busy)));
        for t in parked {
            t.abort();
        }
    }
}
