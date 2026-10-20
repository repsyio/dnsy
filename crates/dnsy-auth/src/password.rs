use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use argon2::{Algorithm, Argon2, Params, Version};

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

/// Run a CPU-heavy closure off the async executor.
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, UserError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| UserError::Hash)
}
