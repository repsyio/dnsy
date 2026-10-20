use dnsy_store::StoreError;

/// Failure of a user or bootstrap operation.
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("username and password must not be empty")]
    Empty,
    #[error("username already exists")]
    DuplicateUsername,
    #[error("user not found")]
    NotFound,
    #[error("the last admin cannot be deleted or demoted")]
    LastAdmin,
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("invalid, expired or already used bootstrap code")]
    InvalidBootstrapCode,
    #[error("password hashing failed")]
    Hash,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Failure of a token, session or login operation.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Malformed, unknown, revoked, expired or mismatching token (deliberately one error).
    #[error("invalid token")]
    InvalidToken,
    #[error("token lacks the required scope")]
    MissingScope,
    #[error("scope is not allowed for the owner's role")]
    ScopeNotAllowed,
    #[error("user not found")]
    UserNotFound,
    #[error("token not found")]
    TokenNotFound,
    #[error("invalid or expired session")]
    InvalidSession,
    /// Too many failed logins; answer 429 with `Retry-After: retry_after_secs`.
    #[error("too many failed logins, retry in {retry_after_secs}s")]
    Throttled { retry_after_secs: u64 },
    #[error(transparent)]
    User(#[from] UserError),
    #[error(transparent)]
    Store(#[from] StoreError),
}
