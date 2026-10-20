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
