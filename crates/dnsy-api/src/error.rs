//! RFC 9457 `application/problem+json` errors.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use dnsy_auth::{AuthError, UserError};
use serde::Serialize;
use utoipa::ToSchema;

/// Media type of every API error body.
pub const PROBLEM_JSON: &str = "application/problem+json";

const TYPE_BASE: &str = "https://dnsy.dev/problems/";

/// RFC 9457 problem document.
#[derive(Debug, Serialize, ToSchema)]
pub struct Problem {
    /// URI identifying the problem type.
    #[serde(rename = "type")]
    pub type_: String,
    /// Short, human-readable summary of the problem type.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Explanation specific to this occurrence. Never contains secrets.
    pub detail: String,
    /// Seconds to wait before retrying (only on 429).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

/// Every failure a handler or extractor can return.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("authentication required")]
    Unauthorized,
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    PreconditionFailed(String),
    #[error("{0}")]
    Unprocessable(String),
    #[error("too many failed logins, retry in {retry_after_secs}s")]
    Throttled { retry_after_secs: u64 },
    #[error("service unavailable")]
    Unavailable,
    /// Details are logged, never sent to the client.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, &'static str) {
        match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "Unauthorized"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden", "Forbidden"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad-request", "Bad request"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "not-found", "Not found"),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "conflict", "Conflict"),
            ApiError::PreconditionFailed(_) => (
                StatusCode::PRECONDITION_FAILED,
                "precondition-failed",
                "Precondition failed",
            ),
            ApiError::Unprocessable(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "unprocessable",
                "Unprocessable content",
            ),
            ApiError::Throttled { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "too-many-requests",
                "Too many requests",
            ),
            ApiError::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Service unavailable",
            ),
            ApiError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "Internal server error",
            ),
        }
    }

    fn problem(&self) -> Problem {
        let (status, slug, title) = self.parts();
        let detail = match self {
            ApiError::Internal(_) => "an internal error occurred".to_owned(),
            other => other.to_string(),
        };
        Problem {
            type_: format!("{TYPE_BASE}{slug}"),
            title: title.to_owned(),
            status: status.as_u16(),
            detail,
            retry_after_secs: match self {
                ApiError::Throttled { retry_after_secs } => Some(*retry_after_secs),
                _ => None,
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(msg) = &self {
            tracing::error!(error = %msg, "internal API error");
        }
        let (status, ..) = self.parts();
        let problem = self.problem();
        let mut res = (status, Json(problem)).into_response();
        res.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(PROBLEM_JSON));
        match self {
            ApiError::Unauthorized => {
                res.headers_mut()
                    .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            }
            ApiError::Throttled { retry_after_secs } => {
                res.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
            }
            _ => {}
        }
        res
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::InvalidToken | AuthError::InvalidSession => ApiError::Unauthorized,
            AuthError::MissingScope | AuthError::ScopeNotAllowed => {
                ApiError::Forbidden("the credential lacks the required scope")
            }
            AuthError::UserNotFound => ApiError::NotFound("user not found".to_owned()),
            AuthError::TokenNotFound => ApiError::NotFound("token not found".to_owned()),
            AuthError::Throttled { retry_after_secs } => ApiError::Throttled { retry_after_secs },
            AuthError::User(u) => u.into(),
            AuthError::Store(s) => ApiError::Internal(s.to_string()),
        }
    }
}

impl From<UserError> for ApiError {
    fn from(e: UserError) -> Self {
        match e {
            UserError::Empty => ApiError::BadRequest(e.to_string()),
            UserError::DuplicateUsername | UserError::LastAdmin => {
                ApiError::Conflict(e.to_string())
            }
            UserError::NotFound => ApiError::NotFound(e.to_string()),
            UserError::InvalidCredentials | UserError::InvalidBootstrapCode => {
                ApiError::Unauthorized
            }
            UserError::Hash | UserError::Store(_) => ApiError::Internal(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_maps_to_429_with_retry_after() {
        let err: ApiError = AuthError::Throttled {
            retry_after_secs: 42,
        }
        .into();
        let res = err.into_response();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(res.headers()[header::RETRY_AFTER], "42");
        assert_eq!(res.headers()[header::CONTENT_TYPE], PROBLEM_JSON);
    }

    #[test]
    fn internal_detail_is_hidden() {
        let p = ApiError::Internal("sqlite exploded".into()).problem();
        assert!(!p.detail.contains("sqlite"));
        assert_eq!(p.status, 500);
    }

    #[test]
    fn auth_and_user_errors_map() {
        let status = |e: ApiError| e.into_response().status();
        assert_eq!(
            status(AuthError::InvalidToken.into()),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(AuthError::MissingScope.into()),
            StatusCode::FORBIDDEN
        );
        assert_eq!(status(UserError::LastAdmin.into()), StatusCode::CONFLICT);
        assert_eq!(status(UserError::NotFound.into()), StatusCode::NOT_FOUND);
        assert_eq!(status(UserError::Empty.into()), StatusCode::BAD_REQUEST);
        assert_eq!(
            status(AuthError::TokenNotFound.into()),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(ApiError::Unavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
