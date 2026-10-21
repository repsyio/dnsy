//! User management (admin only).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use dnsy_auth::User;
use dnsy_core::{Role, UserId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::{AdminScope, RequireScope};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

/// Shortest accepted password.
pub(super) const MIN_PASSWORD_LEN: usize = 8;

pub(super) fn check_password(password: &str) -> Result<(), ApiError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::BadRequest(format!(
            "the password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    Ok(())
}

/// A user account. Never carries password material.
#[derive(Serialize, ToSchema)]
pub struct UserInfo {
    pub id: i64,
    pub username: String,
    /// `admin`, `operator` or `viewer`.
    #[schema(value_type = String, example = "viewer")]
    pub role: Role,
    /// Unix seconds.
    pub created_at: i64,
    /// A disabled user cannot log in and their tokens are refused.
    pub disabled: bool,
    /// Unix seconds when the user was disabled.
    pub disabled_at: Option<i64>,
}

impl From<User> for UserInfo {
    fn from(u: User) -> Self {
        UserInfo {
            id: u.id.0,
            username: u.username,
            role: u.role,
            created_at: u.created_at,
            disabled: u.disabled_at.is_some(),
            disabled_at: u.disabled_at,
        }
    }
}

/// New user.
#[derive(Deserialize, ToSchema)]
pub struct CreateUser {
    pub username: String,
    /// At least 8 characters.
    pub password: String,
    #[schema(value_type = String, example = "viewer")]
    pub role: Role,
}

/// Fields to change; absent fields stay as they are.
#[derive(Deserialize, ToSchema)]
pub struct UpdateUser {
    /// Changing the role ends all of the user's sessions.
    #[schema(value_type = Option<String>, example = "operator")]
    pub role: Option<Role>,
    /// Reset the password (at least 8 characters); ends all of the user's sessions.
    pub password: Option<String>,
    /// `true` disables the user (sessions end at once, tokens are refused, login fails);
    /// `false` enables them again. The last active admin cannot be disabled.
    pub disabled: Option<bool>,
}

/// Routes relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_users, create_user))
        .routes(routes!(get_user, update_user, delete_user))
}

/// List all users.
#[utoipa::path(get, path = "/users", tag = "users", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, description = "Users", body = Vec<UserInfo>),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn list_users(
    _: RequireScope<AdminScope>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<UserInfo>>, ApiError> {
    let users = state.users.list().await?;
    Ok(Json(users.into_iter().map(UserInfo::from).collect()))
}

/// Create a user.
#[utoipa::path(post, path = "/users", tag = "users", security(("bearer" = []), ("session" = [])),
    request_body = CreateUser,
    responses(
        (status = 201, description = "Created", body = UserInfo),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Username taken", body = Problem, content_type = "application/problem+json"),
    ))]
async fn create_user(
    _: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Json(body): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserInfo>), ApiError> {
    check_password(&body.password)?;
    let user = state
        .users
        .create(&body.username, &body.password, body.role)
        .await?;
    Ok((StatusCode::CREATED, Json(user.into())))
}

/// Get one user.
#[utoipa::path(get, path = "/users/{id}", tag = "users", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "User id")),
    responses(
        (status = 200, body = UserInfo),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn get_user(
    _: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<UserInfo>, ApiError> {
    Ok(Json(state.users.get(UserId(id)).await?.into()))
}

/// Change a user's role, reset the password, and/or disable or enable the user.
#[utoipa::path(patch, path = "/users/{id}", tag = "users", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "User id")),
    request_body = UpdateUser,
    responses(
        (status = 200, body = UserInfo),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Would demote or disable the last active admin", body = Problem, content_type = "application/problem+json"),
    ))]
async fn update_user(
    _: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateUser>,
) -> Result<Json<UserInfo>, ApiError> {
    let id = UserId(id);
    if let Some(password) = &body.password {
        check_password(password)?;
    }
    // Validate existence and the last-admin rule before touching the password.
    let mut user = state.users.get(id).await?;
    if let Some(role) = body.role {
        user = state.users.update_role(id, role).await?;
    }
    if let Some(disabled) = body.disabled {
        user = state.users.set_disabled(id, disabled).await?;
    }
    if let Some(password) = &body.password {
        state.users.set_password(id, password).await?;
    }
    Ok(Json(user.into()))
}

/// Delete a user. Their tokens and sessions go with them. The last active admin cannot be
/// deleted.
#[utoipa::path(delete, path = "/users/{id}", tag = "users", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "User id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Last admin", body = Problem, content_type = "application/problem+json"),
    ))]
async fn delete_user(
    _: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.users.delete(UserId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}
