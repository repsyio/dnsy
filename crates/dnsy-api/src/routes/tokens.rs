//! API tokens: create (secret shown once), list, revoke.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use dnsy_auth::TokenMeta;
use dnsy_core::{Role, Scope, TokenId};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::{AuthMethod, AuthUser, Read, RequireScope};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

/// Token metadata. The secret is never part of it.
#[derive(Serialize, ToSchema)]
pub struct TokenInfo {
    pub id: i64,
    /// Owner.
    pub user_id: i64,
    pub name: String,
    /// Subset of `dns:query`, `api:read`, `api:write`, `admin`.
    #[schema(value_type = Vec<String>)]
    pub scopes: Vec<Scope>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked: bool,
}

impl From<TokenMeta> for TokenInfo {
    fn from(m: TokenMeta) -> Self {
        TokenInfo {
            id: m.id.0,
            user_id: m.user.0,
            name: m.name,
            scopes: m.scopes,
            created_at: m.created_at,
            expires_at: m.expires_at,
            last_used_at: m.last_used_at,
            revoked: m.revoked,
        }
    }
}

/// New token for the caller.
#[derive(Deserialize, ToSchema)]
pub struct CreateToken {
    pub name: String,
    /// Must be allowed by the caller's role.
    #[schema(value_type = Vec<String>)]
    pub scopes: Vec<Scope>,
    /// Unix seconds; omit for a token that does not expire.
    pub expires_at: Option<i64>,
}

/// The only response that contains the token secret.
#[derive(Serialize, ToSchema)]
pub struct CreatedToken {
    /// The secret. Store it now; it cannot be retrieved again.
    pub token: String,
    pub meta: TokenInfo,
}

/// Routes relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_tokens, create_token))
        .routes(routes!(revoke_token))
}

/// List the caller's tokens; admins see everyone's.
#[utoipa::path(get, path = "/tokens", tag = "tokens", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = Vec<TokenInfo>),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    ))]
async fn list_tokens(
    scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<TokenInfo>>, ApiError> {
    let mut out = Vec::new();
    if scope.0.role == Role::Admin {
        for user in state.users.list().await? {
            out.extend(state.tokens.list(user.id).await?);
        }
    } else {
        out = state.tokens.list(scope.0.user).await?;
    }
    Ok(Json(out.into_iter().map(TokenInfo::from).collect()))
}

/// Create a token for the caller. Needs a session, so a token cannot mint tokens.
#[utoipa::path(post, path = "/tokens", tag = "tokens", security(("session" = [])),
    request_body = CreateToken,
    responses(
        (status = 201, description = "Created; the secret is in this response only", body = CreatedToken),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 403, description = "Not a session, or a scope the role does not allow", body = Problem, content_type = "application/problem+json"),
    ))]
async fn create_token(
    scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Json(body): Json<CreateToken>,
) -> Result<(StatusCode, Json<CreatedToken>), ApiError> {
    if scope.0.method != AuthMethod::Session {
        return Err(ApiError::Forbidden(
            "tokens can only be created from a session",
        ));
    }
    if body.name.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "the token name must not be empty".to_owned(),
        ));
    }
    if body.scopes.is_empty() {
        return Err(ApiError::BadRequest(
            "at least one scope is required".to_owned(),
        ));
    }
    let (token, meta) = state
        .tokens
        .create(scope.0.user, &body.name, &body.scopes, body.expires_at)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedToken {
            token,
            meta: meta.into(),
        }),
    ))
}

/// Revoke a token (own tokens; admins any).
#[utoipa::path(delete, path = "/tokens/{id}", tag = "tokens", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "Token id")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn revoke_token(
    scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let id = TokenId(id);
    if !owns(&state, &scope.0, id).await? {
        return Err(ApiError::NotFound("token not found".to_owned()));
    }
    state.tokens.revoke(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Admins own every token; others only their own. Unknown ids answer false for them.
async fn owns(state: &ApiState, me: &AuthUser, id: TokenId) -> Result<bool, ApiError> {
    if me.role == Role::Admin {
        return Ok(true);
    }
    Ok(state.tokens.list(me.user).await?.iter().any(|t| t.id == id))
}
