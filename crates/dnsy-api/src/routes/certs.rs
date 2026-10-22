//! mTLS client-certificate fingerprint allowlist for `DoT` (admin only).
//!
//! Every change reloads the server's allowlist through [`ApiState::cert_reload`], which bumps
//! its generation so connections that are already open are re-checked against the new list.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use dnsy_auth::ClientCert;
use dnsy_core::{Clock as _, SystemClock};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::acl::parse_fingerprint;
use super::live::internal;
use crate::auth::{AdminScope, RequireScope};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;
use dnsy_core::hex;

const MAX_LABEL: usize = 128;
const MAX_CERTS: usize = 10_000;

/// An allowed client certificate.
#[derive(Serialize, ToSchema)]
pub struct ClientCertView {
    pub id: i64,
    /// SHA-256 fingerprint of the DER certificate, lowercase hex.
    pub sha256: String,
    pub label: String,
    pub enabled: bool,
    /// Unix seconds; the certificate is refused from then on.
    pub expires_at: Option<i64>,
    pub created_at: i64,
    /// `expires_at` has passed.
    pub expired: bool,
}

impl From<ClientCert> for ClientCertView {
    fn from(c: ClientCert) -> Self {
        ClientCertView {
            id: c.id,
            sha256: hex::lower(&c.sha256),
            label: c.label,
            enabled: c.enabled,
            expired: c.expires_at.is_some_and(|t| t <= SystemClock.unix_secs()),
            expires_at: c.expires_at,
            created_at: c.created_at,
        }
    }
}

/// New allowed certificate.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateClientCert {
    /// SHA-256 fingerprint: 64 hex digits, optionally colon separated.
    pub sha256: String,
    /// 1 to 128 characters.
    pub label: String,
    /// Unix seconds in the future; omit for no expiry.
    pub expires_at: Option<i64>,
}

/// Fields that can change.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchClientCert {
    pub enabled: bool,
}

/// Routes of this group, relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_certs, create_cert))
        .routes(routes!(patch_cert, delete_cert))
}

async fn reload(state: &ApiState) -> Result<(), ApiError> {
    if let Some(reload) = &state.auth.cert_reload {
        reload().await.map_err(internal)?;
    }
    Ok(())
}

#[utoipa::path(get, path = "/client-certs", tag = "client-certs", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = Vec<ClientCertView>),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn list_certs(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<ClientCertView>>, ApiError> {
    let certs = state.auth.client_certs.list().await.map_err(internal)?;
    Ok(Json(certs.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/client-certs", tag = "client-certs", security(("bearer" = []), ("session" = [])),
    request_body = CreateClientCert,
    responses(
        (status = 201, description = "Created and active", body = ClientCertView),
        (status = 409, description = "The fingerprint is already listed", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ))]
async fn create_cert(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Json(req): Json<CreateClientCert>,
) -> Result<(StatusCode, Json<ClientCertView>), ApiError> {
    let sha256 = parse_fingerprint(&req.sha256)?;
    let label = req.label.trim();
    if label.is_empty() || label.chars().count() > MAX_LABEL {
        return Err(ApiError::Unprocessable(format!(
            "label must be 1 to {MAX_LABEL} characters"
        )));
    }
    if req.expires_at.is_some_and(|t| t <= SystemClock.unix_secs()) {
        return Err(ApiError::Unprocessable(
            "expires_at must be in the future".to_owned(),
        ));
    }
    let _guard = state.apply_lock.lock().await;
    super::live::require_cert_reload(&state)?;
    let existing = state.auth.client_certs.list().await.map_err(internal)?;
    if existing.iter().any(|c| c.sha256 == sha256) {
        return Err(ApiError::Conflict(
            "the fingerprint is already listed".to_owned(),
        ));
    }
    if existing.len() >= MAX_CERTS {
        return Err(ApiError::Unprocessable("too many certificates".to_owned()));
    }
    let cert = state
        .auth
        .client_certs
        .add(sha256, label, req.expires_at)
        .await
        .map_err(internal)?;
    reload(&state).await?;
    Ok((StatusCode::CREATED, Json(cert.into())))
}

#[utoipa::path(patch, path = "/client-certs/{id}", tag = "client-certs", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "Certificate id")),
    request_body = PatchClientCert,
    responses(
        (status = 200, body = ClientCertView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn patch_cert(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    Json(req): Json<PatchClientCert>,
) -> Result<Json<ClientCertView>, ApiError> {
    let _guard = state.apply_lock.lock().await;
    super::live::require_cert_reload(&state)?;
    if !state
        .auth
        .client_certs
        .set_enabled(id, req.enabled)
        .await
        .map_err(internal)?
    {
        return Err(ApiError::NotFound(
            "client certificate not found".to_owned(),
        ));
    }
    reload(&state).await?;
    let cert = state
        .auth
        .client_certs
        .get(id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::NotFound("client certificate not found".to_owned()))?;
    Ok(Json(cert.into()))
}

#[utoipa::path(delete, path = "/client-certs/{id}", tag = "client-certs", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "Certificate id")),
    responses(
        (status = 204, description = "Removed; open connections are re-checked"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn delete_cert(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let _guard = state.apply_lock.lock().await;
    super::live::require_cert_reload(&state)?;
    if !state.auth.client_certs.remove(id).await.map_err(internal)? {
        return Err(ApiError::NotFound(
            "client certificate not found".to_owned(),
        ));
    }
    reload(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}
