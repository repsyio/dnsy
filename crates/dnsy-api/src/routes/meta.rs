//! Health, readiness and version.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::{ApiError, Problem};
use crate::state::ApiState;

/// Liveness/readiness answer.
#[derive(Serialize, ToSchema)]
pub struct Status {
    /// `ok` or `ready`.
    pub status: &'static str,
}

/// Build information.
#[derive(Serialize, ToSchema)]
pub struct Version {
    /// `dnsy` crate version.
    pub version: &'static str,
}

/// Unauthenticated probes, mounted at the root.
#[must_use]
pub fn root_router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(healthz))
        .routes(routes!(readyz))
}

/// Routes relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new().routes(routes!(version))
}

/// The process is up.
#[utoipa::path(get, path = "/healthz", tag = "meta",
    responses((status = 200, description = "Alive", body = Status)))]
async fn healthz() -> Json<Status> {
    Json(Status { status: "ok" })
}

/// The process can serve requests (the database answers).
#[utoipa::path(get, path = "/readyz", tag = "meta",
    responses(
        (status = 200, description = "Ready", body = Status),
        (status = 503, description = "Not ready", body = Problem, content_type = "application/problem+json"),
    ))]
async fn readyz(State(state): State<ApiState>) -> Result<Json<Status>, ApiError> {
    state
        .store
        .read(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?))
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(Json(Status { status: "ready" }))
}

/// The server version.
#[utoipa::path(get, path = "/version", tag = "meta",
    responses((status = 200, description = "Version", body = Version)))]
async fn version() -> Json<Version> {
    Json(Version {
        version: env!("CARGO_PKG_VERSION"),
    })
}
