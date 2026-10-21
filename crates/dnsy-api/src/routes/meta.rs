//! Health, readiness and version.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::error::{ApiError, Problem, problem_response};
use crate::state::ApiState;

/// Liveness/readiness answer.
#[derive(Serialize, ToSchema)]
pub struct Status {
    /// `ok` or `ready`.
    pub status: &'static str,
}

/// Readiness answer.
#[derive(Serialize, ToSchema)]
pub struct Ready {
    /// `ready`.
    pub status: &'static str,
    /// Conditions that do not stop serving but need attention. `dnssec_clock_untrusted`: the
    /// system clock is before the build time, so DNSSEC validation is suspended.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<&'static str>,
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
        (status = 200, description = "Ready", body = Ready),
        (status = 503, description = "Not ready: the database does not answer, or a DNSSEC zone cannot be signed (`dnssec_signing_failed`)", body = Problem, content_type = "application/problem+json"),
    ))]
async fn readyz(State(state): State<ApiState>) -> Response {
    if state
        .observe
        .store
        .read(|c| Ok(c.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?))
        .await
        .is_err()
    {
        return ApiError::Unavailable.into_response();
    }
    // A zone whose signing failed (its keys cannot be opened, for instance after a passphrase
    // change that was not carried over to the environment) is not served unsigned: the pod is
    // not ready until an operator fixes it.
    if let Some(zones) = &state.zones.store {
        let failed = zones.signing_failures().len();
        if failed > 0 {
            return problem_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Service unavailable",
                format!(
                    "dnssec_signing_failed: {failed} signed zone(s) cannot be signed; see the log"
                ),
            );
        }
    }
    let mut warnings = Vec::new();
    if state
        .policy
        .as_ref()
        .is_some_and(|p| p.dnssec_clock_untrusted())
    {
        warnings.push("dnssec_clock_untrusted");
    }
    if dnsy_observe::querylog_counters().disk_full {
        warnings.push("querylog_disk_full");
    }
    Json(Ready {
        status: "ready",
        warnings,
    })
    .into_response()
}

/// The server version.
#[utoipa::path(get, path = "/version", tag = "meta",
    responses((status = 200, description = "Version", body = Version)))]
async fn version() -> Json<Version> {
    Json(Version {
        version: env!("CARGO_PKG_VERSION"),
    })
}
