//! Resolver cache: live stats and flush.

use axum::Json;
use axum::extract::State;
use dnsy_proto::Name;
use dnsy_resolver::Cache;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::querylog::Params;
use crate::auth::{Read, RequireScope, Write};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

/// Routes relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(cache_stats, flush_all))
        .routes(routes!(flush_entries))
}

/// Live cache counters.
#[derive(Debug, Serialize, ToSchema)]
pub struct CacheStatsBody {
    pub entries: u64,
    pub capacity: u64,
    pub hits: u64,
    pub misses: u64,
    /// `hits / (hits + misses)`, 0 before any lookup.
    pub hit_ratio: f64,
    pub inserts: u64,
    pub evictions: u64,
    pub expired: u64,
    pub stale_served: u64,
    pub prefetches: u64,
}

/// Outcome of a flush.
#[derive(Debug, Serialize, ToSchema)]
pub struct Flushed {
    /// Entries removed.
    pub removed: u64,
}

/// Flush-by-name parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FlushParams {
    /// Domain name whose entries are removed.
    name: String,
    /// Also remove everything below the name (default false).
    #[serde(default)]
    subtree: bool,
}

fn cache(state: &ApiState) -> Result<&Cache, ApiError> {
    state.cache.as_deref().ok_or(ApiError::Unavailable)
}

/// Live cache statistics.
#[utoipa::path(get, path = "/cache", tag = "cache", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = CacheStatsBody),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "No cache is running", body = Problem, content_type = "application/problem+json"),
    ))]
async fn cache_stats(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<CacheStatsBody>, ApiError> {
    let s = cache(&state)?.stats();
    #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
    let hit_ratio = match s.hits + s.misses {
        0 => 0.0,
        n => s.hits as f64 / n as f64,
    };
    Ok(Json(CacheStatsBody {
        entries: s.entries,
        capacity: s.capacity,
        hits: s.hits,
        misses: s.misses,
        hit_ratio,
        inserts: s.inserts,
        evictions: s.evictions,
        expired: s.expired,
        stale_served: s.stale_served,
        prefetches: s.prefetches,
    }))
}

/// Remove every cache entry. Needs `api:write`.
#[utoipa::path(delete, path = "/cache", tag = "cache", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = Flushed),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "No cache is running", body = Problem, content_type = "application/problem+json"),
    ))]
async fn flush_all(
    scope: RequireScope<Write>,
    State(state): State<ApiState>,
) -> Result<Json<Flushed>, ApiError> {
    let removed = cache(&state)?.flush_all() as u64;
    tracing::info!(user = scope.0.user.0, removed, "cache flushed");
    Ok(Json(Flushed { removed }))
}

/// Remove the entries of one name, optionally with its subtree. Needs `api:write`.
#[utoipa::path(delete, path = "/cache/entries", tag = "cache", security(("bearer" = []), ("session" = [])),
    params(FlushParams),
    responses(
        (status = 200, body = Flushed),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "No cache is running", body = Problem, content_type = "application/problem+json"),
    ))]
async fn flush_entries(
    scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Params(p): Params<FlushParams>,
) -> Result<Json<Flushed>, ApiError> {
    let name = Name::from_ascii(&p.name)
        .map_err(|_| ApiError::BadRequest("`name` is not a valid domain name".to_owned()))?
        .to_lowercase();
    let removed = cache(&state)?.flush_name(&name, p.subtree) as u64;
    tracing::info!(user = scope.0.user.0, %name, subtree = p.subtree, removed, "cache entries flushed");
    Ok(Json(Flushed { removed }))
}
