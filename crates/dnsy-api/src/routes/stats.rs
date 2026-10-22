//! Stats: summary, timeseries and top lists over the query-log rollups.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use dnsy_observe::{ObserveError, StatsService, TimeRange, redact_client_ip};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::querylog::{Params, check_ms, scrub};
use crate::auth::{Read, RequireScope};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

const DEFAULT_RANGE_MS: i64 = 24 * 3600 * 1000;
const MAX_RANGE_MS: i64 = 366 * 24 * 3600 * 1000;
const DEFAULT_BUCKET_S: u64 = 3600;
const MAX_BUCKET_S: u64 = 366 * 24 * 3600;
const MAX_POINTS: i64 = 5000;
const DEFAULT_TOP: usize = 10;
const MAX_TOP: usize = 100;

/// Routes relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(summary))
        .routes(routes!(timeseries))
        .routes(routes!(top_domains))
        .routes(routes!(top_blocked))
        .routes(routes!(top_clients))
        .routes(routes!(dashboard))
}

/// Time range. Rollups are minute (counters) or hour (top lists) granular, so buckets that
/// touch the range are included whole.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RangeParams {
    /// Inclusive start, unix milliseconds (default: `to` minus 24 hours).
    from: Option<i64>,
    /// Exclusive end, unix milliseconds (default: now).
    to: Option<i64>,
}

// `serde(flatten)` cannot carry numbers in a query string, so the range fields are repeated.
/// Timeseries parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SeriesParams {
    /// Inclusive start, unix milliseconds (default: `to` minus 24 hours).
    from: Option<i64>,
    /// Exclusive end, unix milliseconds (default: now).
    to: Option<i64>,
    /// Bucket width in seconds, a multiple of 60 (default 3600).
    bucket: Option<u64>,
}

/// Top-list parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TopParams {
    /// Inclusive start, unix milliseconds (default: `to` minus 24 hours).
    from: Option<i64>,
    /// Exclusive end, unix milliseconds (default: now).
    to: Option<i64>,
    /// Number of entries, 1 to 100 (default 10).
    limit: Option<usize>,
}

/// Aggregate over the range.
#[derive(Debug, Serialize, ToSchema)]
pub struct SummaryBody {
    pub from: i64,
    pub to: i64,
    pub total: u64,
    /// Answers blocked by a blocklist or rule.
    pub blocked: u64,
    /// `blocked / total`, 0 when there are no queries.
    pub blocked_ratio: f64,
    /// Response code number to count.
    pub by_rcode: BTreeMap<String, u64>,
    /// Answer source to count.
    pub by_source: BTreeMap<String, u64>,
    /// DNSSEC status (`unchecked`, `secure`, `insecure`, `bogus`, `indeterminate`) to count.
    pub dnssec: BTreeMap<String, u64>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_hit_ratio: f64,
    pub stale_answers: u64,
    /// Upstream and overall latency, microseconds.
    pub avg_latency_us: u64,
    pub max_latency_us: u64,
    /// Query-log events lost since the server started: the channel was full or a batch failed to
    /// write. Not limited to the requested range.
    pub querylog_dropped: u64,
    /// Query-log batches that failed to write since the server started.
    pub querylog_flush_errors: u64,
}

/// One timeseries bucket.
#[derive(Debug, Serialize, ToSchema)]
pub struct SeriesPoint {
    pub start_ms: i64,
    pub total: u64,
    pub blocked: u64,
    pub cache_hits: u64,
    pub max_latency_us: u64,
}

/// A ranked name or address.
#[derive(Debug, Serialize, ToSchema)]
pub struct TopItem {
    pub key: String,
    pub count: u64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

fn range(from: Option<i64>, to: Option<i64>) -> Result<TimeRange, ApiError> {
    let to_ms = check_ms("to", to.unwrap_or_else(now_ms))?;
    let from_ms = match from {
        Some(f) => check_ms("from", f)?,
        None => to_ms.saturating_sub(DEFAULT_RANGE_MS).max(0),
    };
    if from_ms >= to_ms {
        return Err(ApiError::BadRequest(
            "`from` must be before `to`".to_owned(),
        ));
    }
    if to_ms.saturating_sub(from_ms) > MAX_RANGE_MS {
        return Err(ApiError::BadRequest(
            "the range must not exceed 366 days".to_owned(),
        ));
    }
    Ok(TimeRange { from_ms, to_ms })
}

fn internal(e: ObserveError) -> ApiError {
    match e {
        ObserveError::InvalidBucket => {
            ApiError::BadRequest("`bucket` must be a non-zero multiple of 60 seconds".to_owned())
        }
        other @ ObserveError::Store(_) => ApiError::Internal(other.to_string()),
    }
}

fn top_limit(limit: Option<usize>) -> Result<usize, ApiError> {
    let n = limit.unwrap_or(DEFAULT_TOP);
    if n == 0 || n > MAX_TOP {
        return Err(ApiError::BadRequest(format!(
            "`limit` must be between 1 and {MAX_TOP}"
        )));
    }
    Ok(n)
}

/// Totals, answer sources, DNSSEC status counts, cache hit ratio, blocked ratio and latency.
#[utoipa::path(get, path = "/stats/summary", tag = "stats", security(("bearer" = []), ("session" = [])),
    params(RangeParams),
    responses(
        (status = 200, body = SummaryBody),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn summary(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Params(p): Params<RangeParams>,
) -> Result<Json<SummaryBody>, ApiError> {
    summary_body(&state, range(p.from, p.to)?).await.map(Json)
}

async fn summary_body(state: &ApiState, range: TimeRange) -> Result<SummaryBody, ApiError> {
    let s = StatsService::new(state.observe.store.clone())
        .summary(range)
        .await
        .map_err(internal)?;
    let lost = dnsy_observe::querylog_counters();
    let blocked = s.by_source.get("blocked").copied().unwrap_or(0);
    #[expect(clippy::cast_precision_loss, reason = "counts far below 2^52")]
    let blocked_ratio = if s.total == 0 {
        0.0
    } else {
        blocked as f64 / s.total as f64
    };
    Ok(SummaryBody {
        from: range.from_ms,
        to: range.to_ms,
        total: s.total,
        blocked,
        blocked_ratio,
        by_rcode: s
            .by_rcode
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        by_source: s.by_source,
        dnssec: s.by_dnssec,
        cache_hits: s.cache_hits,
        cache_misses: s.cache_misses,
        cache_hit_ratio: s.cache_hit_ratio,
        stale_answers: s.stale_answers,
        avg_latency_us: s.avg_latency_us,
        max_latency_us: s.max_latency_us,
        querylog_dropped: lost.dropped,
        querylog_flush_errors: lost.flush_errors,
    })
}

/// Query counts per bucket (only buckets with data), oldest first.
#[utoipa::path(get, path = "/stats/timeseries", tag = "stats", security(("bearer" = []), ("session" = [])),
    params(SeriesParams),
    responses(
        (status = 200, body = Vec<SeriesPoint>),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn timeseries(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Params(p): Params<SeriesParams>,
) -> Result<Json<Vec<SeriesPoint>>, ApiError> {
    series_points(&state, range(p.from, p.to)?, p.bucket)
        .await
        .map(Json)
}

async fn series_points(
    state: &ApiState,
    range: TimeRange,
    bucket: Option<u64>,
) -> Result<Vec<SeriesPoint>, ApiError> {
    let bucket = bucket.unwrap_or(DEFAULT_BUCKET_S);
    if bucket > MAX_BUCKET_S {
        return Err(ApiError::BadRequest(
            "`bucket` must not exceed 366 days".to_owned(),
        ));
    }
    #[expect(clippy::cast_possible_wrap, reason = "bucket is capped at 366 days")]
    let width = bucket.max(1) as i64;
    if (range.to_ms - range.from_ms) / 1000 / width > MAX_POINTS {
        return Err(ApiError::BadRequest(format!(
            "the range holds more than {MAX_POINTS} buckets; use a larger `bucket`"
        )));
    }
    let points = StatsService::new(state.observe.store.clone())
        .timeseries(range, Duration::from_secs(bucket))
        .await
        .map_err(internal)?;
    Ok(points
        .into_iter()
        .map(|t| SeriesPoint {
            start_ms: t.start_ms,
            total: t.total,
            blocked: t.blocked,
            cache_hits: t.cache_hits,
            max_latency_us: t.max_latency_us,
        })
        .collect())
}

fn items(state: &ApiState, v: Vec<dnsy_observe::TopEntry>, clients: bool) -> Vec<TopItem> {
    v.into_iter()
        .map(|t| TopItem {
            key: if clients && state.observe.redact_client_ip {
                // Defence in depth: rollups are written redacted already.
                t.key
                    .parse()
                    .map_or(t.key, |ip| redact_client_ip(ip).to_string())
            } else {
                scrub(&t.key)
            },
            count: t.count,
        })
        .collect()
}

/// Most queried names.
#[utoipa::path(get, path = "/stats/top-domains", tag = "stats", security(("bearer" = []), ("session" = [])),
    params(TopParams),
    responses(
        (status = 200, body = Vec<TopItem>),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn top_domains(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Params(p): Params<TopParams>,
) -> Result<Json<Vec<TopItem>>, ApiError> {
    let (range, n) = (range(p.from, p.to)?, top_limit(p.limit)?);
    top_items(&state, range, n, Top::Domains).await.map(Json)
}

/// Most blocked names.
#[utoipa::path(get, path = "/stats/top-blocked", tag = "stats", security(("bearer" = []), ("session" = [])),
    params(TopParams),
    responses(
        (status = 200, body = Vec<TopItem>),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn top_blocked(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Params(p): Params<TopParams>,
) -> Result<Json<Vec<TopItem>>, ApiError> {
    let (range, n) = (range(p.from, p.to)?, top_limit(p.limit)?);
    top_items(&state, range, n, Top::Blocked).await.map(Json)
}

/// Busiest clients (network addresses when client redaction is on).
#[utoipa::path(get, path = "/stats/top-clients", tag = "stats", security(("bearer" = []), ("session" = [])),
    params(TopParams),
    responses(
        (status = 200, body = Vec<TopItem>),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn top_clients(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Params(p): Params<TopParams>,
) -> Result<Json<Vec<TopItem>>, ApiError> {
    let (range, n) = (range(p.from, p.to)?, top_limit(p.limit)?);
    top_items(&state, range, n, Top::Clients).await.map(Json)
}

#[derive(Clone, Copy)]
enum Top {
    Domains,
    Blocked,
    Clients,
}

async fn top_items(
    state: &ApiState,
    range: TimeRange,
    n: usize,
    kind: Top,
) -> Result<Vec<TopItem>, ApiError> {
    let svc = StatsService::new(state.observe.store.clone());
    let v = match kind {
        Top::Domains => svc.top_domains(range, n).await,
        Top::Blocked => svc.top_blocked(range, n).await,
        Top::Clients => svc.top_clients(range, n).await,
    }
    .map_err(internal)?;
    Ok(items(state, v, matches!(kind, Top::Clients)))
}

/// Dashboard parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DashboardParams {
    /// Inclusive start, unix milliseconds (default: `to` minus 24 hours).
    from: Option<i64>,
    /// Exclusive end, unix milliseconds (default: now).
    to: Option<i64>,
    /// Timeseries bucket width in seconds, a multiple of 60 (default 3600).
    bucket: Option<u64>,
    /// Entries per top list, 1 to 100 (default 10).
    limit: Option<usize>,
}

/// Everything the dashboard shows from the stats rollups, in one response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DashboardBody {
    pub summary: SummaryBody,
    pub series: Vec<SeriesPoint>,
    pub top_domains: Vec<TopItem>,
    pub top_blocked: Vec<TopItem>,
    pub top_clients: Vec<TopItem>,
}

/// Summary, timeseries and the three top lists for one range: the same data as the individual
/// `/stats/*` routes, with the same parameters, limits and read scope.
#[utoipa::path(get, path = "/stats/dashboard", tag = "stats", security(("bearer" = []), ("session" = [])),
    params(DashboardParams),
    responses(
        (status = 200, body = DashboardBody),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn dashboard(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Params(p): Params<DashboardParams>,
) -> Result<Json<DashboardBody>, ApiError> {
    let (range, n) = (range(p.from, p.to)?, top_limit(p.limit)?);
    let (summary, series, top_domains, top_blocked, top_clients) = tokio::try_join!(
        summary_body(&state, range),
        series_points(&state, range, p.bucket),
        top_items(&state, range, n, Top::Domains),
        top_items(&state, range, n, Top::Blocked),
        top_items(&state, range, n, Top::Clients),
    )?;
    Ok(Json(DashboardBody {
        summary,
        series,
        top_domains,
        top_blocked,
        top_clients,
    }))
}
