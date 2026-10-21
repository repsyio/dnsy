//! Blocklist sources (add, remove, enable, refresh, status) and custom block/allow rules.
//!
//! SSRF: a source is either a file path or an http(s) URL. File paths and private, loopback or
//! otherwise non-public targets need `allow_private`, which only a credential with the `admin`
//! scope may set. URL hosts that are names are resolved and pinned at fetch time by
//! `dnsy-filter`, which refuses non-public addresses for every source without `allow_private`.

use std::net::IpAddr;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use dnsy_core::Scope;
use dnsy_filter::{
    BlockMode, FilterLimits, FilterSetBuilder, ListFormat, ListSource, Location, NewSource,
    RefreshError, RefreshOutcome, RuleKind, is_public,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::live::{filter_err, internal, reload_filter};
use crate::auth::{Authenticator, Read, RequireScope, Write};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

const MIN_INTERVAL_SECS: u64 = 60;
const MAX_INTERVAL_SECS: u64 = 30 * 86_400;
const DEFAULT_INTERVAL_SECS: u64 = 86_400;
const MAX_SOURCES: usize = 200;
const MAX_RULES: usize = 10_000;

/// List file format.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Auto,
    Hosts,
    Domains,
    Adblock,
}

impl From<Format> for ListFormat {
    fn from(f: Format) -> Self {
        match f {
            Format::Auto => ListFormat::Auto,
            Format::Hosts => ListFormat::Hosts,
            Format::Domains => ListFormat::Domains,
            Format::Adblock => ListFormat::Adblock,
        }
    }
}

impl From<ListFormat> for Format {
    fn from(f: ListFormat) -> Self {
        match f {
            ListFormat::Auto => Format::Auto,
            ListFormat::Hosts => Format::Hosts,
            ListFormat::Domains => Format::Domains,
            ListFormat::Adblock => Format::Adblock,
        }
    }
}

/// A blocklist source and the status of its last fetch.
#[derive(Serialize, ToSchema)]
pub struct BlocklistView {
    pub id: i64,
    pub name: String,
    /// http(s) URL or file path.
    pub location: String,
    pub format: Format,
    pub enabled: bool,
    pub interval_secs: u64,
    /// Private and loopback targets (and file paths) are allowed for this source.
    pub allow_private: bool,
    /// Unix seconds of the last fetch attempt.
    pub last_fetched: Option<i64>,
    /// Outcome of the last fetch attempt.
    pub last_status: Option<String>,
    /// Entries loaded from the last successful fetch.
    pub entries: u64,
}

impl From<ListSource> for BlocklistView {
    fn from(s: ListSource) -> Self {
        BlocklistView {
            id: s.id,
            name: s.name,
            location: s.location,
            format: s.format.into(),
            enabled: s.enabled,
            interval_secs: s.interval_secs,
            allow_private: s.allow_private,
            last_fetched: s.last_fetched,
            last_status: s.last_status,
            entries: s.entries,
        }
    }
}

/// New source.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateBlocklist {
    /// Unique, 1 to 128 characters.
    pub name: String,
    /// `http://` or `https://` URL, or a file path (file paths need the `admin` scope).
    pub location: String,
    pub format: Option<Format>,
    /// Default true.
    pub enabled: Option<bool>,
    /// Seconds between refreshes, 60 to 2,592,000; default 86,400.
    pub interval_secs: Option<u64>,
    /// Allow private, loopback and link-local targets. Needs the `admin` scope.
    #[serde(default)]
    pub allow_private: bool,
}

/// Fields of a source that can change.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchBlocklist {
    pub enabled: bool,
}

/// Result of a manual refresh.
#[derive(Serialize, ToSchema)]
pub struct RefreshResult {
    /// `updated` or `not_modified`.
    pub outcome: String,
    /// Block plus allow entries now loaded (only when `updated`).
    pub entries: Option<u64>,
}

/// Custom rule kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKindView {
    Block,
    Allow,
}

/// A custom rule: the domain and everything below it. Allow beats block.
#[derive(Serialize, ToSchema)]
pub struct RuleView {
    pub id: i64,
    pub kind: RuleKindView,
    pub domain: String,
}

/// New custom rule.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRule {
    pub kind: RuleKindView,
    /// Domain name, e.g. `ads.example.com`; subdomains match too.
    pub domain: String,
}

/// Routes of this group, relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_blocklists, create_blocklist))
        .routes(routes!(patch_blocklist, delete_blocklist))
        .routes(routes!(refresh_blocklist))
        .routes(routes!(list_rules, create_rule))
        .routes(routes!(delete_rule))
}

/// The location needs the `admin` scope: a file path or a non-public IP literal or `localhost`.
fn needs_private(location: &str) -> Result<bool, ApiError> {
    match Location::parse(location).map_err(|e| ApiError::Unprocessable(e.to_string()))? {
        Location::File(_) => Ok(true),
        Location::Url(url) => {
            let host = url
                .host_str()
                .unwrap_or_default()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            Ok(match host.parse::<IpAddr>() {
                Ok(ip) => !is_public(ip),
                Err(_) => host.is_empty() || host == "localhost" || host.ends_with(".localhost"),
            })
        }
    }
}

#[utoipa::path(get, path = "/blocklists", tag = "blocklists", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = Vec<BlocklistView>),
        (status = 401, body = Problem, content_type = "application/problem+json"),
    ))]
async fn list_blocklists(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<BlocklistView>>, ApiError> {
    let sources = state.stores.sources.list().await.map_err(filter_err)?;
    Ok(Json(sources.into_iter().map(Into::into).collect()))
}

#[utoipa::path(post, path = "/blocklists", tag = "blocklists", security(("bearer" = []), ("session" = [])),
    request_body = CreateBlocklist,
    responses(
        (status = 201, description = "Created", body = BlocklistView),
        (status = 403, description = "A file path or private target needs the admin scope", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Name or location exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid source or SSRF target refused", body = Problem, content_type = "application/problem+json"),
    ))]
async fn create_blocklist(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<CreateBlocklist>,
) -> Result<(StatusCode, Json<BlocklistView>), ApiError> {
    super::live::require_policy(&state)?;
    let interval = req.interval_secs.unwrap_or(DEFAULT_INTERVAL_SECS);
    if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&interval) {
        return Err(ApiError::Unprocessable(format!(
            "interval_secs must be between {MIN_INTERVAL_SECS} and {MAX_INTERVAL_SECS}"
        )));
    }
    let private_target = needs_private(&req.location)?;
    if req.allow_private || private_target {
        Authenticator::new(&state)
            .authenticate(&headers, &Method::POST, Scope::Admin)
            .await
            .map_err(|e| match e {
                ApiError::Forbidden(_) => ApiError::Forbidden(
                    "file paths, private targets and allow_private need the admin scope",
                ),
                other => other,
            })?;
        if !req.allow_private {
            return Err(ApiError::Unprocessable(
                "target is not public; set allow_private to use it".to_owned(),
            ));
        }
    }
    if state.stores.sources.list().await.map_err(filter_err)?.len() >= MAX_SOURCES {
        return Err(ApiError::Unprocessable("too many blocklists".to_owned()));
    }
    let enabled = req.enabled.unwrap_or(true);
    let id = state
        .stores
        .sources
        .add(NewSource {
            name: req.name,
            location: req.location,
            format: req.format.unwrap_or(Format::Auto).into(),
            enabled,
            interval_secs: interval,
            allow_private: req.allow_private,
        })
        .await
        .map_err(filter_err)?;
    if enabled
        && let Some(manager) = &state.lists
        && let Err(e) = manager.refresh_source(id).await
    {
        // A failed fetch shows in `last_status`; the source stays and the scheduler retries.
        tracing::warn!(id, error = %e, "initial blocklist fetch failed");
    }
    let source = state
        .stores
        .sources
        .list()
        .await
        .map_err(filter_err)?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| internal("created source vanished"))?;
    Ok((StatusCode::CREATED, Json(source.into())))
}

#[utoipa::path(patch, path = "/blocklists/{id}", tag = "blocklists", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "Source id")),
    request_body = PatchBlocklist,
    responses(
        (status = 200, body = BlocklistView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn patch_blocklist(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    Json(req): Json<PatchBlocklist>,
) -> Result<Json<BlocklistView>, ApiError> {
    let _guard = state.apply_lock.lock().await;
    super::live::require_policy(&state)?;
    state
        .stores
        .sources
        .set_enabled(id, req.enabled)
        .await
        .map_err(filter_err)?;
    reload_filter(&state).await?;
    if req.enabled {
        // Disabling dropped the list's loaded content; fetch it again now instead of
        // leaving the list empty until the scheduler next wakes up. A failed fetch shows in
        // `last_status` and keeps the previous (empty) state.
        if let Some(manager) = &state.lists
            && let Err(e) = manager.refresh_source(id).await
        {
            tracing::warn!(id, error = %e, "fetching a re-enabled blocklist failed");
        }
    }
    let source = state
        .stores
        .sources
        .list()
        .await
        .map_err(filter_err)?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| ApiError::NotFound("blocklist not found".to_owned()))?;
    Ok(Json(source.into()))
}

#[utoipa::path(delete, path = "/blocklists/{id}", tag = "blocklists", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "Source id")),
    responses(
        (status = 204, description = "Deleted; its entries leave the filter"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn delete_blocklist(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let _guard = state.apply_lock.lock().await;
    super::live::require_policy(&state)?;
    state.stores.sources.delete(id).await.map_err(filter_err)?;
    reload_filter(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/blocklists/{id}/refresh", tag = "blocklists", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "Source id")),
    responses(
        (status = 200, body = RefreshResult),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "The fetch failed; the previous list stays active", body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "No blocklist manager is running", body = Problem, content_type = "application/problem+json"),
    ))]
async fn refresh_blocklist(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<Json<RefreshResult>, ApiError> {
    let manager = state.lists.as_ref().ok_or(ApiError::Unavailable)?;
    match manager.refresh_source(id).await {
        Ok(RefreshOutcome::Updated { entries }) => Ok(Json(RefreshResult {
            outcome: "updated".to_owned(),
            entries: Some(entries),
        })),
        Ok(RefreshOutcome::NotModified) => Ok(Json(RefreshResult {
            outcome: "not_modified".to_owned(),
            entries: None,
        })),
        Err(RefreshError::NotFound) => Err(ApiError::NotFound("blocklist not found".to_owned())),
        Err(RefreshError::Task | RefreshError::Store(_)) => Err(internal("refresh failed")),
        Err(e) => Err(ApiError::Unprocessable(format!("refresh failed: {e}"))),
    }
}

/// Validates through the same builder that applies rules and returns the stored spelling.
fn normalize_domain(domain: &str) -> Result<String, ApiError> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let mut probe = FilterSetBuilder::new(BlockMode::NullIp, FilterLimits::default());
    if d.is_empty() || d.len() > 253 || probe.add_block_rule(&d).is_err() {
        return Err(ApiError::Unprocessable(
            "not a valid domain name".to_owned(),
        ));
    }
    Ok(d)
}

fn kind_of(k: RuleKind) -> RuleKindView {
    match k {
        RuleKind::Block => RuleKindView::Block,
        RuleKind::Allow => RuleKindView::Allow,
    }
}

#[utoipa::path(get, path = "/rules", tag = "rules", security(("bearer" = []), ("session" = [])),
    responses((status = 200, body = Vec<RuleView>)))]
async fn list_rules(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<RuleView>>, ApiError> {
    let rules = state
        .stores
        .sources
        .custom_rules_with_ids()
        .await
        .map_err(filter_err)?;
    Ok(Json(
        rules
            .into_iter()
            .map(|r| RuleView {
                id: r.id,
                kind: kind_of(r.kind),
                domain: r.domain,
            })
            .collect(),
    ))
}

#[utoipa::path(post, path = "/rules", tag = "rules", security(("bearer" = []), ("session" = [])),
    request_body = CreateRule,
    responses(
        (status = 201, description = "Created and active", body = RuleView),
        (status = 409, body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ))]
async fn create_rule(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Json(req): Json<CreateRule>,
) -> Result<(StatusCode, Json<RuleView>), ApiError> {
    let domain = normalize_domain(&req.domain)?;
    let kind = match req.kind {
        RuleKindView::Block => RuleKind::Block,
        RuleKindView::Allow => RuleKind::Allow,
    };
    let _guard = state.apply_lock.lock().await;
    super::live::require_policy(&state)?;
    let existing = state
        .stores
        .sources
        .custom_rules_with_ids()
        .await
        .map_err(filter_err)?;
    if existing.len() >= MAX_RULES {
        return Err(ApiError::Unprocessable("too many rules".to_owned()));
    }
    let id = state
        .stores
        .sources
        .add_custom_rule(kind, &domain)
        .await
        .map_err(filter_err)?;
    reload_filter(&state).await?;
    Ok((
        StatusCode::CREATED,
        Json(RuleView {
            id,
            kind: req.kind,
            domain,
        }),
    ))
}

#[utoipa::path(delete, path = "/rules/{id}", tag = "rules", security(("bearer" = []), ("session" = [])),
    params(("id" = i64, Path, description = "Rule id")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn delete_rule(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let _guard = state.apply_lock.lock().await;
    super::live::require_policy(&state)?;
    state
        .stores
        .sources
        .delete_custom_rule(id)
        .await
        .map_err(filter_err)?;
    reload_filter(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}
