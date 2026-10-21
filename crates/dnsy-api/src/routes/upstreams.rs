//! Upstream groups, their members and live health. Changes need the `admin` scope (a member
//! is a network target the server will connect to) and swap a validated group set into the
//! running engine; health counters of the rebuilt set start fresh.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use dnsy_resolver::Upstream;
use dnsy_resolver::groups::{GroupMember, GroupSet, GroupSpec, Strategy, UpstreamHealth};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::live::{build_groups, group_store_err};
use crate::auth::{AdminScope, Read, RequireScope};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

const MAX_GROUPS: usize = 64;
const MAX_MEMBERS: usize = 32;
const MAX_DOMAINS: usize = 256;
const MAX_WEIGHT: u32 = 1_000;
const MAX_NAME: usize = 64;

/// How a group orders its members.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StrategyView {
    RoundRobin,
    Weighted,
    LowestLatency,
    Failover,
}

impl From<StrategyView> for Strategy {
    fn from(s: StrategyView) -> Self {
        match s {
            StrategyView::RoundRobin => Strategy::RoundRobin,
            StrategyView::Weighted => Strategy::Weighted,
            StrategyView::LowestLatency => Strategy::LowestLatency,
            StrategyView::Failover => Strategy::Failover,
        }
    }
}

impl From<Strategy> for StrategyView {
    fn from(s: Strategy) -> Self {
        match s {
            Strategy::RoundRobin => StrategyView::RoundRobin,
            Strategy::Weighted => StrategyView::Weighted,
            Strategy::LowestLatency => StrategyView::LowestLatency,
            Strategy::Failover => StrategyView::Failover,
        }
    }
}

/// A member as written by a client.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberInput {
    /// `udp://host[:port]`, `tcp://host[:port]` or `tls://host[:port][#sni]`.
    pub upstream: String,
    /// Used by the `weighted` strategy; 1 to 1000, default 1.
    pub weight: Option<u32>,
}

/// Group definition for create and replace.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupBody {
    pub strategy: StrategyView,
    /// Receives queries no domain pattern matches. Exactly one group is the default.
    #[serde(default)]
    pub default: bool,
    /// Patterns such as `corp.example` or `*.corp.example`.
    #[serde(default)]
    pub domains: Vec<String>,
    pub members: Vec<MemberInput>,
}

/// New group.
#[derive(Deserialize, ToSchema)]
pub struct CreateGroup {
    /// 1 to 64 characters of `[A-Za-z0-9._-]`.
    pub name: String,
    #[serde(flatten)]
    pub body: GroupBody,
}

/// Live state of one member.
#[derive(Serialize, ToSchema)]
pub struct HealthView {
    pub upstream: String,
    /// Not ejected by the passive health check.
    pub available: bool,
    pub consecutive_failures: u32,
    /// Smoothed round-trip time; absent until measured.
    pub latency_ms: Option<f64>,
}

impl From<UpstreamHealth> for HealthView {
    fn from(h: UpstreamHealth) -> Self {
        HealthView {
            upstream: h.upstream.to_string(),
            available: h.available,
            consecutive_failures: h.consecutive_failures,
            latency_ms: h.latency_ewma.map(|d: Duration| d.as_secs_f64() * 1000.0),
        }
    }
}

/// A member of a group.
#[derive(Serialize, ToSchema)]
pub struct MemberView {
    /// Position in the group, for `DELETE /upstream-groups/{name}/upstreams/{index}`.
    pub index: usize,
    pub upstream: String,
    pub weight: u32,
}

/// A group with its members and, when the server is running, their health.
#[derive(Serialize, ToSchema)]
pub struct GroupView {
    pub name: String,
    pub strategy: StrategyView,
    pub default: bool,
    pub domains: Vec<String>,
    pub members: Vec<MemberView>,
    pub health: Option<Vec<HealthView>>,
}

fn view(spec: GroupSpec, live: Option<&GroupSet>) -> GroupView {
    let health = live
        .and_then(|g| g.health(&spec.name))
        .map(|h| h.into_iter().map(Into::into).collect());
    GroupView {
        strategy: spec.strategy.into(),
        default: spec.default,
        domains: spec.domains,
        members: spec
            .members
            .into_iter()
            .enumerate()
            .map(|(index, m)| MemberView {
                index,
                upstream: m.upstream.to_string(),
                weight: m.weight,
            })
            .collect(),
        health,
        name: spec.name,
    }
}

fn live(state: &ApiState) -> Option<Arc<GroupSet>> {
    state.live_groups.as_ref().and_then(|g| g.load_full())
}

fn parse_member(m: &MemberInput) -> Result<GroupMember, ApiError> {
    let upstream: Upstream = m
        .upstream
        .parse()
        .map_err(|_| ApiError::Unprocessable("invalid upstream address".to_owned()))?;
    let weight = m.weight.unwrap_or(1);
    if !(1..=MAX_WEIGHT).contains(&weight) {
        return Err(ApiError::Unprocessable(format!(
            "weight must be between 1 and {MAX_WEIGHT}"
        )));
    }
    Ok(GroupMember { upstream, weight })
}

fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn spec_of(name: &str, body: GroupBody) -> Result<GroupSpec, ApiError> {
    if !valid_name(name) {
        return Err(ApiError::Unprocessable(
            "name must be 1 to 64 characters of letters, digits, '.', '_' and '-'".to_owned(),
        ));
    }
    if body.members.is_empty() || body.members.len() > MAX_MEMBERS {
        return Err(ApiError::Unprocessable(format!(
            "a group needs 1 to {MAX_MEMBERS} members"
        )));
    }
    if body.domains.len() > MAX_DOMAINS {
        return Err(ApiError::Unprocessable(
            "too many domain patterns".to_owned(),
        ));
    }
    Ok(GroupSpec {
        name: name.to_owned(),
        strategy: body.strategy.into(),
        default: body.default,
        domains: body.domains,
        members: body
            .members
            .iter()
            .map(parse_member)
            .collect::<Result<_, _>>()?,
    })
}

/// Validates `specs`, stores `spec` and swaps the new set into the engine.
async fn commit(
    state: &ApiState,
    mut specs: Vec<GroupSpec>,
    changed: Option<GroupSpec>,
    deleted: Option<&str>,
) -> Result<(), ApiError> {
    if let Some(name) = deleted {
        specs.retain(|s| s.name != name);
    }
    if let Some(spec) = &changed {
        if spec.default {
            for s in &mut specs {
                s.default = false;
            }
        }
        specs.retain(|s| s.name != spec.name);
        specs.push(spec.clone());
        specs.sort_by(|a, b| a.name.cmp(&b.name));
    }
    let set = build_groups(specs)?;
    if let Some(spec) = &changed {
        state.groups.put(spec).await.map_err(group_store_err)?;
    }
    if let Some(name) = deleted {
        state.groups.delete(name).await.map_err(group_store_err)?;
    }
    if let Some(engine) = &state.engine {
        engine.set_groups(set);
    }
    Ok(())
}

/// Routes of this group, relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_groups, create_group))
        .routes(routes!(get_group, replace_group, delete_group))
        .routes(routes!(add_member))
        .routes(routes!(remove_member))
        .routes(routes!(group_health))
}

async fn find(state: &ApiState, name: &str) -> Result<(Vec<GroupSpec>, GroupSpec), ApiError> {
    let specs = state.groups.list().await.map_err(group_store_err)?;
    let spec = specs
        .iter()
        .find(|s| s.name == name)
        .cloned()
        .ok_or_else(|| ApiError::NotFound("upstream group not found".to_owned()))?;
    Ok((specs, spec))
}

#[utoipa::path(get, path = "/upstream-groups", tag = "upstreams", security(("bearer" = []), ("session" = [])),
    responses((status = 200, body = Vec<GroupView>)))]
async fn list_groups(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<GroupView>>, ApiError> {
    let specs = state.groups.list().await.map_err(group_store_err)?;
    let set = live(&state);
    Ok(Json(
        specs.into_iter().map(|s| view(s, set.as_deref())).collect(),
    ))
}

#[utoipa::path(post, path = "/upstream-groups", tag = "upstreams", security(("bearer" = []), ("session" = [])),
    request_body = CreateGroup,
    responses(
        (status = 201, body = GroupView),
        (status = 409, description = "The group exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ))]
async fn create_group(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Json(req): Json<CreateGroup>,
) -> Result<(StatusCode, Json<GroupView>), ApiError> {
    let spec = spec_of(&req.name, req.body)?;
    let _guard = state.apply_lock.lock().await;
    super::live::require_engine(&state)?;
    let specs = state.groups.list().await.map_err(group_store_err)?;
    if specs.iter().any(|s| s.name == spec.name) {
        return Err(ApiError::Conflict("the group exists".to_owned()));
    }
    if specs.len() >= MAX_GROUPS {
        return Err(ApiError::Unprocessable("too many groups".to_owned()));
    }
    commit(&state, specs, Some(spec.clone()), None).await?;
    Ok((
        StatusCode::CREATED,
        Json(view(spec, live(&state).as_deref())),
    ))
}

#[utoipa::path(get, path = "/upstream-groups/{name}", tag = "upstreams", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Group name")),
    responses(
        (status = 200, body = GroupView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn get_group(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<GroupView>, ApiError> {
    let (_, spec) = find(&state, &name).await?;
    Ok(Json(view(spec, live(&state).as_deref())))
}

#[utoipa::path(put, path = "/upstream-groups/{name}", tag = "upstreams", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Group name")),
    request_body = GroupBody,
    responses(
        (status = 200, body = GroupView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ))]
async fn replace_group(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(body): Json<GroupBody>,
) -> Result<Json<GroupView>, ApiError> {
    let spec = spec_of(&name, body)?;
    let _guard = state.apply_lock.lock().await;
    super::live::require_engine(&state)?;
    let (specs, _) = find(&state, &name).await?;
    commit(&state, specs, Some(spec.clone()), None).await?;
    Ok(Json(view(spec, live(&state).as_deref())))
}

#[utoipa::path(delete, path = "/upstream-groups/{name}", tag = "upstreams", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Group name")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Would leave no default group", body = Problem, content_type = "application/problem+json"),
    ))]
async fn delete_group(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let _guard = state.apply_lock.lock().await;
    super::live::require_engine(&state)?;
    let (specs, _) = find(&state, &name).await?;
    commit(&state, specs, None, Some(&name)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/upstream-groups/{name}/upstreams", tag = "upstreams", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Group name")),
    request_body = MemberInput,
    responses(
        (status = 201, body = GroupView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ))]
async fn add_member(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(req): Json<MemberInput>,
) -> Result<(StatusCode, Json<GroupView>), ApiError> {
    let member = parse_member(&req)?;
    let _guard = state.apply_lock.lock().await;
    super::live::require_engine(&state)?;
    let (specs, mut spec) = find(&state, &name).await?;
    if spec.members.len() >= MAX_MEMBERS {
        return Err(ApiError::Unprocessable("too many members".to_owned()));
    }
    if spec.members.iter().any(|m| m.upstream == member.upstream) {
        return Err(ApiError::Conflict(
            "the upstream is already a member".to_owned(),
        ));
    }
    spec.members.push(member);
    commit(&state, specs, Some(spec.clone()), None).await?;
    Ok((
        StatusCode::CREATED,
        Json(view(spec, live(&state).as_deref())),
    ))
}

#[utoipa::path(delete, path = "/upstream-groups/{name}/upstreams/{index}", tag = "upstreams", security(("bearer" = []), ("session" = [])),
    params(
        ("name" = String, Path, description = "Group name"),
        ("index" = usize, Path, description = "Member index as listed"),
    ),
    responses(
        (status = 200, body = GroupView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "A group keeps at least one member", body = Problem, content_type = "application/problem+json"),
    ))]
async fn remove_member(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path((name, index)): Path<(String, usize)>,
) -> Result<Json<GroupView>, ApiError> {
    let _guard = state.apply_lock.lock().await;
    super::live::require_engine(&state)?;
    let (specs, mut spec) = find(&state, &name).await?;
    if index >= spec.members.len() {
        return Err(ApiError::NotFound("member not found".to_owned()));
    }
    spec.members.remove(index);
    if spec.members.is_empty() {
        return Err(ApiError::Unprocessable(
            "a group keeps at least one member; delete the group instead".to_owned(),
        ));
    }
    commit(&state, specs, Some(spec.clone()), None).await?;
    Ok(Json(view(spec, live(&state).as_deref())))
}

#[utoipa::path(get, path = "/upstream-groups/{name}/health", tag = "upstreams", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Group name")),
    responses(
        (status = 200, body = Vec<HealthView>),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 503, description = "The server is not running upstream groups", body = Problem, content_type = "application/problem+json"),
    ))]
async fn group_health(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<HealthView>>, ApiError> {
    find(&state, &name).await?;
    let health = live(&state)
        .and_then(|g| g.health(&name))
        .ok_or(ApiError::Unavailable)?;
    Ok(Json(health.into_iter().map(Into::into).collect()))
}
