//! Client access control: CIDR allow/refuse/drop rules (IP blocking) and the per-client rate
//! limit. Every change rebuilds the ACL and swaps it into the running engine.

use std::net::IpAddr;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use dnsy_core::hex;
use dnsy_filter::{AclAction, AclMatcher, AclRule};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::live::{apply_acl, filter_err, internal};
use crate::auth::{Read, RequireScope, Write};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

/// Longest rule comment.
const MAX_COMMENT: usize = 256;
/// Rules the API will hold.
const MAX_RULES: usize = 10_000;
/// Highest per-client rate limit accepted.
pub(super) const MAX_QPS: u32 = 1_000_000;

/// What to do with a matching client.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Serve the client.
    Allow,
    /// Answer REFUSED.
    Refuse,
    /// Send nothing.
    Drop,
}

impl From<Action> for AclAction {
    fn from(a: Action) -> Self {
        match a {
            Action::Allow => AclAction::Allow,
            Action::Refuse => AclAction::Refuse,
            Action::Drop => AclAction::Drop,
        }
    }
}

impl From<AclAction> for Action {
    fn from(a: AclAction) -> Self {
        match a {
            AclAction::Allow => Action::Allow,
            AclAction::Refuse => Action::Refuse,
            AclAction::Drop => Action::Drop,
        }
    }
}

/// A stored rule.
#[derive(Serialize, ToSchema)]
pub struct AclRuleView {
    pub id: i64,
    /// Network the rule matches (host bits cleared), for address rules.
    pub cidr: Option<String>,
    /// SHA-256 fingerprint (hex) of an mTLS client certificate, for identity rules.
    pub client_cert_sha256: Option<String>,
    pub action: Action,
    pub comment: String,
}

impl From<AclRule> for AclRuleView {
    fn from(r: AclRule) -> Self {
        let (cidr, cert) = match r.matcher {
            AclMatcher::Cidr(n) => (Some(n.trunc().to_string()), None),
            AclMatcher::ClientCert(fp) => (None, Some(hex::lower(&fp))),
        };
        AclRuleView {
            id: r.id,
            cidr,
            client_cert_sha256: cert,
            action: r.action.into(),
            comment: r.comment,
        }
    }
}

/// Rules and the rate limit.
#[derive(Serialize, ToSchema)]
pub struct AclOverview {
    /// Applied to clients no rule matches.
    pub default_action: Action,
    pub rules: Vec<AclRuleView>,
    /// Queries per second per client; 0 means unlimited.
    pub rate_limit_qps: u32,
}

/// New rule: exactly one of `cidr` and `client_cert_sha256`.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateAclRule {
    /// Address or network, e.g. `203.0.113.7` or `10.0.0.0/8` (longest prefix wins).
    pub cidr: Option<String>,
    /// SHA-256 fingerprint (64 hex digits) of an mTLS client certificate.
    pub client_cert_sha256: Option<String>,
    pub action: Action,
    #[serde(default)]
    pub comment: String,
}

/// Per-client rate limit.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    /// Queries per second per client; 0 disables limiting. At most 1,000,000.
    pub qps: u32,
}

pub(super) fn parse_cidr(s: &str) -> Result<IpNet, ApiError> {
    let s = s.trim();
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net);
    }
    s.parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|_| ApiError::Unprocessable("cidr is not an address or network".to_owned()))
}

pub(super) fn parse_fingerprint(s: &str) -> Result<[u8; 32], ApiError> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| *b != b':')
        .map(|b| b.to_ascii_lowercase())
        .collect();
    let bad = || ApiError::Unprocessable("sha256 must be 64 hex digits".to_owned());
    if digits.len() != 64 {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(digits.chunks(2)) {
        let hi = char::from(pair[0]).to_digit(16).ok_or_else(bad)?;
        let lo = char::from(pair[1]).to_digit(16).ok_or_else(bad)?;
        *slot = u8::try_from(hi * 16 + lo).map_err(|_| bad())?;
    }
    Ok(out)
}

/// Routes of this group, relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(get_acl, create_rule))
        .routes(routes!(delete_rule))
        .routes(routes!(set_rate_limit))
}

#[utoipa::path(get, path = "/acl", tag = "acl", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = AclOverview),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn get_acl(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<AclOverview>, ApiError> {
    let rules = state.stores.rules.list().await.map_err(filter_err)?;
    let qps = state
        .stores
        .rules
        .rate_limit_qps()
        .await
        .map_err(filter_err)?;
    Ok(Json(AclOverview {
        default_action: Action::Allow,
        rules: rules.into_iter().map(Into::into).collect(),
        rate_limit_qps: qps.unwrap_or_else(|| state.settings.per_client_qps()),
    }))
}

#[utoipa::path(post, path = "/acl", tag = "acl", security(("bearer" = []), ("session" = [])),
    request_body = CreateAclRule,
    responses(
        (status = 201, description = "Created", body = AclRuleView),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "An identical rule exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ))]
async fn create_rule(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Json(req): Json<CreateAclRule>,
) -> Result<(StatusCode, Json<AclRuleView>), ApiError> {
    let matcher = match (&req.cidr, &req.client_cert_sha256) {
        (Some(c), None) => AclMatcher::Cidr(parse_cidr(c)?),
        (None, Some(f)) => AclMatcher::ClientCert(parse_fingerprint(f)?),
        _ => {
            return Err(ApiError::Unprocessable(
                "give exactly one of cidr and client_cert_sha256".to_owned(),
            ));
        }
    };
    if req.comment.chars().count() > MAX_COMMENT {
        return Err(ApiError::Unprocessable("comment is too long".to_owned()));
    }
    let _guard = state.apply_lock.lock().await;
    super::live::require_policy(&state)?;
    if state.stores.rules.list().await.map_err(filter_err)?.len() >= MAX_RULES {
        return Err(ApiError::Unprocessable("too many rules".to_owned()));
    }
    let id = state
        .stores
        .rules
        .add(matcher, req.action.into(), &req.comment)
        .await
        .map_err(filter_err)?;
    apply_acl(&state).await?;
    let rule = state
        .stores
        .rules
        .list()
        .await
        .map_err(filter_err)?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| internal("created rule vanished"))?;
    Ok((StatusCode::CREATED, Json(rule.into())))
}

#[utoipa::path(delete, path = "/acl/{id}", tag = "acl", security(("bearer" = []), ("session" = [])),
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
    state.stores.rules.delete(id).await.map_err(filter_err)?;
    apply_acl(&state).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(put, path = "/acl/rate-limit", tag = "acl", security(("bearer" = []), ("session" = [])),
    request_body = RateLimit,
    responses(
        (status = 200, body = RateLimit),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ))]
async fn set_rate_limit(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Json(req): Json<RateLimit>,
) -> Result<Json<RateLimit>, ApiError> {
    if req.qps > MAX_QPS {
        return Err(ApiError::Unprocessable(format!(
            "qps must be at most {MAX_QPS}"
        )));
    }
    let _guard = state.apply_lock.lock().await;
    super::live::require_policy(&state)?;
    state
        .stores
        .rules
        .set_rate_limit_qps(req.qps)
        .await
        .map_err(filter_err)?;
    if let Some(policy) = &state.policy {
        policy.set_rate_limit(req.qps);
    }
    state.settings.set_per_client_qps(req.qps);
    Ok(Json(req))
}
