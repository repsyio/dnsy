//! Response-IP policy: networks whose addresses block an upstream answer. The list starts from
//! `[filter] response_ip_blocklist`; a change is stored and swapped into the running engine, and
//! the stored list wins over the file after a restart.

use axum::Json;
use axum::extract::State;
use dnsy_engine::ResponseIpPolicy;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::acl::parse_cidr;
use super::live::filter_err;
use crate::auth::{Read, RequireScope, Write};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

/// Networks the API will hold.
const MAX_NETS: usize = 10_000;

/// The response-IP networks.
#[derive(Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ResponseIpList {
    /// Addresses or networks, e.g. `10.0.0.0/8` or `192.0.2.1`. An upstream answer with an A or
    /// AAAA record inside any of them is blocked (EDE 15). An empty list disables the policy.
    pub cidrs: Vec<String>,
}

/// Routes of this group, relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new().routes(routes!(get_response_ip, put_response_ip))
}

#[utoipa::path(get, path = "/response-ip", tag = "acl", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = ResponseIpList),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn get_response_ip(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<ResponseIpList>, ApiError> {
    let cidrs = match state
        .stores
        .rules
        .response_ip_cidrs()
        .await
        .map_err(filter_err)?
    {
        Some(stored) => stored,
        None => state.settings.snapshot().filter.response_ip_blocklist,
    };
    Ok(Json(ResponseIpList { cidrs }))
}

#[utoipa::path(put, path = "/response-ip", tag = "acl", security(("bearer" = []), ("session" = [])),
    request_body = ResponseIpList,
    responses(
        (status = 200, description = "The list now in effect", body = ResponseIpList),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid or too many entries; nothing changed", body = Problem, content_type = "application/problem+json"),
    ))]
async fn put_response_ip(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Json(req): Json<ResponseIpList>,
) -> Result<Json<ResponseIpList>, ApiError> {
    if req.cidrs.len() > MAX_NETS {
        return Err(ApiError::Unprocessable("too many networks".to_owned()));
    }
    let mut cidrs: Vec<String> = Vec::with_capacity(req.cidrs.len());
    for c in &req.cidrs {
        let net = parse_cidr(c)?.trunc().to_string();
        if !cidrs.contains(&net) {
            cidrs.push(net);
        }
    }
    let _guard = state.apply_lock.lock().await;
    let policy = super::live::require_policy(&state)?;
    state
        .stores
        .rules
        .set_response_ip_cidrs(&cidrs)
        .await
        .map_err(filter_err)?;
    policy.set_response_ip_policy(ResponseIpPolicy::from_strings(&cidrs));
    Ok(Json(ResponseIpList { cidrs }))
}
