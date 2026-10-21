//! Route groups. Each group lives in its own file and exposes
//! `pub fn router() -> OpenApiRouter<ApiState>` with paths relative to `/api/v1`.
//!
//! To register a group, add `mod <name>;` and append one `.merge(<name>::router())` line to
//! [`v1`].

use utoipa_axum::router::OpenApiRouter;

use crate::state::ApiState;

mod acl;
mod auth;
mod blocklists;
mod cache;
mod certs;
mod dnssec;
mod filtering;
mod live;
mod meta;
mod querylog;
mod settings;
mod stats;
mod tokens;
mod upstreams;
mod users;
mod zones;

/// Everything under `/api/v1`.
pub fn v1() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .merge(meta::router())
        .merge(auth::router())
        .merge(users::router())
        .merge(tokens::router())
        .merge(zones::router())
        .merge(dnssec::router())
        .merge(filtering::router())
        .merge(acl::router())
        .merge(blocklists::router())
        .merge(upstreams::router())
        .merge(certs::router())
        .merge(settings::router())
        .merge(querylog::router())
        .merge(stats::router())
        .merge(cache::router())
}

/// Unauthenticated probes at the root.
pub fn root() -> OpenApiRouter<ApiState> {
    meta::root_router()
}
