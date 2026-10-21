//! Helpers shared by the routes that change live policy (ACL, upstreams, blocklists).

use std::fmt::Display;
use std::sync::Arc;

use dnsy_filter::FilterError;
use dnsy_resolver::groups::{GroupSet, GroupSpec, GroupStoreError, SystemClock, ThreadRng};

use crate::error::ApiError;
use crate::state::ApiState;

#[expect(clippy::needless_pass_by_value, reason = "used as a map_err callback")]
pub(super) fn filter_err(e: FilterError) -> ApiError {
    match e {
        FilterError::Duplicate => ApiError::Conflict(e.to_string()),
        FilterError::NotFound => ApiError::NotFound(e.to_string()),
        FilterError::Invalid(_) => ApiError::Unprocessable(e.to_string()),
        FilterError::Corrupt | FilterError::Store(_) => ApiError::Internal(e.to_string()),
    }
}

pub(super) fn internal(e: impl Display) -> ApiError {
    ApiError::Internal(e.to_string())
}

pub(super) fn group_store_err(e: GroupStoreError) -> ApiError {
    internal(e)
}

/// Mutating handlers check this before persisting anything: without a running engine the change
/// could not take effect, so they answer 503 instead of reporting success (fail closed).
pub(super) fn require_engine(state: &ApiState) -> Result<(), ApiError> {
    state
        .engine
        .as_ref()
        .map(|_| ())
        .ok_or(ApiError::Unavailable)
}

/// Same for client-certificate changes, which must reach the `DoT` allowlist.
pub(super) fn require_cert_reload(state: &ApiState) -> Result<(), ApiError> {
    state
        .cert_reload
        .as_ref()
        .map(|_| ())
        .ok_or(ApiError::Unavailable)
}

/// Rebuilds the ACL from the stored rules and swaps it into the running engine.
pub(super) async fn apply_acl(state: &ApiState) -> Result<(), ApiError> {
    let rules = state.rules.list().await.map_err(filter_err)?;
    if let Some(engine) = &state.engine {
        let acl = engine
            .acl()
            .with_rules(rules.into_iter().map(|r| (r.matcher, r.action)));
        engine.set_acl(acl);
    }
    Ok(())
}

/// Rebuilds the blocklist filter (custom rules, enabled sources) in the running engine.
pub(super) async fn reload_filter(state: &ApiState) -> Result<(), ApiError> {
    if let Some(manager) = &state.lists {
        manager.reload().await.map_err(internal)?;
    }
    Ok(())
}

/// Validates `specs` as a group set and swaps it into the running engine. An empty list leaves
/// the engine without upstreams.
pub(super) fn build_groups(specs: Vec<GroupSpec>) -> Result<Option<GroupSet>, ApiError> {
    if specs.is_empty() {
        return Ok(None);
    }
    GroupSet::new(specs, Arc::new(SystemClock::new()), Arc::new(ThreadRng))
        .map(Some)
        .map_err(|e| ApiError::Unprocessable(e.to_string()))
}
