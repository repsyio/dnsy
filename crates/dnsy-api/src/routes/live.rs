//! Helpers shared by the routes that change live policy (ACL, upstreams, blocklists).

use std::fmt::Display;
use std::sync::Arc;

use dnsy_engine::LivePolicy;
use dnsy_filter::FilterError;
use dnsy_resolver::groups::{GroupSet, GroupSpec, GroupStoreError};

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
pub(super) fn require_policy(state: &ApiState) -> Result<&Arc<dyn LivePolicy>, ApiError> {
    state.policy.as_ref().ok_or(ApiError::Unavailable)
}

/// Same for client-certificate changes, which must reach the `DoT` allowlist.
pub(super) fn require_cert_reload(state: &ApiState) -> Result<(), ApiError> {
    state
        .auth
        .cert_reload
        .as_ref()
        .map(|_| ())
        .ok_or(ApiError::Unavailable)
}

/// Rebuilds the ACL from the stored rules and swaps it into the running engine.
pub(super) async fn apply_acl(state: &ApiState) -> Result<(), ApiError> {
    let rules = state.stores.rules.list().await.map_err(filter_err)?;
    if let Some(policy) = &state.policy {
        policy.apply_acl_rules(rules.into_iter().map(|r| (r.matcher, r.action)).collect());
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

/// Checks that `specs` form a valid group set (an empty list is valid: the engine is then left
/// without upstreams).
pub(super) fn validate_groups(specs: &[GroupSpec]) -> Result<(), ApiError> {
    if specs.is_empty() {
        return Ok(());
    }
    GroupSet::from_specs(specs.to_vec())
        .map(|_| ())
        .map_err(|e| ApiError::Unprocessable(e.to_string()))
}
