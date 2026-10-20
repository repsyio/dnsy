//! Helpers shared by the routes that change live policy (ACL, upstreams, blocklists).

use std::fmt::Display;
use std::sync::Arc;

use dnsy_filter::{Acl, AclAction, FilterError};
use dnsy_resolver::groups::{GroupSet, GroupSpec, GroupStoreError, SystemClock, ThreadRng};

use crate::error::ApiError;
use crate::state::ApiState;

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

/// Rebuilds the ACL from the stored rules and swaps it into the running engine.
pub(super) async fn apply_acl(state: &ApiState) -> Result<(), ApiError> {
    let rules = state.rules.list().await.map_err(filter_err)?;
    if let Some(engine) = &state.engine {
        engine.set_acl(Acl::new(
            AclAction::Allow,
            rules.into_iter().map(|r| (r.matcher, r.action)),
        ));
    }
    Ok(())
}

/// Rebuilds the blocklist filter (custom rules, enabled sources) in the running engine.
pub(super) async fn reload_filter(state: &ApiState) -> Result<(), ApiError> {
    if let Some(manager) = state.engine.as_ref().and_then(|e| e.list_manager()) {
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
