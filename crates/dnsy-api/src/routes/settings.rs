//! The runtime-changeable subset of the configuration (admin only).
//!
//! Only the fields below can be read or patched; every other key (listeners, TLS paths, the
//! DNSSEC key passphrase file, ...) is not part of the model, so it can neither leak nor be
//! changed here. A patch is applied to a copy of the running configuration and checked with
//! `dnsy_config::Config::validate`, the validation the loader uses, before anything changes.
//! Changes take effect immediately. They are not written to `dnsy.toml`: after a restart the
//! file wins, except the rate limit, which is persisted with the ACL.

use axum::Json;
use axum::extract::State;
use dnsy_config::{Config, ConfigError};
use dnsy_core::BlockMode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::acl::MAX_QPS;
use super::live::{filter_err, internal};
use crate::auth::{AdminScope, RequireScope};
use crate::error::{ApiError, Problem};
use crate::runtime_settings::retention_of;
use crate::state::ApiState;

const MAX_RETENTION_DAYS: u32 = 3_650;
const MAX_TTL: u32 = 0x7fff_ffff;

/// How blocked names are answered.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockModeView {
    /// `0.0.0.0` / `::`.
    NullIp,
    Nxdomain,
    Refused,
}

impl From<BlockMode> for BlockModeView {
    fn from(m: BlockMode) -> Self {
        match m {
            // `CustomIp` is never produced by configuration, the only source of this value.
            BlockMode::NullIp | BlockMode::CustomIp { .. } => BlockModeView::NullIp,
            BlockMode::NxDomain => BlockModeView::Nxdomain,
            BlockMode::Refused => BlockModeView::Refused,
        }
    }
}

impl From<BlockModeView> for BlockMode {
    fn from(m: BlockModeView) -> Self {
        match m {
            BlockModeView::NullIp => BlockMode::NullIp,
            BlockModeView::Nxdomain => BlockMode::NxDomain,
            BlockModeView::Refused => BlockMode::Refused,
        }
    }
}

/// Filtering settings.
#[derive(Serialize, ToSchema)]
pub struct FilterSettings {
    pub block_mode: BlockModeView,
}

/// Query log settings.
#[derive(Serialize, ToSchema)]
pub struct QueryLogSettings {
    /// Days of history kept.
    pub retention_days: u32,
}

/// Limits.
#[derive(Serialize, ToSchema)]
pub struct LimitSettings {
    /// Queries per second per client; 0 means unlimited.
    pub per_client_qps: u32,
}

/// A feature switch.
#[derive(Serialize, ToSchema)]
pub struct Toggle {
    pub enabled: bool,
}

/// Cache settings.
#[derive(Serialize, ToSchema)]
pub struct CacheSettings {
    /// Lowest TTL (seconds) given to cached positive answers.
    pub min_ttl: u32,
    /// Highest TTL (seconds) given to cached positive answers.
    pub max_ttl: u32,
    pub serve_stale: Toggle,
    pub prefetch: Toggle,
}

/// The settings that can change at runtime.
#[derive(Serialize, ToSchema)]
pub struct SettingsView {
    pub filter: FilterSettings,
    pub querylog: QueryLogSettings,
    pub limits: LimitSettings,
    pub cache: CacheSettings,
}

fn view(c: &Config) -> SettingsView {
    SettingsView {
        filter: FilterSettings {
            block_mode: c.filter.block_mode.into(),
        },
        querylog: QueryLogSettings {
            retention_days: c.querylog.retention_days,
        },
        limits: LimitSettings {
            per_client_qps: c.limits.per_client_qps,
        },
        cache: CacheSettings {
            min_ttl: c.cache.min_ttl,
            max_ttl: c.cache.max_ttl,
            serve_stale: Toggle {
                enabled: c.cache.serve_stale.enabled,
            },
            prefetch: Toggle {
                enabled: c.cache.prefetch.enabled,
            },
        },
    }
}

/// Partial update: omitted fields keep their value.
#[derive(Deserialize, ToSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct SettingsPatch {
    pub filter: Option<FilterPatch>,
    pub querylog: Option<QueryLogPatch>,
    pub limits: Option<LimitsPatch>,
    pub cache: Option<CachePatch>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct FilterPatch {
    pub block_mode: Option<BlockModeView>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryLogPatch {
    /// 1 to 3650.
    pub retention_days: Option<u32>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct LimitsPatch {
    /// 0 to 1,000,000; 0 disables the limit.
    pub per_client_qps: Option<u32>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TogglePatch {
    pub enabled: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CachePatch {
    pub min_ttl: Option<u32>,
    /// Not below `min_ttl`.
    pub max_ttl: Option<u32>,
    pub serve_stale: Option<TogglePatch>,
    pub prefetch: Option<TogglePatch>,
}

impl SettingsPatch {
    fn apply(self, c: &mut Config) {
        if let Some(mode) = self.filter.and_then(|f| f.block_mode) {
            c.filter.block_mode = mode.into();
        }
        if let Some(days) = self.querylog.and_then(|q| q.retention_days) {
            c.querylog.retention_days = days;
        }
        if let Some(qps) = self.limits.and_then(|l| l.per_client_qps) {
            c.limits.per_client_qps = qps;
        }
        if let Some(cache) = self.cache {
            if let Some(v) = cache.min_ttl {
                c.cache.min_ttl = v;
            }
            if let Some(v) = cache.max_ttl {
                c.cache.max_ttl = v;
            }
            if let Some(v) = cache.serve_stale.and_then(|t| t.enabled) {
                c.cache.serve_stale.enabled = v;
            }
            if let Some(v) = cache.prefetch.and_then(|t| t.enabled) {
                c.cache.prefetch.enabled = v;
            }
        }
    }
}

fn check(c: &Config) -> Result<(), ApiError> {
    c.validate().map_err(|e| match e {
        ConfigError::Invalid(m) => ApiError::Unprocessable(m),
        other => ApiError::Unprocessable(other.to_string()),
    })?;
    if !(1..=MAX_RETENTION_DAYS).contains(&c.querylog.retention_days) {
        return Err(ApiError::Unprocessable(format!(
            "querylog.retention_days must be between 1 and {MAX_RETENTION_DAYS}"
        )));
    }
    if c.limits.per_client_qps > MAX_QPS {
        return Err(ApiError::Unprocessable(format!(
            "limits.per_client_qps must be at most {MAX_QPS}"
        )));
    }
    if c.cache.max_ttl > MAX_TTL {
        return Err(ApiError::Unprocessable(format!(
            "cache.max_ttl must be at most {MAX_TTL}"
        )));
    }
    Ok(())
}

/// Routes of this group, relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new().routes(routes!(get_settings, patch_settings))
}

#[utoipa::path(get, path = "/settings", tag = "settings", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = SettingsView),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn get_settings(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
) -> Json<SettingsView> {
    Json(view(&state.settings.snapshot()))
}

#[utoipa::path(patch, path = "/settings", tag = "settings", security(("bearer" = []), ("session" = [])),
    request_body = SettingsPatch,
    responses(
        (status = 200, description = "The settings now in effect", body = SettingsView),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Unknown field or invalid value; nothing changed", body = Problem, content_type = "application/problem+json"),
    ))]
async fn patch_settings(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Json(body): Json<Value>,
) -> Result<Json<SettingsView>, ApiError> {
    let patch: SettingsPatch = serde_json::from_value(body)
        .map_err(|e| ApiError::Unprocessable(format!("invalid settings patch: {e}")))?;
    let _guard = state.apply_lock.lock().await;
    super::live::require_policy(&state)?;
    let old = state.settings.snapshot();
    let mut next = old.clone();
    patch.apply(&mut next);
    check(&next)?;
    apply(&state, &old, &next).await?;
    state.settings.store(next.clone());
    Ok(Json(view(&next)))
}

async fn apply(state: &ApiState, old: &Config, new: &Config) -> Result<(), ApiError> {
    if new.filter.block_mode != old.filter.block_mode
        && let Some(policy) = &state.policy
    {
        if let Some(manager) = &state.lists {
            manager.set_block_mode(new.filter.block_mode);
            if let Err(e) = manager.reload().await {
                manager.set_block_mode(old.filter.block_mode);
                return Err(internal(e));
            }
        }
        policy.set_block_mode(new.filter.block_mode);
    }
    if new.limits.per_client_qps != old.limits.per_client_qps {
        state
            .stores
            .rules
            .set_rate_limit_qps(new.limits.per_client_qps)
            .await
            .map_err(filter_err)?;
        if let Some(policy) = &state.policy {
            policy.set_rate_limit(new.limits.per_client_qps);
        }
    }
    if let Some(cache) = &state.cache {
        let (old, new) = (&old.cache, &new.cache);
        cache.reconfigure(|c| {
            if new.min_ttl != old.min_ttl {
                c.min_ttl = new.min_ttl;
            }
            if new.max_ttl != old.max_ttl {
                c.max_ttl = new.max_ttl;
            }
            if new.serve_stale.enabled != old.serve_stale.enabled {
                c.serve_stale.enabled = new.serve_stale.enabled;
            }
            if new.prefetch.enabled != old.prefetch.enabled {
                c.prefetch.enabled = new.prefetch.enabled;
            }
        });
    }
    state
        .settings
        .retention
        .send_replace(retention_of(new.querylog.retention_days));
    Ok(())
}
