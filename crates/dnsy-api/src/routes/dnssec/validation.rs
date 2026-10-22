//! Validation settings and status routes.

use axum::Json;
use axum::extract::State;
use dnsy_core::SystemClock;
use dnsy_observe::{StatsService, TimeRange};
use dnsy_proto::Name;

use crate::auth::{AdminScope, Read, RequireScope};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;
use dnsy_engine::{LivePolicy, TrustAnchorInfo};

use super::*;

fn settings_of(control: &dyn LivePolicy, now: i64) -> ValidationSettings {
    let entries: Vec<NtaView> = control
        .negative_trust_anchors()
        .into_iter()
        .filter(|(_, expires)| expires.is_none_or(|e| i64::from(e) > now))
        .map(|(name, expires)| NtaView {
            name: name.to_string(),
            expires_at: expires.map(i64::from),
        })
        .collect();
    ValidationSettings {
        validation: control.dnssec_mode().into(),
        negative_trust_anchors: entries.iter().map(|e| e.name.clone()).collect(),
        negative_trust_anchor_entries: entries,
        trust_anchors: control
            .trust_anchors()
            .into_iter()
            .map(|a: TrustAnchorInfo| TrustAnchorView {
                owner: a.owner,
                key_tag: a.key_tag,
                algorithm: a.algorithm,
                kind: if a.digest_type.is_some() {
                    "ds"
                } else {
                    "dnskey"
                }
                .to_owned(),
                digest_type: a.digest_type,
                digest: a.digest,
            })
            .collect(),
    }
}

fn parse_ntas(inputs: &[NtaInput], now: i64) -> Result<Vec<(Name, Option<u32>)>, ApiError> {
    if inputs.len() > MAX_NTAS {
        return Err(ApiError::Unprocessable(format!(
            "at most {MAX_NTAS} negative trust anchors"
        )));
    }
    let mut out: Vec<(Name, Option<u32>)> = Vec::new();
    for input in inputs {
        let (text, expires_at) = match input {
            NtaInput::Name(n) => (n, None),
            NtaInput::Entry(e) => (&e.name, e.expires_at),
        };
        let name = Name::from_ascii(text)
            .map_err(|e| ApiError::Unprocessable(format!("invalid name {text:?}: {e}")))?
            .to_lowercase();
        if name.is_root() {
            return Err(ApiError::Unprocessable(
                "a negative trust anchor at the root disables validation; set the mode to off"
                    .to_owned(),
            ));
        }
        let expires = match expires_at {
            None => None,
            Some(t) if t <= now => {
                return Err(ApiError::Unprocessable(format!(
                    "expires_at of {text:?} is not in the future"
                )));
            }
            Some(t) => Some(u32::try_from(t).map_err(|_| {
                ApiError::Unprocessable(format!("expires_at of {text:?} is too far ahead"))
            })?),
        };
        if !out.iter().any(|(n, _)| *n == name) {
            out.push((name, expires));
        }
    }
    Ok(out)
}

/// Validation mode, negative trust anchors and the (read-only) trust anchors.
#[utoipa::path(get, path = "/settings/dnssec", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = ValidationSettings),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
pub(super) async fn get_validation(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<ValidationSettings>, ApiError> {
    Ok(Json(settings_of(
        validation(&state)?.as_ref(),
        state.clock.unix_secs(),
    )))
}

/// Change the validation mode or the negative trust anchors at run time. A change flushes the
/// resolver cache.
#[utoipa::path(patch, path = "/settings/dnssec", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    request_body = ValidationPatch,
    responses(
        (status = 200, body = ValidationSettings),
        (status = 422, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
pub(super) async fn patch_validation(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Json(patch): Json<ValidationPatch>,
) -> Result<Json<ValidationSettings>, ApiError> {
    let control = validation(&state)?;
    if patch.validation.is_none() && patch.negative_trust_anchors.is_none() {
        return Err(ApiError::Unprocessable(
            "give `validation` or `negative_trust_anchors`".to_owned(),
        ));
    }
    let ntas = patch
        .negative_trust_anchors
        .as_deref()
        .map(|n| parse_ntas(n, state.clock.unix_secs()))
        .transpose()?;
    if let Some(mode) = patch.validation {
        control.set_dnssec_mode(mode.into());
    }
    if let Some(ntas) = ntas {
        control.set_negative_trust_anchors(ntas);
    }
    Ok(Json(settings_of(control.as_ref(), state.clock.unix_secs())))
}

// ---------------------------------------------------------------------------------------
// status

/// Validation counters of the last 24 hours and whether the clock is trusted.
#[utoipa::path(get, path = "/dnssec/status", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    responses((status = 200, body = DnssecStatus)))]
pub(super) async fn dnssec_status(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<DnssecStatus>, ApiError> {
    let to_ms = SystemClock.unix_millis();
    let summary = StatsService::new(state.observe.store.clone())
        .summary(TimeRange {
            from_ms: to_ms.saturating_sub(STATUS_WINDOW_MS).max(0),
            to_ms,
        })
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let signed_zones = state.zones.store.as_ref().map_or(0, |z| {
        z.snapshot()
            .iter()
            .filter(|zone| zone.dnssec.as_ref().is_some_and(|d| d.enabled))
            .count()
    });
    Ok(Json(DnssecStatus {
        validation: validation(&state).ok().map(|v| v.dnssec_mode().into()),
        clock_trusted: !state
            .policy
            .as_ref()
            .is_some_and(|p| p.dnssec_clock_untrusted()),
        window_ms: STATUS_WINDOW_MS,
        counters: summary.by_dnssec,
        secure: summary.secure,
        bogus: summary.bogus,
        signed_zones,
    }))
}
