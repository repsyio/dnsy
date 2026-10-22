//! DNSSEC: zone signing policy, keys, rollover, DS export and validation settings.
//!
//! Key material never leaves the key store: no type in this file can carry a private key, and
//! the key store's errors (which never contain key material either) are mapped to generic
//! problem responses. Mutating routes need the `admin` scope.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use dnsy_core::Clock as _;
use dnsy_dnssec::{Algorithm, DigestType, ds_for};
use dnsy_keys::{KeyLayout, KeyRecord, KeyRole, KeyState, KeyStoreError, Passphrase};
use dnsy_proto::Name;
use dnsy_zone::{Denial, DnssecPolicy, Zone, ZoneSigning};
use serde_json::{Map, Value};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::zones::{edit, existing, zone_name};
use crate::auth::{AdminScope, Read, RequireScope};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;
use dnsy_engine::{LivePolicy, hex_upper};

mod dto;
mod validation;

use dto::{
    AbortRolloverInput, ChangePassphraseInput, DenialBody, DnskeyRecordView, DnssecPolicyInput,
    DnssecStatus, DnssecView, DsExport, DsRecordView, ExportKeysInput, GenerateKeyInput, KeyBackup,
    KeyLayoutBody, KeyView, Nsec3Body, NtaInput, NtaView, PassphraseChanged, RolloverInput,
    RolloverRoleView, RolloverView, TrustAnchorView, ValidationPatch, ValidationSettings,
};
use validation::{
    __path_dnssec_status, __path_get_validation, __path_patch_validation, dnssec_status,
    get_validation, patch_validation,
};

/// Negative trust anchors the API accepts.
const MAX_NTAS: usize = 256;
/// The window of `GET /dnssec/status` counters.
const STATUS_WINDOW_MS: i64 = 24 * 3600 * 1000;

/// Routes relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(get_dnssec, put_dnssec))
        .routes(routes!(list_keys, generate_key))
        .routes(routes!(start_rollover))
        .routes(routes!(confirm_ds))
        .routes(routes!(abort_rollover))
        .routes(routes!(export_keys))
        .routes(routes!(change_passphrase))
        .routes(routes!(ds_export))
        .routes(routes!(get_validation, patch_validation))
        .routes(routes!(dnssec_status))
}

// ---------------------------------------------------------------------------------------
// helpers

fn signing(state: &ApiState) -> Result<&ZoneSigning, ApiError> {
    state.zones.signing.as_ref().ok_or(ApiError::Unavailable)
}

/// The live policy (the engine); the settings routes answer 503 without it.
fn validation(state: &ApiState) -> Result<Arc<dyn LivePolicy>, ApiError> {
    state.policy.clone().ok_or(ApiError::Unavailable)
}
fn key_error(e: &KeyStoreError) -> ApiError {
    match e {
        KeyStoreError::NotFound(_) => ApiError::NotFound(e.to_string()),
        KeyStoreError::RolloverInProgress(_)
        | KeyStoreError::NoRollover(_)
        | KeyStoreError::NoActiveKey(_)
        | KeyStoreError::InvalidState(_) => ApiError::Conflict(e.to_string()),
        // Details (which may name files or crypto failures) stay in the log.
        _ => ApiError::Internal(e.to_string()),
    }
}

fn check_algorithm(algorithm: u8) -> Result<Algorithm, ApiError> {
    match algorithm {
        13 | 15 => Ok(Algorithm::from(algorithm)),
        n => Err(ApiError::Unprocessable(format!(
            "algorithm {n} is unsupported (use 13 or 15)"
        ))),
    }
}

fn key_view(k: &KeyRecord) -> KeyView {
    KeyView {
        id: k.id,
        role: k.role.to_string(),
        algorithm: k.algorithm.number(),
        key_tag: k.key_tag,
        state: k.state.to_string(),
        created_at: k.created_at,
        published_at: k.published_at,
        active_at: k.active_at,
        retired_at: k.retired_at,
        removed_at: k.removed_at,
        ds_confirmed_at: k.ds_confirmed_at,
    }
}

fn rollover_view(keys: &[KeyRecord]) -> RolloverView {
    let rollovers: Vec<RolloverRoleView> = keys
        .iter()
        .filter(|k| matches!(k.state, KeyState::Generated | KeyState::Published))
        .map(|k| RolloverRoleView {
            role: k.role.to_string(),
            state: if k.role.is_sep()
                && k.state == KeyState::Published
                && k.ds_confirmed_at.is_none()
            {
                "awaiting_ds_confirmation"
            } else {
                "in_progress"
            }
            .to_owned(),
            new_key_id: k.id,
        })
        .collect();
    let state = if rollovers.is_empty() {
        "idle"
    } else if rollovers
        .iter()
        .any(|r| r.state == "awaiting_ds_confirmation")
    {
        "awaiting_ds_confirmation"
    } else {
        "in_progress"
    };
    RolloverView {
        state: state.to_owned(),
        role: rollovers.first().map(|r| r.role.clone()),
        new_key_id: rollovers.first().map(|r| r.new_key_id),
        rollovers,
    }
}

fn policy_of(zone: &Zone) -> DnssecPolicy {
    zone.dnssec.clone().unwrap_or_else(|| {
        serde_json::from_value(Value::Object(Map::new())).expect("an empty policy has defaults")
    })
}

async fn view_of(
    state: &ApiState,
    signing: &ZoneSigning,
    zone: &Zone,
) -> Result<DnssecView, ApiError> {
    let policy = policy_of(zone);
    let keys: Vec<KeyRecord> = signing
        .keys()
        .keys(&zone.origin)
        .await
        .map_err(|e| key_error(&e))?
        .into_iter()
        .filter(|k| k.state != KeyState::Removed)
        .collect();
    let next_resign = state.zones.store.as_ref().and_then(|z| {
        z.snapshot()
            .signed(&zone.origin)
            .map(|s| i64::from(s.next_resign))
    });
    Ok(DnssecView {
        enabled: policy.enabled,
        algorithm: policy.algorithm,
        key_layout: match policy.key_layout {
            KeyLayout::Csk => KeyLayoutBody::Csk,
            KeyLayout::KskZsk => KeyLayoutBody::KskZsk,
        },
        denial: match policy.denial {
            Denial::Nsec => DenialBody::Nsec,
            Denial::Nsec3 => DenialBody::Nsec3,
        },
        nsec3: Nsec3Body {
            iterations: policy.nsec3.iterations,
            salt: policy.nsec3.salt.clone(),
            opt_out: policy.nsec3.opt_out,
            allow_nonzero_iterations: policy.nsec3.allow_nonzero_iterations,
        },
        signature_validity_days: policy.signature_validity_days,
        refresh_days: policy.refresh_days,
        dnskey_ttl: policy.dnskey_ttl,
        propagation_delay: policy.propagation_delay,
        rollover: rollover_view(&keys),
        keys: keys.iter().map(key_view).collect(),
        next_resign,
        keys_encrypted: signing.keys().keys_encrypted(),
    })
}

/// A key of the zone, or 404.
async fn zone_key(signing: &ZoneSigning, origin: &Name, id: i64) -> Result<KeyRecord, ApiError> {
    signing
        .keys()
        .keys(origin)
        .await
        .map_err(|e| key_error(&e))?
        .into_iter()
        .find(|k| k.id == id && k.state != KeyState::Removed)
        .ok_or_else(|| ApiError::NotFound(format!("key {id} not found in zone {origin}")))
}

// ---------------------------------------------------------------------------------------
// zone policy

/// A zone's DNSSEC policy, keys and rollover state.
#[utoipa::path(get, path = "/zones/{name}/dnssec", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    responses(
        (status = 200, body = DnssecView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn get_dnssec(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<DnssecView>, ApiError> {
    let signing = signing(&state)?;
    let (_, zone) = existing(&state, &name)?;
    Ok(Json(view_of(&state, signing, &zone).await?))
}

/// Enable, disable or change a zone's signing policy. Writes the zone file's `dnssec` block;
/// enabling creates the keys and signs the zone before the response is sent.
#[utoipa::path(put, path = "/zones/{name}/dnssec", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    request_body = DnssecPolicyInput,
    responses(
        (status = 200, body = DnssecView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn put_dnssec(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(body): Json<DnssecPolicyInput>,
) -> Result<Json<DnssecView>, ApiError> {
    let signing = signing(&state)?;
    let origin = zone_name(&name)?;
    if let Some(a) = body.algorithm {
        check_algorithm(a)?;
    }
    let Ok(Value::Object(given)) = serde_json::to_value(&body) else {
        return Err(ApiError::Internal("policy did not serialise".to_owned()));
    };
    let (zone, ()) = edit(&state, origin, None, move |z| {
        let mut doc: Value = serde_json::from_str(&z.to_json()).expect("zone JSON parses");
        let mut policy = match doc.get("dnssec") {
            Some(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        };
        policy.extend(given);
        doc["dnssec"] = Value::Object(policy);
        *z = Zone::from_json(&doc.to_string())?.0;
        Ok(())
    })
    .await?;
    signing.sign_due().await;
    Ok(Json(view_of(&state, signing, &zone).await?))
}

// ---------------------------------------------------------------------------------------
// keys

/// The zone's keys (public metadata only), including removed ones.
#[utoipa::path(get, path = "/zones/{name}/dnssec/keys", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    responses(
        (status = 200, body = Vec<KeyView>),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn list_keys(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<Vec<KeyView>>, ApiError> {
    let signing = signing(&state)?;
    let (_, zone) = existing(&state, &name)?;
    let keys = signing
        .keys()
        .keys(&zone.origin)
        .await
        .map_err(|e| key_error(&e))?;
    Ok(Json(keys.iter().map(key_view).collect()))
}

/// Generate a key in the `generated` state (not yet published). The zone needs signing
/// enabled.
#[utoipa::path(post, path = "/zones/{name}/dnssec/keys", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    request_body = GenerateKeyInput,
    responses(
        (status = 201, body = KeyView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn generate_key(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(body): Json<GenerateKeyInput>,
) -> Result<(StatusCode, Json<KeyView>), ApiError> {
    let signing = signing(&state)?;
    let (_, zone) = existing(&state, &name)?;
    let policy = policy_of(&zone);
    if !policy.enabled {
        return Err(ApiError::Conflict(
            "DNSSEC signing is not enabled for this zone".to_owned(),
        ));
    }
    let algorithm = check_algorithm(body.algorithm.unwrap_or(policy.algorithm))?;
    let key = signing
        .keys()
        .generate_key(&zone.origin, body.role.into(), algorithm)
        .await
        .map_err(|e| key_error(&e))?;
    Ok((StatusCode::CREATED, Json(key_view(&key))))
}

/// Start a rollover of the role of an active key: a new key is generated and published, and
/// the rollover state machine moves it along. KSK and CSK rollovers wait for
/// `ds-confirmed`.
#[utoipa::path(post, path = "/zones/{name}/dnssec/keys/{id}/rollover", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name"), ("id" = i64, Path, description = "Active key to replace")),
    request_body(content = RolloverInput, description = "Optional"),
    responses(
        (status = 202, description = "The incoming key", body = KeyView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn start_rollover(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path((name, id)): Path<(String, i64)>,
    body: Option<Json<RolloverInput>>,
) -> Result<(StatusCode, Json<KeyView>), ApiError> {
    let signing = signing(&state)?;
    let (_, zone) = existing(&state, &name)?;
    let old = zone_key(signing, &zone.origin, id).await?;
    if old.state != KeyState::Active {
        return Err(ApiError::Conflict(
            "only an active key can be rolled over".to_owned(),
        ));
    }
    let algorithm = match body.and_then(|Json(b)| b.algorithm) {
        Some(a) => check_algorithm(a)?,
        None => old.algorithm,
    };
    let key = signing
        .keys()
        .start_rollover(&zone.origin, old.role, algorithm)
        .await
        .map_err(|e| key_error(&e))?;
    // Publish the incoming key's DNSKEY now instead of at the next refresh.
    signing.sign_due().await;
    Ok((StatusCode::ACCEPTED, Json(key_view(&key))))
}

/// Record that the key's DS is published at the parent; a KSK or CSK rollover waits for this.
#[utoipa::path(post, path = "/zones/{name}/dnssec/keys/{id}/ds-confirmed", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name"), ("id" = i64, Path, description = "Published KSK or CSK")),
    responses(
        (status = 204, description = "Recorded"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn confirm_ds(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path((name, id)): Path<(String, i64)>,
) -> Result<StatusCode, ApiError> {
    let signing = signing(&state)?;
    let (_, zone) = existing(&state, &name)?;
    zone_key(signing, &zone.origin, id).await?;
    signing
        .keys()
        .confirm_ds(id)
        .await
        .map_err(|e| key_error(&e))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Abort the rollover of one role (or of every role): the incoming key is withdrawn and its
/// private key destroyed, and the active key keeps signing. A rollover whose new key already
/// became active cannot be aborted. If the incoming KSK or CSK's DS was already published at
/// the parent, remove it there.
#[utoipa::path(post, path = "/zones/{name}/dnssec/rollover/abort", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    request_body(content = AbortRolloverInput, description = "Optional"),
    responses(
        (status = 200, description = "The zone's DNSSEC state after the abort", body = DnssecView),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn abort_rollover(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    body: Option<Json<AbortRolloverInput>>,
) -> Result<Json<DnssecView>, ApiError> {
    let signing = signing(&state)?;
    let (_, zone) = existing(&state, &name)?;
    let role = body.and_then(|Json(b)| b.role).map(KeyRole::from);
    signing
        .keys()
        .abort_rollover(&zone.origin, role)
        .await
        .map_err(|e| key_error(&e))?;
    // Drop the withdrawn DNSKEY from the signed zone now instead of at the next refresh.
    signing.sign_due().await;
    tracing::info!(zone = %zone.origin, "dnssec rollover aborted");
    Ok(Json(view_of(&state, signing, &zone).await?))
}

// ---------------------------------------------------------------------------------------
// key backup and passphrase

/// Shortest passphrase accepted for a bundle or the key store.
const MIN_PASSPHRASE_LEN: usize = 12;

fn passphrase(text: &str) -> Result<Passphrase, ApiError> {
    if text.chars().count() < MIN_PASSPHRASE_LEN {
        return Err(ApiError::Unprocessable(format!(
            "the passphrase needs at least {MIN_PASSPHRASE_LEN} characters"
        )));
    }
    Ok(Passphrase::new(text))
}

/// Export the zone keys as a bundle encrypted under the given passphrase, for backup. The
/// response holds ciphertext only; the passphrase and the keys are never logged. Refused with
/// 403 when the API listener is plain HTTP.
#[utoipa::path(post, path = "/dnssec/keys/export", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    request_body = ExportKeysInput,
    responses(
        (status = 200, body = KeyBackup),
        (status = 403, description = "Admin scope missing, or the API listener is plain HTTP", body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn export_keys(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Json(body): Json<ExportKeysInput>,
) -> Result<Json<KeyBackup>, ApiError> {
    let signing = signing(&state)?;
    // The bundle holds every private key and its passphrase travels in the request body:
    // never over a plain-HTTP hop.
    if !state.auth.cookie_secure {
        return Err(ApiError::Forbidden(
            "key export is refused on a plain-HTTP API listener; enable TLS or reach the API through a TLS-terminating proxy",
        ));
    }
    let bundle_pass = passphrase(&body.passphrase)?;
    let origin = match &body.zone {
        Some(z) => Some(existing(&state, z)?.1.origin.clone()),
        None => None,
    };
    let bundle = signing
        .keys()
        .export_bundle(origin.as_ref(), &bundle_pass)
        .await
        .map_err(|e| key_error(&e))?;
    tracing::info!(zone = ?body.zone, "dnssec keys exported");
    Ok(Json(KeyBackup {
        bundle: STANDARD.encode(bundle),
    }))
}

/// Change the key passphrase: every stored private key is re-encrypted under the new one in a
/// single transaction (all or none). Keys stored unencrypted become encrypted. The running
/// server uses the new passphrase at once; update `DNSY_DNSSEC_PASSPHRASE` or the passphrase
/// file before the next start, or the keys cannot be read.
#[utoipa::path(post, path = "/dnssec/passphrase", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    request_body = ChangePassphraseInput,
    responses(
        (status = 200, body = PassphraseChanged),
        (status = 422, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn change_passphrase(
    _scope: RequireScope<AdminScope>,
    State(state): State<ApiState>,
    Json(body): Json<ChangePassphraseInput>,
) -> Result<Json<PassphraseChanged>, ApiError> {
    let signing = signing(&state)?;
    let new = passphrase(&body.new_passphrase)?;
    let keys_reencrypted = signing
        .keys()
        .change_passphrase(new)
        .await
        .map_err(|e| key_error(&e))?;
    tracing::info!(keys = keys_reencrypted, "dnssec key passphrase changed");
    Ok(Json(PassphraseChanged { keys_reencrypted }))
}

// ---------------------------------------------------------------------------------------
// DS export

/// DS records (SHA-256 and SHA-384) and DNSKEY records of the zone's KSKs and CSKs, for the
/// parent zone or registrar. JSON by default; `Accept: text/plain` returns zone-file lines.
#[utoipa::path(get, path = "/zones/{name}/dnssec/ds", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    responses(
        (status = 200, description = "DS and DNSKEY records; `text/plain` (zone-file lines) when asked for by `Accept`",
            body = DsExport),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn ds_export(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let signing = signing(&state)?;
    let (_, zone) = existing(&state, &name)?;
    let mut export = DsExport {
        zone: zone.origin.to_string(),
        ds: Vec::new(),
        dnskey: Vec::new(),
    };
    let sep_keys = signing
        .keys()
        .dnskeys(&zone.origin)
        .await
        .map_err(|e| key_error(&e))?
        .into_iter()
        .filter(|(rec, _)| {
            rec.role.is_sep() && matches!(rec.state, KeyState::Published | KeyState::Active)
        });
    for (rec, dnskey) in sep_keys {
        for digest in [DigestType::Sha256, DigestType::Sha384] {
            let ds = ds_for(&zone.origin, &dnskey, digest)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            export.ds.push(DsRecordView {
                key_id: rec.id,
                key_tag: ds.key_tag,
                algorithm: ds.algorithm,
                digest_type: ds.digest_type,
                digest: hex_upper(&ds.digest),
                record: format!("{} IN DS {ds}", zone.origin),
            });
        }
        export.dnskey.push(DnskeyRecordView {
            key_id: rec.id,
            key_tag: dnskey.key_tag(),
            flags: dnskey.flags,
            protocol: dnskey.protocol,
            algorithm: dnskey.algorithm,
            public_key: STANDARD.encode(&dnskey.public_key),
            record: format!("{} IN DNSKEY {dnskey}", zone.origin),
        });
    }
    let wants_text = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/plain") && !a.contains("application/json"));
    if wants_text {
        let mut text = String::new();
        for line in export
            .ds
            .iter()
            .map(|d| &d.record)
            .chain(export.dnskey.iter().map(|k| &k.record))
        {
            text.push_str(line);
            text.push('\n');
        }
        return Ok((
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            text,
        )
            .into_response());
    }
    Ok(Json(export).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_errors_map_to_problems() {
        assert!(matches!(
            key_error(&KeyStoreError::NotFound(1)),
            ApiError::NotFound(_)
        ));
        assert!(matches!(
            key_error(&KeyStoreError::NoActiveKey(KeyRole::Ksk)),
            ApiError::Conflict(_)
        ));
        assert!(matches!(
            key_error(&KeyStoreError::InvalidState("x")),
            ApiError::Conflict(_)
        ));
        // Everything else is hidden from the client.
        assert!(matches!(
            key_error(&KeyStoreError::Decrypt),
            ApiError::Internal(_)
        ));
        assert!(matches!(
            key_error(&KeyStoreError::PassphraseRequired),
            ApiError::Internal(_)
        ));
    }
}
