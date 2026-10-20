//! DNSSEC: zone signing policy, keys, rollover, DS export and validation settings.
//!
//! Key material never leaves the key store: no type in this file can carry a private key, and
//! the key store's errors (which never contain key material either) are mapped to generic
//! problem responses. Mutating routes need the `admin` scope.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use dnsy_config::Validation;
use dnsy_dnssec::{Algorithm, DigestType, KeyRecord, KeyRole, KeyState, ds_for};
use dnsy_observe::{StatsService, TimeRange};
use dnsy_proto::Name;
use dnsy_zone::{Denial, DnssecPolicy, KeyLayout, KeyStoreError, Zone, ZoneSigning};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::zones::{current, existing, mutate, zone_error, zone_name};
use crate::auth::{AdminScope, Read, RequireScope};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;
use crate::validation::{TrustAnchorInfo, ValidationControl, hex_upper};

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
        .routes(routes!(ds_export))
        .routes(routes!(get_validation, patch_validation))
        .routes(routes!(dnssec_status))
}

// ---------------------------------------------------------------------------------------
// types

/// Whether one key signs everything or keys are split into KSK and ZSK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeyLayoutBody {
    Csk,
    KskZsk,
}

/// Authenticated denial of existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DenialBody {
    Nsec,
    Nsec3,
}

/// NSEC3 parameters (RFC 5155, RFC 9276).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Nsec3Body {
    /// Extra hash iterations; 0 unless `allow_nonzero_iterations` is set.
    #[serde(default)]
    pub iterations: u16,
    /// Salt in hexadecimal; empty for none.
    #[serde(default)]
    pub salt: String,
    #[serde(default)]
    pub opt_out: bool,
    /// Accept a non-zero iteration count despite RFC 9276.
    #[serde(default)]
    pub allow_nonzero_iterations: bool,
}

/// Signing policy of a zone. Omitted fields keep their current value (the defaults for a zone
/// that never had a policy).
#[derive(Debug, Deserialize, Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DnssecPolicyInput {
    /// Sign the zone. Turning it on creates the zone's keys.
    pub enabled: bool,
    /// 13 (ECDSAP256SHA256) or 15 (Ed25519). Existing keys are replaced only by a rollover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_layout: Option<KeyLayoutBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial: Option<DenialBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsec3: Option<Nsec3Body>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_validity_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnskey_ttl: Option<u32>,
}

/// Public metadata of a key. There is no private key field.
#[derive(Debug, Serialize, ToSchema)]
pub struct KeyView {
    pub id: i64,
    /// `csk`, `ksk` or `zsk`.
    pub role: String,
    pub algorithm: u8,
    pub key_tag: u16,
    /// `generated`, `published`, `active`, `retired` or `removed`.
    pub state: String,
    pub created_at: i64,
    pub published_at: Option<i64>,
    pub active_at: Option<i64>,
    pub retired_at: Option<i64>,
    pub removed_at: Option<i64>,
    /// When the operator confirmed the DS at the parent (KSK and CSK).
    pub ds_confirmed_at: Option<i64>,
}

/// Where the key rollover stands.
#[derive(Debug, Serialize, ToSchema)]
pub struct RolloverView {
    /// `idle`, `in_progress` or `awaiting_ds_confirmation`.
    pub state: String,
    /// Role being rolled over.
    pub role: Option<String>,
    /// The incoming key.
    pub new_key_id: Option<i64>,
}

/// A zone's DNSSEC state.
#[derive(Debug, Serialize, ToSchema)]
pub struct DnssecView {
    pub enabled: bool,
    pub algorithm: u8,
    pub key_layout: KeyLayoutBody,
    pub denial: DenialBody,
    pub nsec3: Nsec3Body,
    pub signature_validity_days: u32,
    pub refresh_days: u32,
    pub dnskey_ttl: u32,
    /// Keys that are not removed.
    pub keys: Vec<KeyView>,
    /// Unix time from which signatures are refreshed; `None` while the zone is unsigned.
    pub next_resign: Option<i64>,
    pub rollover: RolloverView,
    /// Private keys are encrypted at rest (a key passphrase is configured).
    pub keys_encrypted: bool,
}

/// A new key.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GenerateKeyInput {
    /// `csk`, `ksk` or `zsk`.
    pub role: KeyRoleBody,
    /// 13 or 15; defaults to the zone policy's algorithm.
    pub algorithm: Option<u8>,
}

/// Key role.
#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum KeyRoleBody {
    Csk,
    Ksk,
    Zsk,
}

impl From<KeyRoleBody> for KeyRole {
    fn from(r: KeyRoleBody) -> Self {
        match r {
            KeyRoleBody::Csk => KeyRole::Csk,
            KeyRoleBody::Ksk => KeyRole::Ksk,
            KeyRoleBody::Zsk => KeyRole::Zsk,
        }
    }
}

/// Rollover options.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RolloverInput {
    /// Algorithm of the new key (13 or 15); defaults to the rolled key's algorithm.
    pub algorithm: Option<u8>,
}

/// A DS record to publish at the parent.
#[derive(Debug, Serialize, ToSchema)]
pub struct DsRecordView {
    pub key_id: i64,
    pub key_tag: u16,
    pub algorithm: u8,
    /// 2 (SHA-256) or 4 (SHA-384).
    pub digest_type: u8,
    /// Upper-case hex.
    pub digest: String,
    /// The record in presentation format.
    pub record: String,
}

/// A DNSKEY record, for registrars that take keys instead of digests.
#[derive(Debug, Serialize, ToSchema)]
pub struct DnskeyRecordView {
    pub key_id: i64,
    pub key_tag: u16,
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    /// Base64 public key.
    pub public_key: String,
    /// The record in presentation format.
    pub record: String,
}

/// What to hand the registrar.
#[derive(Debug, Serialize, ToSchema)]
pub struct DsExport {
    pub zone: String,
    /// SHA-256 first, then SHA-384, for each published or active KSK or CSK.
    pub ds: Vec<DsRecordView>,
    pub dnskey: Vec<DnskeyRecordView>,
}

/// Validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ValidationMode {
    /// No validation.
    Off,
    /// Validate; bogus answers are returned without AD.
    Permissive,
    /// Validate; bogus answers become SERVFAIL.
    Strict,
}

impl From<ValidationMode> for Validation {
    fn from(m: ValidationMode) -> Self {
        match m {
            ValidationMode::Off => Validation::Off,
            ValidationMode::Permissive => Validation::Permissive,
            ValidationMode::Strict => Validation::Strict,
        }
    }
}

impl From<Validation> for ValidationMode {
    fn from(m: Validation) -> Self {
        match m {
            Validation::Off => ValidationMode::Off,
            Validation::Permissive => ValidationMode::Permissive,
            Validation::Strict => ValidationMode::Strict,
        }
    }
}

/// A configured trust anchor (read-only; set in the configuration file).
#[derive(Debug, Serialize, ToSchema)]
pub struct TrustAnchorView {
    /// Zone the anchor belongs to (`.` for the root).
    pub owner: String,
    pub key_tag: u16,
    pub algorithm: u8,
    /// `ds` or `dnskey`.
    pub kind: String,
    pub digest_type: Option<u8>,
    pub digest: Option<String>,
}

/// Validation settings.
#[derive(Debug, Serialize, ToSchema)]
pub struct ValidationSettings {
    pub validation: ValidationMode,
    /// Names at or below which validation is skipped (RFC 7646).
    pub negative_trust_anchors: Vec<String>,
    pub trust_anchors: Vec<TrustAnchorView>,
}

/// Validation settings changes. Applied at once; not persisted across restarts (the
/// configuration file is the source at startup). Changing the mode or the negative trust
/// anchors flushes the cache.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidationPatch {
    pub validation: Option<ValidationMode>,
    /// Replaces the whole list; `[]` clears it.
    pub negative_trust_anchors: Option<Vec<String>>,
}

/// Validation counters and clock trust.
#[derive(Debug, Serialize, ToSchema)]
pub struct DnssecStatus {
    /// `None` while the validation control is not wired.
    pub validation: Option<ValidationMode>,
    /// False while the system clock is before the build time: validation is suspended.
    pub clock_trusted: bool,
    /// Window of the counters, milliseconds, ending now.
    pub window_ms: i64,
    /// Answers in the window by DNSSEC status (`unchecked`, `secure`, `insecure`, `bogus`,
    /// `indeterminate`).
    pub counters: BTreeMap<String, u64>,
    pub secure: u64,
    pub bogus: u64,
    /// Zones with signing enabled.
    pub signed_zones: usize,
}

// ---------------------------------------------------------------------------------------
// helpers

fn signing(state: &ApiState) -> Result<&ZoneSigning, ApiError> {
    state.signing.as_ref().ok_or(ApiError::Unavailable)
}

/// The validation control: the one set explicitly, else the engine.
fn validation(state: &ApiState) -> Result<Arc<dyn ValidationControl>, ApiError> {
    state
        .validation
        .clone()
        .or_else(|| {
            state
                .engine
                .clone()
                .map(|e| e as Arc<dyn ValidationControl>)
        })
        .ok_or(ApiError::Unavailable)
}
fn key_error(e: &KeyStoreError) -> ApiError {
    match e {
        KeyStoreError::NotFound(_) => ApiError::NotFound(e.to_string()),
        KeyStoreError::RolloverInProgress(_)
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
    let incoming = keys
        .iter()
        .find(|k| matches!(k.state, KeyState::Generated | KeyState::Published));
    match incoming {
        None => RolloverView {
            state: "idle".to_owned(),
            role: None,
            new_key_id: None,
        },
        Some(k) => RolloverView {
            state: if k.role.is_sep()
                && k.state == KeyState::Published
                && k.ds_confirmed_at.is_none()
            {
                "awaiting_ds_confirmation"
            } else {
                "in_progress"
            }
            .to_owned(),
            role: Some(k.role.to_string()),
            new_key_id: Some(k.id),
        },
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
    let next_resign = state.zones.as_ref().and_then(|z| {
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
    let zone = mutate(&state, move |store| {
        let old = current(store, &origin, None)?;
        let mut doc: Value = serde_json::from_str(&old.to_json()).expect("zone JSON parses");
        let mut policy = match doc.get("dnssec") {
            Some(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        };
        policy.extend(given);
        doc["dnssec"] = Value::Object(policy);
        let (zone, _) = Zone::from_json(&doc.to_string()).map_err(|e| zone_error(&e))?;
        store.write_zone(&zone).map_err(|e| zone_error(&e))?;
        Ok(zone)
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

// ---------------------------------------------------------------------------------------
// validation settings

fn settings_of(control: &dyn ValidationControl) -> ValidationSettings {
    ValidationSettings {
        validation: control.mode().into(),
        negative_trust_anchors: control
            .negative_trust_anchors()
            .iter()
            .map(ToString::to_string)
            .collect(),
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

fn parse_ntas(names: &[String]) -> Result<Vec<Name>, ApiError> {
    if names.len() > MAX_NTAS {
        return Err(ApiError::Unprocessable(format!(
            "at most {MAX_NTAS} negative trust anchors"
        )));
    }
    let mut out: Vec<Name> = Vec::new();
    for text in names {
        let name = Name::from_ascii(text)
            .map_err(|e| ApiError::Unprocessable(format!("invalid name {text:?}: {e}")))?
            .to_lowercase();
        if name.is_root() {
            return Err(ApiError::Unprocessable(
                "a negative trust anchor at the root disables validation; set the mode to off"
                    .to_owned(),
            ));
        }
        if !out.contains(&name) {
            out.push(name);
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
async fn get_validation(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<ValidationSettings>, ApiError> {
    Ok(Json(settings_of(validation(&state)?.as_ref())))
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
async fn patch_validation(
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
        .map(parse_ntas)
        .transpose()?;
    if let Some(mode) = patch.validation {
        control.set_mode(mode.into());
    }
    if let Some(ntas) = ntas {
        control.set_negative_trust_anchors(ntas);
    }
    Ok(Json(settings_of(control.as_ref())))
}

// ---------------------------------------------------------------------------------------
// status

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Validation counters of the last 24 hours and whether the clock is trusted.
#[utoipa::path(get, path = "/dnssec/status", tag = "dnssec", security(("bearer" = []), ("session" = [])),
    responses((status = 200, body = DnssecStatus)))]
async fn dnssec_status(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<DnssecStatus>, ApiError> {
    let to_ms = now_ms();
    let summary = StatsService::new(state.store.clone())
        .summary(TimeRange {
            from_ms: to_ms.saturating_sub(STATUS_WINDOW_MS).max(0),
            to_ms,
        })
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let signed_zones = state.zones.as_ref().map_or(0, |z| {
        z.snapshot()
            .iter()
            .filter(|zone| zone.dnssec.as_ref().is_some_and(|d| d.enabled))
            .count()
    });
    Ok(Json(DnssecStatus {
        validation: validation(&state).ok().map(|v| v.mode().into()),
        clock_trusted: !state
            .dnssec_clock_untrusted
            .load(std::sync::atomic::Ordering::Relaxed),
        window_ms: STATUS_WINDOW_MS,
        counters: summary.by_dnssec,
        secure: summary.secure,
        bogus: summary.bogus,
        signed_zones,
    }))
}

#[cfg(test)]
#[path = "dnssec_tests.rs"]
mod tests;
