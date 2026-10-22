//! Request and response types of the DNSSEC routes.

use std::collections::BTreeMap;

use dnsy_config::Validation;
use dnsy_keys::KeyRole;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zeroize::Zeroizing;

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
    /// Seconds added to the DNSKEY TTL before a published key may sign (default 3600,
    /// at most 604800).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagation_delay: Option<u32>,
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

/// One rollover under way: a role with an incoming key.
#[derive(Debug, Serialize, ToSchema)]
pub struct RolloverRoleView {
    /// `csk`, `ksk` or `zsk`.
    pub role: String,
    /// `in_progress` or `awaiting_ds_confirmation`.
    pub state: String,
    /// The incoming key.
    pub new_key_id: i64,
}

/// Where the key rollover stands.
#[derive(Debug, Serialize, ToSchema)]
pub struct RolloverView {
    /// `idle`, `in_progress`, or `awaiting_ds_confirmation` when any rollover waits for the
    /// registrar's DS.
    pub state: String,
    /// Role of the first rollover in `rollovers`; use `rollovers` to see them all.
    pub role: Option<String>,
    /// The incoming key of the first rollover in `rollovers`.
    pub new_key_id: Option<i64>,
    /// Every rollover under way (a KSK and a ZSK rollover can run at the same time).
    pub rollovers: Vec<RolloverRoleView>,
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
    pub propagation_delay: u32,
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

/// Which rollover to abort.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AbortRolloverInput {
    /// Abort only this role's rollover; omitted aborts every rollover of the zone.
    pub role: Option<KeyRoleBody>,
}

/// Key export request.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportKeysInput {
    /// Passphrase the bundle is encrypted under (at least 12 characters). It may differ from
    /// the key passphrase; keep it apart from the bundle. Wiped from memory on drop.
    #[schema(value_type = String)]
    pub passphrase: Zeroizing<String>,
    /// Export only this zone's keys; omitted exports every zone's.
    pub zone: Option<String>,
}

impl std::fmt::Debug for ExportKeysInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportKeysInput")
            .field("zone", &self.zone)
            .finish_non_exhaustive()
    }
}

/// An encrypted key backup.
#[derive(Debug, Serialize, ToSchema)]
pub struct KeyBackup {
    /// Base64 of the bundle: every non-removed key, sealed with AES-256-GCM under a key
    /// derived from the request's passphrase. `dnsy dnssec keys import` restores it.
    pub bundle: String,
}

/// Key passphrase change.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangePassphraseInput {
    /// The new key passphrase (at least 12 characters). Wiped from memory on drop.
    #[schema(value_type = String)]
    pub new_passphrase: Zeroizing<String>,
}

impl std::fmt::Debug for ChangePassphraseInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePassphraseInput")
            .finish_non_exhaustive()
    }
}

/// Result of a key passphrase change.
#[derive(Debug, Serialize, ToSchema)]
pub struct PassphraseChanged {
    /// Keys re-encrypted under the new passphrase.
    pub keys_reencrypted: usize,
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
    /// Names at or below which validation is skipped (RFC 7646); expired entries are left out.
    pub negative_trust_anchors: Vec<String>,
    /// The same anchors with their expiry.
    pub negative_trust_anchor_entries: Vec<NtaView>,
    pub trust_anchors: Vec<TrustAnchorView>,
}

/// A negative trust anchor in force.
#[derive(Debug, Serialize, ToSchema)]
pub struct NtaView {
    pub name: String,
    /// Unix time at which the anchor stops applying; `None` until it is removed.
    pub expires_at: Option<i64>,
}

/// A negative trust anchor to set: a bare name, or a name with an optional expiry.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum NtaInput {
    Name(String),
    Entry(NtaEntryInput),
}

/// A negative trust anchor with an optional expiry.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NtaEntryInput {
    pub name: String,
    /// Unix time (in the future) at which the anchor stops applying; omitted keeps it until
    /// removed.
    pub expires_at: Option<i64>,
}

/// Validation settings changes. Applied at once; not persisted across restarts (the
/// configuration file is the source at startup). Changing the mode or the negative trust
/// anchors flushes the cache.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidationPatch {
    pub validation: Option<ValidationMode>,
    /// Replaces the whole list; `[]` clears it. An entry is a name, or `{name, expires_at}`
    /// for an anchor that stops applying at `expires_at` (Unix time).
    pub negative_trust_anchors: Option<Vec<NtaInput>>,
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
