//! Zones, their records and BIND export.
//!
//! Zones live as JSON files in the zones directory ([`dnsy_zone::ZoneStore`]). Every edit goes
//! through [`ZoneStore::update`], which owns the lock, the serial bump and the atomic write; the
//! candidate zone is parsed again by [`Zone::from_json`], so API writes obey exactly the rules of
//! files on disk. This module maps requests onto it. Zone names are validated through
//! [`zone_file_name`] (lowercase `[a-z0-9.-]`), so a name can never leave the zones directory.
//! Writes honour `If-Match` against the zone's `ETag`.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::Json;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use dnsy_proto::Name;
use dnsy_zone::{Record, RecordId, Zone, ZoneError, ZoneStore, export_bind, zone_file_name};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::{Read, RequireScope, Write};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

/// Largest request body of the zone routes.
const MAX_BODY_BYTES: usize = 1 << 20;
/// Records one zone may hold.
const MAX_RECORDS: usize = 10_000;
/// Zones the API will create.
const MAX_ZONES: usize = 1_000;
/// Longest record value or name accepted in a request.
const MAX_FIELD_LEN: usize = 4_096;
/// Largest TTL (RFC 2181 section 8).
const MAX_TTL: u32 = 0x7fff_ffff;
const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 1_000;

/// Overview row of a zone.
#[derive(Serialize, ToSchema)]
pub struct ZoneSummary {
    /// Absolute, lowercase zone name.
    pub name: String,
    pub serial: u32,
    pub record_count: usize,
    pub dnssec_enabled: bool,
    /// Why the zone file on disk is not being served, if its latest version is invalid.
    pub load_error: Option<String>,
}

/// The SOA record of a zone.
#[derive(Serialize, Deserialize, ToSchema)]
pub struct SoaBody {
    /// Primary name server.
    pub mname: String,
    /// Responsible mailbox, as a domain name.
    pub rname: String,
    /// Initial serial on create (default 1). Ignored on replace: every write bumps the serial.
    pub serial: Option<u32>,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    /// TTL of the SOA record; defaults to the zone default TTL.
    pub ttl: Option<u32>,
}

/// A zone with its SOA (no records; see `/zones/{name}/records`).
#[derive(Serialize, ToSchema)]
pub struct ZoneDetail {
    pub name: String,
    pub default_ttl: u32,
    pub soa: SoaBody,
    pub record_count: usize,
    pub dnssec_enabled: bool,
    pub load_error: Option<String>,
}

/// A record as written by a client.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordInput {
    /// `@`, a name relative to the zone, or an absolute name ending in a dot.
    pub name: String,
    /// A, AAAA, NS, CNAME, PTR, MX, TXT, SRV or CAA.
    #[serde(rename = "type")]
    pub rtype: String,
    /// Seconds; defaults to the zone default TTL.
    pub ttl: Option<u32>,
    /// Presentation-format rdata, e.g. `10 mail.example.com.`.
    pub value: String,
}

/// A stored record.
#[derive(Serialize, ToSchema)]
pub struct RecordView {
    /// Stable id: hash of owner name, type and value.
    pub id: String,
    /// Absolute owner name.
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub ttl: u32,
    pub value: String,
}

/// Settings and records of a zone, for create and replace.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ZoneBody {
    pub default_ttl: u32,
    pub soa: SoaBody,
    /// Must contain at least one NS record at the apex.
    #[serde(default)]
    pub records: Vec<RecordInput>,
}

/// New zone: the name plus the settings and records of a zone body.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateZone {
    /// Zone name, e.g. `example.com.`.
    pub name: String,
    pub default_ttl: u32,
    pub soa: SoaBody,
    /// Must contain at least one NS record at the apex.
    #[serde(default)]
    pub records: Vec<RecordInput>,
}

impl CreateZone {
    fn into_parts(self) -> (String, ZoneBody) {
        let body = ZoneBody {
            default_ttl: self.default_ttl,
            soa: self.soa,
            records: self.records,
        };
        (self.name, body)
    }
}

/// One page of records.
#[derive(Serialize, ToSchema)]
pub struct RecordPage {
    pub items: Vec<RecordView>,
    /// Records matching the filters, across all pages.
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

/// Paging and filters of the record list.
#[derive(Deserialize, IntoParams)]
pub struct RecordQuery {
    /// Page size (default 100, at most 1000).
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    /// Only this record type.
    #[serde(rename = "type")]
    #[param(rename = "type")]
    pub rtype: Option<String>,
    /// Only this owner name (relative or absolute).
    pub name: Option<String>,
}

/// Routes relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list_zones, create_zone))
        .routes(routes!(get_zone, replace_zone, delete_zone))
        .routes(routes!(list_records, create_record))
        .routes(routes!(replace_record, delete_record))
        .routes(routes!(export_zone))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

// ---------------------------------------------------------------------------------------
// helpers

type Etagged<T> = ([(header::HeaderName, String); 1], T);

fn etagged<T>(zone: &Zone, body: T) -> Etagged<T> {
    ([(header::ETAG, etag(zone))], body)
}

/// Strong validator of the stored state of a zone.
fn etag(zone: &Zone) -> String {
    let digest = Sha256::digest(zone.to_json().as_bytes());
    format!("\"{}\"", hex(&digest[..16]))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn rtype_name(rdata: &dnsy_proto::RData) -> String {
    format!("{:?}", rdata.rtype()).to_ascii_uppercase()
}

fn view(record: &dnsy_zone::Record) -> RecordView {
    let name = record.name.to_lowercase().to_string();
    let rtype = rtype_name(&record.rdata);
    let value = record.rdata.to_string();
    RecordView {
        id: record.id().to_string(),
        name,
        rtype,
        ttl: record.ttl,
        value,
    }
}

fn soa_body(zone: &Zone) -> SoaBody {
    SoaBody {
        mname: zone.soa.mname.to_string(),
        rname: zone.soa.rname.to_string(),
        serial: Some(zone.soa.serial),
        refresh: zone.soa.refresh,
        retry: zone.soa.retry,
        expire: zone.soa.expire,
        minimum: zone.soa.minimum,
        ttl: Some(zone.soa_ttl),
    }
}

fn detail(store: &ZoneStore, zone: &Zone) -> ZoneDetail {
    ZoneDetail {
        name: zone.origin.to_string(),
        default_ttl: zone.default_ttl,
        soa: soa_body(zone),
        record_count: zone.records.len(),
        dnssec_enabled: zone.dnssec.as_ref().is_some_and(|d| d.enabled),
        load_error: zone.file_name().ok().and_then(|f| store.load_error(&f)),
    }
}

pub(super) fn zone_error(e: &ZoneError) -> ApiError {
    match e {
        ZoneError::Invalid(_) | ZoneError::Json(_) => ApiError::Unprocessable(e.to_string()),
        ZoneError::Io(_) => ApiError::Internal(e.to_string()),
        ZoneError::SerialMismatch { .. } => ApiError::PreconditionFailed(
            "the zone changed since it was read; reload it and retry".to_owned(),
        ),
        ZoneError::NoSuchZone(_) | ZoneError::NoSuchRecord(_) => ApiError::NotFound(e.to_string()),
        ZoneError::ZoneExists(_) | ZoneError::Duplicate => ApiError::Conflict(e.to_string()),
    }
}

pub(super) fn store(state: &ApiState) -> Result<&Arc<ZoneStore>, ApiError> {
    state.zones.store.as_ref().ok_or(ApiError::Unavailable)
}

/// Parses a zone name from a path or body. Only names that map to a safe file name pass.
pub(super) fn zone_name(text: &str) -> Result<Name, ApiError> {
    let bad = |why: &str| ApiError::BadRequest(format!("invalid zone name: {why}"));
    if text.len() > 255 {
        return Err(bad("too long"));
    }
    let name = Name::from_ascii(text).map_err(|e| bad(&e.to_string()))?;
    if name.is_root() {
        return Err(bad("the root zone cannot be managed here"));
    }
    zone_file_name(&name).map_err(|_| bad("only letters, digits, '-' and '.' are allowed"))?;
    Ok(name.to_lowercase())
}

pub(super) fn existing(
    state: &ApiState,
    name: &str,
) -> Result<(Arc<ZoneStore>, Arc<Zone>), ApiError> {
    let origin = zone_name(name)?;
    let store = Arc::clone(store(state)?);
    let zone = store
        .snapshot()
        .get(&origin)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("zone {origin} not found")))?;
    Ok((store, zone))
}

fn if_match(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    headers
        .get(header::IF_MATCH)
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|_| ApiError::BadRequest("invalid If-Match header".to_owned()))
        })
        .transpose()
}

fn check_if_match(wanted: Option<&str>, zone: &Zone) -> Result<(), ApiError> {
    let Some(wanted) = wanted else { return Ok(()) };
    let current = etag(zone);
    if wanted
        .split(',')
        .map(str::trim)
        .any(|t| t == "*" || t == current)
    {
        Ok(())
    } else {
        Err(ApiError::PreconditionFailed(
            "the zone changed since it was read; reload it and retry".to_owned(),
        ))
    }
}

/// The serial a write is conditional on: `None` without `If-Match`, otherwise the stored
/// serial once the header matches the stored zone's `ETag` (the store re-checks it under its
/// write lock, so a concurrent write still turns into 412).
fn expected_serial(
    store: &ZoneStore,
    origin: &Name,
    wanted: Option<&str>,
) -> Result<Option<u32>, ApiError> {
    let Some(wanted) = wanted else {
        return Ok(None);
    };
    let zone = store.stored(origin).map_err(|e| zone_error(&e))?;
    check_if_match(Some(wanted), &zone)?;
    Ok(Some(zone.soa.serial))
}

/// Edits a zone on the blocking pool through [`ZoneStore::update`].
pub(super) async fn edit<T: Send + 'static>(
    state: &ApiState,
    origin: Name,
    wanted: Option<String>,
    f: impl FnOnce(&mut Zone) -> Result<T, ZoneError> + Send + 'static,
) -> Result<(Arc<Zone>, T), ApiError> {
    let store = Arc::clone(store(state)?);
    blocking(move || {
        let expected = expected_serial(&store, &origin, wanted.as_deref())?;
        store
            .update(&origin, expected, f)
            .map_err(|e| zone_error(&e))
    })
    .await
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
}

fn check_field(what: &str, value: &str) -> Result<(), ApiError> {
    if value.len() > MAX_FIELD_LEN {
        return Err(ApiError::Unprocessable(format!("{what} is too long")));
    }
    Ok(())
}

fn check_ttl(ttl: Option<u32>) -> Result<(), ApiError> {
    if ttl.is_some_and(|t| t > MAX_TTL) {
        return Err(ApiError::Unprocessable(format!(
            "TTL must not exceed {MAX_TTL}"
        )));
    }
    Ok(())
}

fn check_input(r: &RecordInput) -> Result<(), ApiError> {
    check_field("record name", &r.name)?;
    check_field("record value", &r.value)?;
    check_ttl(r.ttl)
}

fn parse_input(zone: &Zone, r: &RecordInput) -> Result<Record, ZoneError> {
    Record::parse(
        &zone.origin,
        zone.default_ttl,
        &r.name,
        &r.rtype,
        r.ttl,
        &r.value,
    )
}

fn soa_json(soa: &SoaBody, serial: u32) -> Result<Value, ApiError> {
    check_field("soa.mname", &soa.mname)?;
    check_field("soa.rname", &soa.rname)?;
    check_ttl(soa.ttl)?;
    let mut v = json!({
        "mname": soa.mname, "rname": soa.rname, "serial": serial, "refresh": soa.refresh,
        "retry": soa.retry, "expire": soa.expire, "minimum": soa.minimum,
    });
    if let Some(ttl) = soa.ttl {
        v["ttl"] = json!(ttl);
    }
    Ok(v)
}

fn has_apex_ns(zone: &Zone) -> bool {
    zone.records
        .iter()
        .any(|r| r.name == zone.origin && r.rdata.rtype() == dnsy_proto::RecordType::Ns)
}

/// The API's own rules on top of the file rules: size limit, the apex keeps an NS record
/// (`require_ns`), no duplicate records.
fn check_zone(zone: &Zone, require_ns: bool) -> Result<(), ZoneError> {
    if zone.records.len() > MAX_RECORDS {
        return Err(ZoneError::Invalid(format!(
            "a zone holds at most {MAX_RECORDS} records"
        )));
    }
    if require_ns && !has_apex_ns(zone) {
        return Err(ZoneError::Invalid(
            "the zone apex needs at least one NS record".to_owned(),
        ));
    }
    let mut ids: Vec<RecordId> = zone.records.iter().map(Record::id).collect();
    ids.sort_unstable();
    if ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(ZoneError::Duplicate);
    }
    Ok(())
}

/// Parses a new zone document with the file rules and the API's rules.
fn validate_new(doc: &Value) -> Result<Zone, ApiError> {
    let (zone, _) = Zone::from_json(&doc.to_string()).map_err(|e| zone_error(&e))?;
    check_zone(&zone, true).map_err(|e| zone_error(&e))?;
    Ok(zone)
}

// ---------------------------------------------------------------------------------------
// zones

/// List zones.
#[utoipa::path(get, path = "/zones", tag = "zones", security(("bearer" = []), ("session" = [])),
    responses(
        (status = 200, body = Vec<ZoneSummary>),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 503, body = Problem, content_type = "application/problem+json"),
    ))]
async fn list_zones(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
) -> Result<Json<Vec<ZoneSummary>>, ApiError> {
    let store = store(&state)?;
    let out = store
        .snapshot()
        .iter()
        .map(|z| ZoneSummary {
            name: z.origin.to_string(),
            serial: z.soa.serial,
            record_count: z.records.len(),
            dnssec_enabled: z.dnssec.as_ref().is_some_and(|d| d.enabled),
            load_error: z.file_name().ok().and_then(|f| store.load_error(&f)),
        })
        .collect();
    Ok(Json(out))
}

/// Create a zone.
#[utoipa::path(post, path = "/zones", tag = "zones", security(("bearer" = []), ("session" = [])),
    request_body = CreateZone,
    responses(
        (status = 201, description = "Created", body = ZoneDetail,
            headers(("ETag" = String, description = "Validator for If-Match"))),
        (status = 400, description = "Invalid zone name", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The zone exists", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid zone data", body = Problem, content_type = "application/problem+json"),
    ))]
async fn create_zone(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Json(req): Json<CreateZone>,
) -> Result<(StatusCode, Etagged<Json<ZoneDetail>>), ApiError> {
    let (name, body) = req.into_parts();
    let origin = zone_name(&name)?;
    let doc = zone_document(&origin, &body, body.soa.serial.unwrap_or(1))?;
    let zone = validate_new(&doc)?;
    let store = Arc::clone(store(&state)?);
    let out = blocking(move || {
        let zone = store.create(&zone, MAX_ZONES).map_err(|e| zone_error(&e))?;
        Ok((detail(&store, &zone), etag(&zone)))
    })
    .await?;
    Ok((StatusCode::CREATED, ([(header::ETAG, out.1)], Json(out.0))))
}

fn zone_document(origin: &Name, body: &ZoneBody, serial: u32) -> Result<Value, ApiError> {
    check_ttl(Some(body.default_ttl))?;
    if body.records.len() > MAX_RECORDS {
        return Err(ApiError::Unprocessable(format!(
            "a zone holds at most {MAX_RECORDS} records"
        )));
    }
    let records = body
        .records
        .iter()
        .map(|r| {
            check_input(r)?;
            let mut v = json!({"name": r.name, "type": r.rtype, "value": r.value});
            if let Some(ttl) = r.ttl {
                v["ttl"] = json!(ttl);
            }
            Ok(v)
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(json!({
        "schema": 1,
        "origin": origin.to_string(),
        "default_ttl": body.default_ttl,
        "soa": soa_json(&body.soa, serial)?,
        "records": records,
    }))
}

/// Get a zone, with its `load_error` and an `ETag`.
#[utoipa::path(get, path = "/zones/{name}", tag = "zones", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    responses(
        (status = 200, body = ZoneDetail, headers(("ETag" = String, description = "Validator for If-Match"))),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn get_zone(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Etagged<Json<ZoneDetail>>, ApiError> {
    let (store, zone) = existing(&state, &name)?;
    Ok(etagged(&zone, Json(detail(&store, &zone))))
}

/// Replace a zone's settings and records. The DNSSEC policy is kept; the serial is bumped.
#[utoipa::path(put, path = "/zones/{name}", tag = "zones", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    request_body = ZoneBody,
    responses(
        (status = 200, body = ZoneDetail, headers(("ETag" = String, description = "Validator for If-Match"))),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "If-Match does not match", body = Problem, content_type = "application/problem+json"),
        (status = 422, body = Problem, content_type = "application/problem+json"),
    ))]
async fn replace_zone(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ZoneBody>,
) -> Result<Etagged<Json<ZoneDetail>>, ApiError> {
    let origin = zone_name(&name)?;
    let wanted = if_match(&headers)?;
    let doc = zone_document(&origin, &body, 0)?;
    let (new, _) = Zone::from_json(&doc.to_string()).map_err(|e| zone_error(&e))?;
    let (zone, ()) = edit(&state, origin, wanted, move |z| {
        let had_ns = has_apex_ns(z);
        z.default_ttl = new.default_ttl;
        z.soa_ttl = new.soa_ttl;
        z.soa = new.soa;
        z.records = new.records;
        check_zone(z, had_ns)
    })
    .await?;
    let detail = detail(store(&state)?, &zone);
    Ok(etagged(&zone, Json(detail)))
}

/// Delete a zone and its file.
#[utoipa::path(delete, path = "/zones/{name}", tag = "zones", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "If-Match does not match", body = Problem, content_type = "application/problem+json"),
    ))]
async fn delete_zone(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let origin = zone_name(&name)?;
    let wanted = if_match(&headers)?;
    let store = Arc::clone(store(&state)?);
    blocking(move || {
        let expected = expected_serial(&store, &origin, wanted.as_deref())?;
        store
            .remove_zone(&origin, expected)
            .map_err(|e| zone_error(&e))
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------------------
// records

/// List records of a zone (paged). The SOA is part of the zone detail, not listed here.
#[utoipa::path(get, path = "/zones/{name}/records", tag = "zones", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name"), RecordQuery),
    responses(
        (status = 200, body = RecordPage, headers(("ETag" = String, description = "Validator for If-Match"))),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
    ))]
async fn list_records(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(q): Query<RecordQuery>,
) -> Result<Etagged<Json<RecordPage>>, ApiError> {
    let (_, zone) = existing(&state, &name)?;
    let limit = q.limit.unwrap_or(DEFAULT_PAGE);
    if limit == 0 || limit > MAX_PAGE {
        return Err(ApiError::BadRequest(format!(
            "limit must be between 1 and {MAX_PAGE}"
        )));
    }
    let offset = q.offset.unwrap_or(0);
    let rtype = q.rtype.map(|t| t.to_ascii_uppercase());
    let owner = match q.name.as_deref() {
        None => None,
        Some(n) => Some(owner_filter(&zone, n)?),
    };
    let matching: Vec<RecordView> = zone
        .records
        .iter()
        .map(view)
        .filter(|r| rtype.as_ref().is_none_or(|t| &r.rtype == t))
        .filter(|r| owner.as_ref().is_none_or(|o| &r.name == o))
        .collect();
    let total = matching.len();
    let items = matching.into_iter().skip(offset).take(limit).collect();
    Ok(etagged(
        &zone,
        Json(RecordPage {
            items,
            total,
            limit,
            offset,
        }),
    ))
}

fn owner_filter(zone: &Zone, text: &str) -> Result<String, ApiError> {
    let absolute = if text == "@" {
        zone.origin.to_string()
    } else if text.ends_with('.') {
        text.to_owned()
    } else {
        format!("{text}.{}", zone.origin)
    };
    Name::from_ascii(&absolute)
        .map(|n| n.to_lowercase().to_string())
        .map_err(|e| ApiError::BadRequest(format!("invalid name filter: {e}")))
}

/// Add a record. The SOA serial is bumped.
#[utoipa::path(post, path = "/zones/{name}/records", tag = "zones", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name")),
    request_body = RecordInput,
    responses(
        (status = 201, body = RecordView, headers(("ETag" = String, description = "Validator of the zone after the write"))),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Duplicate record", body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "If-Match does not match", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid name, rdata or TTL, or a CNAME conflict", body = Problem, content_type = "application/problem+json"),
    ))]
async fn create_record(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Json(input): Json<RecordInput>,
) -> Result<(StatusCode, Etagged<Json<RecordView>>), ApiError> {
    let origin = zone_name(&name)?;
    let wanted = if_match(&headers)?;
    check_input(&input)?;
    let (zone, record) = edit(&state, origin, wanted, move |z| {
        let had_ns = has_apex_ns(z);
        let record = parse_input(z, &input)?;
        let view = view(&record);
        z.add_record(record);
        check_zone(z, had_ns)?;
        Ok(view)
    })
    .await?;
    Ok((StatusCode::CREATED, etagged(&zone, Json(record))))
}

/// Replace a record. The id changes when name, type or value change. The serial is bumped.
#[utoipa::path(put, path = "/zones/{name}/records/{id}", tag = "zones", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name"), ("id" = String, Path, description = "Record id")),
    request_body = RecordInput,
    responses(
        (status = 200, body = RecordView, headers(("ETag" = String, description = "Validator of the zone after the write"))),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "Duplicate record", body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "If-Match does not match", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Invalid name, rdata or TTL, a CNAME conflict, or the last apex NS removed", body = Problem, content_type = "application/problem+json"),
    ))]
async fn replace_record(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Path((name, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<RecordInput>,
) -> Result<Etagged<Json<RecordView>>, ApiError> {
    let origin = zone_name(&name)?;
    let wanted = if_match(&headers)?;
    check_input(&input)?;
    let id = RecordId::from(id);
    let (zone, record) = edit(&state, origin, wanted, move |z| {
        let had_ns = has_apex_ns(z);
        let record = parse_input(z, &input)?;
        let view = view(&record);
        z.replace_record(&id, record)?;
        check_zone(z, had_ns)?;
        Ok(view)
    })
    .await?;
    Ok(etagged(&zone, Json(record)))
}

/// Delete a record. The apex keeps at least one NS record. The serial is bumped.
#[utoipa::path(delete, path = "/zones/{name}/records/{id}", tag = "zones", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name"), ("id" = String, Path, description = "Record id")),
    responses(
        (status = 204, description = "Deleted", headers(("ETag" = String, description = "Validator of the zone after the write"))),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "If-Match does not match", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "The last apex NS record cannot be removed", body = Problem, content_type = "application/problem+json"),
    ))]
async fn delete_record(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Path((name, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let origin = zone_name(&name)?;
    let wanted = if_match(&headers)?;
    let id = RecordId::from(id);
    let (zone, ()) = edit(&state, origin, wanted, move |z| {
        let had_ns = has_apex_ns(z);
        z.remove_record(&id)?;
        check_zone(z, had_ns)
    })
    .await?;
    Ok((StatusCode::NO_CONTENT, [(header::ETAG, etag(&zone))]).into_response())
}

// ---------------------------------------------------------------------------------------
// export

/// Export options.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExportParams {
    /// Export the signed zone: adds DNSKEY, RRSIG, NSEC or NSEC3 and NSEC3PARAM records.
    #[serde(default)]
    signed: bool,
}

/// Download the zone as a BIND master file, unsigned or (`signed=true`) with its DNSSEC records.
#[utoipa::path(get, path = "/zones/{name}/export", tag = "zones", security(("bearer" = []), ("session" = [])),
    params(("name" = String, Path, description = "Zone name"), ExportParams),
    responses(
        (status = 200, description = "BIND master file", content_type = "text/dns", body = String),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 404, body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "`signed=true` for a zone that is not signed", body = Problem, content_type = "application/problem+json"),
    ))]
async fn export_zone(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Query(params): Query<ExportParams>,
) -> Result<Response, ApiError> {
    let (store, zone) = existing(&state, &name)?;
    let signed = if params.signed {
        Some(
            store
                .snapshot()
                .signed(&zone.origin)
                .cloned()
                .ok_or_else(|| ApiError::Conflict(format!("zone {} is not signed", zone.origin)))?,
        )
    } else {
        None
    };
    // The file name is `[a-z0-9.-]` by construction of `zone_name`, so it is header-safe.
    let file = zone.file_name().map_err(|e| zone_error(&e))?;
    let file = file.trim_end_matches(".json");
    let suffix = if signed.is_some() { ".signed" } else { "" };
    let disposition =
        HeaderValue::from_str(&format!("attachment; filename=\"{file}{suffix}.zone\""))
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/dns; charset=utf-8"),
            ),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        export_bind(&zone, signed.as_deref()),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use dnsy_core::Role;
    use tower::ServiceExt;

    use super::*;
    use crate::error::PROBLEM_JSON;
    use crate::{ApiConfig, build};

    struct Fx {
        app: Router,
        dir: tempfile::TempDir,
        zones: Arc<ZoneStore>,
        admin: String,
        viewer: String,
    }

    async fn fx() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
        let zones = ZoneStore::open(dir.path().join("zones")).unwrap();
        let mut state = ApiState::new(store);
        state.zones.store = Some(Arc::clone(&zones));
        let mut tokens = Vec::new();
        for (user, role, scopes) in [
            (
                "admin",
                Role::Admin,
                vec![dnsy_core::Scope::ApiRead, dnsy_core::Scope::ApiWrite],
            ),
            ("viewer", Role::Viewer, vec![dnsy_core::Scope::ApiRead]),
        ] {
            let u = state
                .auth
                .users
                .create(user, "pw-pw-pw", role)
                .await
                .unwrap();
            tokens.push(
                state
                    .auth
                    .tokens
                    .create(u.id, "t", &scopes, None)
                    .await
                    .unwrap()
                    .0,
            );
        }
        let app = build(
            state,
            ApiConfig {
                tls: false,
                ..ApiConfig::default()
            },
            Router::new(),
        );
        let viewer = tokens.pop().unwrap();
        let admin = tokens.pop().unwrap();
        Fx {
            app,
            dir,
            zones,
            admin,
            viewer,
        }
    }

    struct Res {
        status: StatusCode,
        headers: HeaderMap,
        body: String,
    }

    impl Res {
        fn json(&self) -> Value {
            serde_json::from_str(&self.body).unwrap()
        }
    }

    async fn call(
        fx: &Fx,
        token: &str,
        method: Method,
        uri: &str,
        extra: &[(&str, &str)],
        body: Option<Value>,
    ) -> Res {
        let mut b = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"));
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string())),
            None => b.body(Body::empty()),
        }
        .unwrap();
        let res = fx.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = res.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 22).await.unwrap();
        Res {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    fn zone_body() -> Value {
        json!({
            "name": "Example.COM",
            "default_ttl": 300,
            "soa": {"mname": "ns1.example.com.", "rname": "hostmaster.example.com.",
                    "refresh": 7200, "retry": 3600, "expire": 1_209_600, "minimum": 300},
            "records": [
                {"name": "@", "type": "NS", "value": "ns1.example.com."},
                {"name": "www", "type": "A", "value": "192.0.2.1"},
            ],
        })
    }

    async fn create(fx: &Fx) -> Res {
        call(
            fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones",
            &[],
            Some(zone_body()),
        )
        .await
    }

    async fn records(fx: &Fx, query: &str) -> Value {
        call(
            fx,
            &fx.admin,
            Method::GET,
            &format!("/api/v1/zones/example.com./records{query}"),
            &[],
            None,
        )
        .await
        .json()
    }

    #[tokio::test]
    async fn create_zone_rejects_unknown_fields() {
        let fx = fx().await;
        let mut body = zone_body();
        body["bogus"] = json!(true);
        let res = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones",
            &[],
            Some(body.clone()),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", res.body);
        assert!(res.body.contains("bogus"), "{}", res.body);
        assert!(fx.zones.snapshot().is_empty());

        assert_eq!(create(&fx).await.status, StatusCode::CREATED);
        body.as_object_mut().unwrap().remove("name");
        let res = call(
            &fx,
            &fx.admin,
            Method::PUT,
            "/api/v1/zones/example.com.",
            &[],
            Some(body),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", res.body);
    }

    #[tokio::test]
    async fn zone_crud_writes_json_file() {
        let fx = fx().await;
        let res = create(&fx).await;
        assert_eq!(res.status, StatusCode::CREATED, "{}", res.body);
        assert_eq!(res.json()["name"], "example.com.");
        let file = fx.dir.path().join("zones/example.com.json");
        assert!(std::fs::read_to_string(&file).unwrap().contains("www"));

        let list = call(&fx, &fx.admin, Method::GET, "/api/v1/zones", &[], None).await;
        assert_eq!(list.json()[0]["record_count"], 2);
        let got = call(
            &fx,
            &fx.admin,
            Method::GET,
            "/api/v1/zones/EXAMPLE.com",
            &[],
            None,
        )
        .await;
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.json()["soa"]["serial"], 1);
        assert!(got.json()["load_error"].is_null());

        let mut replace = zone_body();
        replace.as_object_mut().unwrap().remove("name");
        replace["default_ttl"] = json!(600);
        replace["records"] = json!([{"name": "@", "type": "NS", "value": "ns2.example.com."}]);
        let res = call(
            &fx,
            &fx.admin,
            Method::PUT,
            "/api/v1/zones/example.com.",
            &[],
            Some(replace),
        )
        .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.body);
        assert_eq!(res.json()["soa"]["serial"], 2);
        assert_eq!(res.json()["record_count"], 1);
        assert!(
            std::fs::read_to_string(&file)
                .unwrap()
                .contains("\"default_ttl\": 600")
        );

        let del = call(
            &fx,
            &fx.admin,
            Method::DELETE,
            "/api/v1/zones/example.com.",
            &[],
            None,
        )
        .await;
        assert_eq!(del.status, StatusCode::NO_CONTENT);
        assert!(!file.exists());
        let gone = call(
            &fx,
            &fx.admin,
            Method::GET,
            "/api/v1/zones/example.com.",
            &[],
            None,
        )
        .await;
        assert_eq!(gone.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_zone_rejects_traversal_and_duplicates() {
        let fx = fx().await;
        for bad in [
            "../evil",
            "a/b.example.",
            "..\\evil",
            "a\\046b.example.",
            ".",
            "",
            "under_score.example.",
            "bücher.example.",
        ] {
            let mut body = zone_body();
            body["name"] = json!(bad);
            let res = call(
                &fx,
                &fx.admin,
                Method::POST,
                "/api/v1/zones",
                &[],
                Some(body),
            )
            .await;
            assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}: {}", res.body);
        }
        assert_eq!(create(&fx).await.status, StatusCode::CREATED);
        for dup in ["example.com.", "EXAMPLE.com", "Example.Com."] {
            let mut body = zone_body();
            body["name"] = json!(dup);
            let res = call(
                &fx,
                &fx.admin,
                Method::POST,
                "/api/v1/zones",
                &[],
                Some(body),
            )
            .await;
            assert_eq!(res.status, StatusCode::CONFLICT, "{dup}");
        }
        // Path parameters are validated the same way.
        for uri in [
            "/api/v1/zones/..%2Fetc",
            "/api/v1/zones/a%5Cb.example.",
            "/api/v1/zones/%2e%2e",
        ] {
            let res = call(&fx, &fx.admin, Method::DELETE, uri, &[], None).await;
            assert!(
                res.status == StatusCode::BAD_REQUEST || res.status == StatusCode::NOT_FOUND,
                "{uri}: {}",
                res.status
            );
        }
        // Only the one zone file exists, inside the zones directory.
        let files: Vec<_> = std::fs::read_dir(fx.dir.path().join("zones"))
            .unwrap()
            .collect();
        assert_eq!(files.len(), 1);
    }

    #[tokio::test]
    async fn record_validation_422() {
        let fx = fx().await;
        create(&fx).await;
        let post = |body: Value| {
            call(
                &fx,
                &fx.admin,
                Method::POST,
                "/api/v1/zones/example.com./records",
                &[],
                Some(body),
            )
        };
        for body in [
            json!({"name": "x", "type": "A", "value": "not-an-ip"}),
            json!({"name": "x", "type": "A", "ttl": 2_147_483_648_u32, "value": "192.0.2.9"}),
            json!({"name": "x.other.org.", "type": "A", "value": "192.0.2.9"}),
            json!({"name": "x", "type": "HINFO", "value": "a b"}),
            json!({"name": "x", "type": "SOA", "value": "a b 1 2 3 4 5"}),
            json!({"name": "x", "type": "RRSIG", "value": "x"}),
            // CNAME may not coexist with other data (www has an A record) ...
            json!({"name": "www", "type": "CNAME", "value": "x.example.com."}),
            // ... and the apex cannot be a CNAME.
            json!({"name": "@", "type": "CNAME", "value": "x.example.com."}),
            json!({"name": "x", "type": "TXT", "value": "a".repeat(5000)}),
        ] {
            let res = post(body.clone()).await;
            assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
            assert_eq!(res.headers[header::CONTENT_TYPE], PROBLEM_JSON);
        }
        // Unknown JSON fields are a client error too.
        let res = post(json!({"name": "x", "type": "A", "value": "192.0.2.9", "extra": 1})).await;
        assert!(res.status.is_client_error());
        // Nothing was written.
        assert_eq!(records(&fx, "").await["total"], 2);

        // A CNAME on a fresh name works, and then nothing else may join it.
        let ok = post(json!({"name": "blog", "type": "CNAME", "value": "www.example.com."})).await;
        assert_eq!(ok.status, StatusCode::CREATED, "{}", ok.body);
        let res = post(json!({"name": "blog", "type": "A", "value": "192.0.2.7"})).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn record_crud_bumps_serial_and_ids_are_stable() {
        let fx = fx().await;
        create(&fx).await;
        let page = records(&fx, "").await;
        let www = page["items"][1].clone();
        assert_eq!(www["name"], "www.example.com.");
        assert_eq!(www["type"], "A");
        assert_eq!(www["id"].as_str().unwrap().len(), 16);
        // The id depends only on name, type and value.
        let again = records(&fx, "").await;
        assert_eq!(again["items"][1]["id"], www["id"]);

        let uri = format!(
            "/api/v1/zones/example.com./records/{}",
            www["id"].as_str().unwrap()
        );
        let put = call(
            &fx,
            &fx.admin,
            Method::PUT,
            &uri,
            &[],
            Some(json!({"name": "www", "type": "A", "ttl": 60, "value": "192.0.2.2"})),
        )
        .await;
        assert_eq!(put.status, StatusCode::OK, "{}", put.body);
        assert_ne!(put.json()["id"], www["id"]);
        assert_eq!(put.json()["ttl"], 60);
        // The old id is gone.
        let old = call(&fx, &fx.admin, Method::DELETE, &uri, &[], None).await;
        assert_eq!(old.status, StatusCode::NOT_FOUND);
        // Duplicates are conflicts.
        let dup = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones/example.com./records",
            &[],
            Some(json!({"name": "www.example.com.", "type": "A", "value": "192.0.2.2"})),
        )
        .await;
        assert_eq!(dup.status, StatusCode::CONFLICT);

        let new_uri = format!(
            "/api/v1/zones/example.com./records/{}",
            put.json()["id"].as_str().unwrap()
        );
        let del = call(&fx, &fx.admin, Method::DELETE, &new_uri, &[], None).await;
        assert_eq!(del.status, StatusCode::NO_CONTENT);
        assert!(del.headers.contains_key(header::ETAG));
        let zone = call(
            &fx,
            &fx.admin,
            Method::GET,
            "/api/v1/zones/example.com.",
            &[],
            None,
        )
        .await;
        // create=1, put=2, (dup rejected), delete=3.
        assert_eq!(zone.json()["soa"]["serial"], 3);
        assert_eq!(zone.json()["record_count"], 1);
    }

    #[tokio::test]
    async fn apex_keeps_an_ns_record() {
        let fx = fx().await;
        create(&fx).await;
        let ns = records(&fx, "?type=ns").await["items"][0].clone();
        let uri = format!(
            "/api/v1/zones/example.com./records/{}",
            ns["id"].as_str().unwrap()
        );
        let del = call(&fx, &fx.admin, Method::DELETE, &uri, &[], None).await;
        assert_eq!(del.status, StatusCode::UNPROCESSABLE_ENTITY);
        let put = call(
            &fx,
            &fx.admin,
            Method::PUT,
            &uri,
            &[],
            Some(json!({"name": "sub", "type": "NS", "value": "ns1.example.com."})),
        )
        .await;
        assert_eq!(put.status, StatusCode::UNPROCESSABLE_ENTITY);
        // A second apex NS lets the first go.
        let add = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones/example.com./records",
            &[],
            Some(json!({"name": "@", "type": "NS", "value": "ns2.example.com."})),
        )
        .await;
        assert_eq!(add.status, StatusCode::CREATED);
        let del = call(&fx, &fx.admin, Method::DELETE, &uri, &[], None).await;
        assert_eq!(del.status, StatusCode::NO_CONTENT);
        // Creating a zone without an apex NS is rejected.
        let mut body = zone_body();
        body["name"] = json!("nons.example.");
        body["records"] = json!([]);
        let res = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones",
            &[],
            Some(body),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn records_are_paged_and_filtered() {
        let fx = fx().await;
        let mut body = zone_body();
        let mut rows = vec![json!({"name": "@", "type": "NS", "value": "ns1.example.com."})];
        for i in 0..25 {
            rows.push(
                json!({"name": format!("h{i}"), "type": "A", "value": format!("192.0.2.{i}")}),
            );
        }
        body["records"] = json!(rows);
        assert_eq!(
            call(
                &fx,
                &fx.admin,
                Method::POST,
                "/api/v1/zones",
                &[],
                Some(body)
            )
            .await
            .status,
            StatusCode::CREATED
        );
        let p = records(&fx, "?limit=10&offset=20").await;
        assert_eq!(p["total"], 26);
        assert_eq!(p["items"].as_array().unwrap().len(), 6);
        assert_eq!(records(&fx, "?type=a").await["total"], 25);
        assert_eq!(records(&fx, "?name=h3").await["total"], 1);
        assert_eq!(records(&fx, "?name=@").await["total"], 1);
        for bad in ["?limit=0", "?limit=1001"] {
            let res = call(
                &fx,
                &fx.admin,
                Method::GET,
                &format!("/api/v1/zones/example.com./records{bad}"),
                &[],
                None,
            )
            .await;
            assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
        }
    }

    #[tokio::test]
    async fn if_match_guards_writes() {
        let fx = fx().await;
        let created = create(&fx).await;
        let tag = created.headers[header::ETAG].to_str().unwrap().to_owned();
        let got = call(
            &fx,
            &fx.admin,
            Method::GET,
            "/api/v1/zones/example.com.",
            &[],
            None,
        )
        .await;
        assert_eq!(got.headers[header::ETAG].to_str().unwrap(), tag);

        let rec = json!({"name": "a", "type": "A", "value": "192.0.2.50"});
        let post = |tag: String| {
            let (fx, rec) = (&fx, rec.clone());
            async move {
                call(
                    fx,
                    &fx.admin,
                    Method::POST,
                    "/api/v1/zones/example.com./records",
                    &[("if-match", tag.as_str())],
                    Some(rec),
                )
                .await
            }
        };
        let stale = post("\"deadbeef\"".to_owned()).await;
        assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
        let ok = post(tag.clone()).await;
        assert_eq!(ok.status, StatusCode::CREATED);
        // The old tag is now stale.
        let del = call(
            &fx,
            &fx.admin,
            Method::DELETE,
            "/api/v1/zones/example.com.",
            &[("if-match", &tag)],
            None,
        )
        .await;
        assert_eq!(del.status, StatusCode::PRECONDITION_FAILED);
        let del = call(
            &fx,
            &fx.admin,
            Method::DELETE,
            "/api/v1/zones/example.com.",
            &[("if-match", "*")],
            None,
        )
        .await;
        assert_eq!(del.status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn export_returns_bind_text() {
        let fx = fx().await;
        create(&fx).await;
        let res = call(
            &fx,
            &fx.viewer,
            Method::GET,
            "/api/v1/zones/example.com./export",
            &[],
            None,
        )
        .await;
        assert_eq!(res.status, StatusCode::OK);
        assert!(
            res.headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/dns")
        );
        assert_eq!(
            res.headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"example.com.zone\""
        );
        assert!(res.body.starts_with("$ORIGIN example.com."), "{}", res.body);
        assert!(res.body.contains("SOA"));
        assert!(res.body.contains("192.0.2.1"));
        let missing = call(
            &fx,
            &fx.viewer,
            Method::GET,
            "/api/v1/zones/nope.example./export",
            &[],
            None,
        )
        .await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn authorisation_and_availability() {
        let fx = fx().await;
        create(&fx).await;
        // Viewers read but cannot write.
        let get = call(&fx, &fx.viewer, Method::GET, "/api/v1/zones", &[], None).await;
        assert_eq!(get.status, StatusCode::OK);
        let post = call(
            &fx,
            &fx.viewer,
            Method::POST,
            "/api/v1/zones/example.com./records",
            &[],
            Some(json!({"name": "a", "type": "A", "value": "192.0.2.1"})),
        )
        .await;
        assert_eq!(post.status, StatusCode::FORBIDDEN);
        let del = call(
            &fx,
            &fx.viewer,
            Method::DELETE,
            "/api/v1/zones/example.com.",
            &[],
            None,
        )
        .await;
        assert_eq!(del.status, StatusCode::FORBIDDEN);
        // No credentials.
        let anon = fx
            .app
            .clone()
            .oneshot(Request::get("/api/v1/zones").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);

        // Without a zones directory the routes answer 503.
        let dir = tempfile::tempdir().unwrap();
        let store = dnsy_store::Store::open(&dir.path().join("t.db")).unwrap();
        let state = ApiState::new(store);
        let u = state
            .auth
            .users
            .create("a", "pw-pw-pw", Role::Admin)
            .await
            .unwrap();
        let (tok, _) = state
            .auth
            .tokens
            .create(u.id, "t", &[dnsy_core::Scope::ApiRead], None)
            .await
            .unwrap();
        let bare = Fx {
            app: build(
                state,
                ApiConfig {
                    tls: false,
                    ..ApiConfig::default()
                },
                Router::new(),
            ),
            zones: ZoneStore::open(dir.path().join("unused")).unwrap(),
            dir,
            admin: tok.clone(),
            viewer: tok,
        };
        let res = call(&bare, &bare.admin, Method::GET, "/api/v1/zones", &[], None).await;
        assert_eq!(res.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_and_dnssec_policy_survives() {
        let fx = fx().await;
        let mut body = zone_body();
        body["records"][1]["value"] = json!("a".repeat(MAX_BODY_BYTES));
        let res = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/api/v1/zones",
            &[],
            Some(body),
        )
        .await;
        assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);

        // A DNSSEC policy written to the file is preserved by replace and record writes.
        create(&fx).await;
        let path = fx.dir.path().join("zones/example.com.json");
        let mut doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        doc["dnssec"] = json!({"enabled": false, "algorithm": 13, "key_layout": "csk",
            "denial": "nsec3", "nsec3": {"iterations": 0, "salt": "", "opt_out": false},
            "signature_validity_days": 14, "refresh_days": 5, "dnskey_ttl": 3600});
        let (zone, _) = Zone::from_json(&doc.to_string()).unwrap();
        fx.zones.write_zone(&zone).unwrap();
        let mut replace = zone_body();
        replace.as_object_mut().unwrap().remove("name");
        let res = call(
            &fx,
            &fx.admin,
            Method::PUT,
            "/api/v1/zones/example.com.",
            &[],
            Some(replace),
        )
        .await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.body);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"dnssec\""), "{text}");
    }
}
