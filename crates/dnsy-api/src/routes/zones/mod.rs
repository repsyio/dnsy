//! Zones, their records and BIND export.
//!
//! Zones live as JSON files in the zones directory ([`dnsy_zone::ZoneStore`]). Every edit goes
//! through [`ZoneStore::update`], which owns the lock, the serial bump and the atomic write; the
//! candidate zone is parsed again by [`Zone::from_json`], so API writes obey exactly the rules of
//! files on disk. This module maps requests onto it. Zone names are validated through
//! [`zone_file_name`] (lowercase `[a-z0-9.-]`), so a name can never leave the zones directory.
//! Writes honour `If-Match` against the zone's `ETag`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use dnsy_proto::Name;
use dnsy_zone::{Record, RecordId, Zone, ZoneError, ZoneStore, export_bind, zone_file_name};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::{Read, RequireScope, Write};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

mod dto;

use dto::{
    CreateZone, ExportParams, RecordInput, RecordPage, RecordQuery, RecordView, SoaBody, ZoneBody,
    ZoneDetail, ZoneSummary,
};

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
    format!("\"{}\"", dnsy_core::hex::lower(&digest[..16]))
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
