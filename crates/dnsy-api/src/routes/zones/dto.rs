//! Request and response types of the zone routes.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

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
    pub(super) fn into_parts(self) -> (String, ZoneBody) {
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

/// Export options.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExportParams {
    /// Export the signed zone: adds DNSKEY, RRSIG, NSEC or NSEC3 and NSEC3PARAM records.
    #[serde(default)]
    pub(super) signed: bool,
}
