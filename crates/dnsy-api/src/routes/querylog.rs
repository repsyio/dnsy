//! Query log: filtered keyset-paginated search and the live tail (SSE).

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::IpAddr;

use axum::Json;
use axum::extract::{FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::response::sse::{Event, KeepAlive, Sse};
use dnsy_core::DnssecStatus;
use dnsy_observe::{Cursor, LogEntry, QueryLogQuery, SourceKind, redact_client_ip, search};
use dnsy_proto::{Rcode, RecordType};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::OwnedSemaphorePermit;
use utoipa::{IntoParams, ToSchema};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::auth::{Read, RequireScope, Write};
use crate::error::{ApiError, Problem};
use crate::state::ApiState;

/// `Query` whose rejection is a problem+json 400.
pub(crate) struct Params<T>(pub T);

impl<T: serde::de::DeserializeOwned, S: Send + Sync> FromRequestParts<S> for Params<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(v)| Params(v))
            .map_err(|e| ApiError::BadRequest(scrub(&e.body_text())))
    }
}

/// Latest accepted timestamp: the end of year 9999 in unix milliseconds.
const MAX_MS: i64 = 253_402_300_799_999;

/// Reject timestamps outside `0..=MAX_MS`, so later arithmetic on them cannot overflow.
pub(crate) fn check_ms(what: &str, v: i64) -> Result<i64, ApiError> {
    if (0..=MAX_MS).contains(&v) {
        Ok(v)
    } else {
        Err(ApiError::BadRequest(format!(
            "`{what}` must be unix milliseconds between 0 and {MAX_MS}"
        )))
    }
}

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 500;
/// Rows fetched per live-tail poll.
const TAIL_BATCH: usize = 200;
/// Tolerance for rows whose timestamp is slightly older than the newest seen one.
const TAIL_SKEW_MS: i64 = 5_000;
/// Shortest run of token characters starting with `dnsy_` that is treated as a token.
const TOKEN_MIN_LEN: usize = 40;

/// Routes relative to `/api/v1`.
#[must_use]
pub fn router() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(search_log))
        .routes(routes!(stream_log))
}

/// Filters shared by the search and the live tail.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LogFilter {
    /// Inclusive start, unix milliseconds.
    from: Option<i64>,
    /// Exclusive end, unix milliseconds.
    to: Option<i64>,
    /// Exact client address (the network address when client redaction is on).
    client: Option<String>,
    /// Case-insensitive substring of the query name.
    domain: Option<String>,
    /// Query type by name (`A`, `AAAA`, ...) or number.
    #[serde(rename = "type")]
    #[param(rename = "type")]
    qtype: Option<String>,
    /// Response code by name (`NOERROR`, `NXDOMAIN`, ...) or number.
    outcome: Option<String>,
    /// `authoritative`, `cache`, `cache_stale`, `upstream`, `blocked`, `refused` or `error`.
    source: Option<String>,
    /// `unchecked`, `secure`, `insecure`, `bogus` or `indeterminate`.
    dnssec: Option<String>,
}

/// Search parameters: the [`LogFilter`] fields plus paging.
// `serde(flatten)` cannot carry numbers in a query string, so the fields are repeated.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SearchParams {
    /// Inclusive start, unix milliseconds.
    from: Option<i64>,
    /// Exclusive end, unix milliseconds.
    to: Option<i64>,
    /// Exact client address (the network address when client redaction is on).
    client: Option<String>,
    /// Case-insensitive substring of the query name.
    domain: Option<String>,
    /// Query type by name (`A`, `AAAA`, ...) or number.
    #[serde(rename = "type")]
    #[param(rename = "type")]
    qtype: Option<String>,
    /// Response code by name (`NOERROR`, `NXDOMAIN`, ...) or number.
    outcome: Option<String>,
    /// `authoritative`, `cache`, `cache_stale`, `upstream`, `blocked`, `refused` or `error`.
    source: Option<String>,
    /// `unchecked`, `secure`, `insecure`, `bogus` or `indeterminate`.
    dnssec: Option<String>,
    /// Page size, 1 to 500 (default 100).
    limit: Option<usize>,
    /// `next_cursor` of the previous page.
    cursor: Option<String>,
}

impl SearchParams {
    fn filter(&self) -> LogFilter {
        LogFilter {
            from: self.from,
            to: self.to,
            client: self.client.clone(),
            domain: self.domain.clone(),
            qtype: self.qtype.clone(),
            outcome: self.outcome.clone(),
            source: self.source.clone(),
            dnssec: self.dnssec.clone(),
        }
    }
}

/// One logged query.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogRecord {
    pub id: i64,
    /// Unix milliseconds.
    pub ts_ms: i64,
    /// Client address (truncated to its network when redaction is on).
    pub client: String,
    pub transport: String,
    /// Authenticated principal (`DoH` token name), never a token secret.
    pub principal: Option<String>,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub source: String,
    /// Upstream address or blocklist name.
    pub source_detail: Option<String>,
    pub dnssec: String,
    pub latency_us: u32,
}

/// A page of the query log, newest first.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogPageBody {
    pub entries: Vec<LogRecord>,
    /// Pass as `cursor` for the next page; absent on the last page.
    pub next_cursor: Option<String>,
}

const RECORD_TYPES: &[(&str, RecordType)] = &[
    ("A", RecordType::A),
    ("NS", RecordType::Ns),
    ("CNAME", RecordType::Cname),
    ("SOA", RecordType::Soa),
    ("PTR", RecordType::Ptr),
    ("MX", RecordType::Mx),
    ("TXT", RecordType::Txt),
    ("AAAA", RecordType::Aaaa),
    ("SRV", RecordType::Srv),
    ("DS", RecordType::Ds),
    ("RRSIG", RecordType::Rrsig),
    ("NSEC", RecordType::Nsec),
    ("DNSKEY", RecordType::Dnskey),
    ("NSEC3", RecordType::Nsec3),
    ("NSEC3PARAM", RecordType::Nsec3param),
    ("CDS", RecordType::Cds),
    ("CDNSKEY", RecordType::Cdnskey),
    ("SVCB", RecordType::Svcb),
    ("HTTPS", RecordType::Https),
    ("CAA", RecordType::Caa),
    ("ANY", RecordType::Any),
];

const RCODES: &[(&str, Rcode)] = &[
    ("NOERROR", Rcode::NoError),
    ("FORMERR", Rcode::FormErr),
    ("SERVFAIL", Rcode::ServFail),
    ("NXDOMAIN", Rcode::NxDomain),
    ("NOTIMP", Rcode::NotImp),
    ("REFUSED", Rcode::Refused),
    ("BADVERS", Rcode::BadVers),
];

const SOURCES: &[SourceKind] = &[
    SourceKind::Authoritative,
    SourceKind::Cache,
    SourceKind::CacheStale,
    SourceKind::Upstream,
    SourceKind::Blocked,
    SourceKind::Refused,
    SourceKind::Error,
];

const DNSSEC: &[(&str, DnssecStatus)] = &[
    ("unchecked", DnssecStatus::Unchecked),
    ("secure", DnssecStatus::Secure),
    ("insecure", DnssecStatus::Insecure),
    ("bogus", DnssecStatus::Bogus),
    ("indeterminate", DnssecStatus::Indeterminate),
];

fn bad(what: &str, value: &str) -> ApiError {
    ApiError::BadRequest(format!("unknown {what} `{}`", scrub(value)))
}

fn parse_named<T: Copy + Into<u16>>(
    table: &[(&str, T)],
    from_num: impl Fn(u16) -> T,
    what: &str,
    value: &str,
) -> Result<T, ApiError> {
    if let Some((_, v)) = table.iter().find(|(n, _)| n.eq_ignore_ascii_case(value)) {
        return Ok(*v);
    }
    value
        .parse::<u16>()
        .map(from_num)
        .map_err(|_| bad(what, value))
}

fn name_of<T: Copy + Into<u16>>(table: &[(&str, T)], prefix: &str, v: T) -> String {
    let n: u16 = v.into();
    table
        .iter()
        .find(|(_, t)| (*t).into() == n)
        .map_or_else(|| format!("{prefix}{n}"), |(name, _)| (*name).to_owned())
}

impl LogFilter {
    fn to_query(&self, state: &ApiState) -> Result<QueryLogQuery, ApiError> {
        let from = self.from.map(|v| check_ms("from", v)).transpose()?;
        let to = self.to.map(|v| check_ms("to", v)).transpose()?;
        if let (Some(from), Some(to)) = (from, to)
            && from >= to
        {
            return Err(ApiError::BadRequest(
                "`from` must be before `to`".to_owned(),
            ));
        }
        let client = match &self.client {
            None => None,
            Some(c) => {
                let ip: IpAddr = c.parse().map_err(|_| bad("client address", c))?;
                // Rows are stored redacted, so the filter has to match the stored form.
                Some(if state.redact_client_ip {
                    redact_client_ip(ip)
                } else {
                    ip
                })
            }
        };
        let source = match &self.source {
            None => None,
            Some(s) => Some(
                *SOURCES
                    .iter()
                    .find(|k| k.as_str() == s)
                    .ok_or_else(|| bad("source", s))?,
            ),
        };
        let dnssec = match &self.dnssec {
            None => None,
            Some(s) => Some(
                DNSSEC
                    .iter()
                    .find(|(n, _)| n == s)
                    .ok_or_else(|| bad("dnssec status", s))?
                    .1,
            ),
        };
        Ok(QueryLogQuery {
            from_ms: from,
            to_ms: to,
            client,
            qname_contains: self.domain.clone().filter(|d| !d.is_empty()),
            qtype: self
                .qtype
                .as_deref()
                .map(|t| parse_named(RECORD_TYPES, RecordType::from, "query type", t))
                .transpose()?,
            rcode: self
                .outcome
                .as_deref()
                .map(|t| parse_named(RCODES, Rcode::from, "outcome", t))
                .transpose()?,
            source,
            dnssec,
            limit: 0,
            after: None,
        })
    }
}

fn encode_cursor(c: Cursor) -> String {
    format!("{}.{}", c.ts_ms, c.id)
}

fn decode_cursor(s: &str) -> Result<Cursor, ApiError> {
    let parsed = s
        .split_once('.')
        .and_then(|(t, i)| Some((t.parse().ok()?, i.parse().ok()?)));
    parsed
        .map(|(ts_ms, id)| Cursor { ts_ms, id })
        .ok_or_else(|| ApiError::BadRequest("invalid cursor".to_owned()))
}

/// Replace anything shaped like an API or `DoH` token (`dnsy_` followed by a long run of token
/// characters) with `[redacted]`. Tokens are redacted upstream; this is defence in depth.
pub(crate) fn scrub(s: &str) -> String {
    const PREFIX: &str = "dnsy_";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find(PREFIX) {
        let (head, tail) = rest.split_at(at);
        out.push_str(head);
        let run = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(tail.len());
        if run >= TOKEN_MIN_LEN {
            out.push_str("[redacted]");
            rest = &tail[run..];
        } else {
            out.push_str(PREFIX);
            rest = &tail[PREFIX.len()..];
        }
    }
    out.push_str(rest);
    out
}

fn view_client(state: &ApiState, stored: &str) -> String {
    match stored.parse::<IpAddr>() {
        Ok(ip) if state.redact_client_ip => redact_client_ip(ip).to_string(),
        Ok(_) => stored.to_owned(),
        // Not an address: show nothing rather than guess.
        Err(_) => String::new(),
    }
}

fn record(state: &ApiState, e: LogEntry) -> LogRecord {
    LogRecord {
        id: e.id,
        ts_ms: e.ts_ms,
        client: view_client(state, &e.client),
        transport: e.transport,
        principal: e.principal.map(|p| scrub(&p)),
        qname: scrub(&e.qname),
        qtype: name_of(RECORD_TYPES, "TYPE", RecordType::from(e.qtype)),
        rcode: name_of(RCODES, "RCODE", Rcode::from(e.rcode)),
        source: e.source,
        source_detail: e.source_detail.map(|d| scrub(&d)),
        dnssec: e.dnssec,
        latency_us: e.latency_us,
    }
}

/// Search the query log, newest first.
#[utoipa::path(get, path = "/querylog", tag = "querylog", security(("bearer" = []), ("session" = [])),
    params(SearchParams),
    responses(
        (status = 200, body = LogPageBody),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
    ))]
async fn search_log(
    _scope: RequireScope<Read>,
    State(state): State<ApiState>,
    Params(params): Params<SearchParams>,
) -> Result<Json<LogPageBody>, ApiError> {
    let mut query = params.filter().to_query(&state)?;
    query.limit = params.limit.unwrap_or(DEFAULT_LIMIT);
    if query.limit == 0 || query.limit > MAX_LIMIT {
        return Err(ApiError::BadRequest(format!(
            "`limit` must be between 1 and {MAX_LIMIT}"
        )));
    }
    query.after = params.cursor.as_deref().map(decode_cursor).transpose()?;
    let page = search(&state.store, query)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(LogPageBody {
        entries: page
            .entries
            .into_iter()
            .map(|e| record(&state, e))
            .collect(),
        next_cursor: page.next.map(encode_cursor),
    }))
}

struct Tail {
    state: ApiState,
    query: QueryLogQuery,
    last_id: i64,
    last_ts: Option<i64>,
    pending: VecDeque<Event>,
    _permit: OwnedSemaphorePermit,
}

impl Tail {
    async fn poll(&mut self) {
        let mut q = self.query.clone();
        q.limit = TAIL_BATCH;
        q.from_ms = match (q.from_ms, self.last_ts) {
            (f, None) => f,
            (f, Some(ts)) => Some(f.map_or(ts - TAIL_SKEW_MS, |f| f.max(ts - TAIL_SKEW_MS))),
        };
        let page = match search(&self.state.store, q).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "live tail poll failed");
                return;
            }
        };
        let mut fresh: Vec<LogEntry> = page
            .entries
            .into_iter()
            .filter(|e| e.id > self.last_id)
            .collect();
        // More matching rows exist than one batch holds and every row was new: older ones are
        // skipped so a slow reader never makes the server buffer without bound.
        if page.next.is_some() && fresh.len() == TAIL_BATCH {
            self.pending.push_back(
                Event::default()
                    .event("lagged")
                    .data(r#"{"message":"events were skipped"}"#),
            );
        }
        fresh.reverse();
        for e in fresh {
            self.last_id = self.last_id.max(e.id);
            self.last_ts = Some(self.last_ts.map_or(e.ts_ms, |t| t.max(e.ts_ms)));
            let json = serde_json::to_string(&record(&self.state, e)).unwrap_or_default();
            self.pending
                .push_back(Event::default().event("query").data(json));
        }
    }
}

/// Live tail of the query log as server-sent events.
///
/// Events are named `query` and carry one log record as JSON; `lagged` means rows were
/// skipped because the consumer was too slow. The server polls at its own pace, so a slow
/// consumer never makes it buffer. The number of concurrent streams is capped (429 beyond).
/// Takes the same filters as the search (`from`/`to` bound the stream). Needs `api:write`
/// (operator or admin).
#[utoipa::path(get, path = "/querylog/stream", tag = "querylog", security(("bearer" = []), ("session" = [])),
    params(LogFilter),
    responses(
        (status = 200, description = "text/event-stream", content_type = "text/event-stream"),
        (status = 400, body = Problem, content_type = "application/problem+json"),
        (status = 401, body = Problem, content_type = "application/problem+json"),
        (status = 403, body = Problem, content_type = "application/problem+json"),
        (status = 429, description = "Too many live-tail connections", body = Problem, content_type = "application/problem+json"),
    ))]
async fn stream_log(
    _scope: RequireScope<Write>,
    State(state): State<ApiState>,
    Params(filter): Params<LogFilter>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let query = filter.to_query(&state)?;
    let permit = state
        .live_tail
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::Throttled {
            retry_after_secs: 5,
        })?;
    // Start after the newest existing row.
    let newest = search(
        &state.store,
        QueryLogQuery {
            limit: 1,
            ..QueryLogQuery::default()
        },
    )
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    let (last_id, last_ts) = newest
        .entries
        .first()
        .map_or((0, None), |e| (e.id, Some(e.ts_ms)));
    let tail = Tail {
        state,
        query,
        last_id,
        last_ts,
        pending: VecDeque::new(),
        _permit: permit,
    };
    let stream = futures_util::stream::unfold(tail, |mut tail| async move {
        while tail.pending.is_empty() {
            tokio::time::sleep(tail.state.live_tail_poll).await;
            tail.poll().await;
        }
        let ev = tail.pending.pop_front()?;
        Some((Ok(ev), tail))
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_replaces_only_token_shaped_runs() {
        let token = format!("dnsy_{}_{}", "A".repeat(13), "b".repeat(43));
        assert_eq!(scrub(&format!("x{token}.example.")), "x[redacted].example.");
        assert_eq!(scrub("dnsy_short.example."), "dnsy_short.example.");
        assert_eq!(scrub("no token"), "no token");
    }

    #[test]
    fn cursor_roundtrip_and_garbage() {
        let c = Cursor { ts_ms: 5, id: 9 };
        assert_eq!(decode_cursor(&encode_cursor(c)).unwrap(), c);
        assert!(decode_cursor("nope").is_err());
        assert!(decode_cursor("1.x").is_err());
    }

    #[test]
    fn names_roundtrip() {
        assert_eq!(name_of(RECORD_TYPES, "TYPE", RecordType::Aaaa), "AAAA");
        assert_eq!(
            name_of(RECORD_TYPES, "TYPE", RecordType::Unknown(999)),
            "TYPE999"
        );
        assert_eq!(
            parse_named(RCODES, Rcode::from, "outcome", "nxdomain").unwrap(),
            Rcode::NxDomain
        );
        assert_eq!(
            parse_named(RECORD_TYPES, RecordType::from, "type", "999").unwrap(),
            RecordType::Unknown(999)
        );
        assert!(parse_named(RCODES, Rcode::from, "outcome", "wat").is_err());
    }
}
