use std::net::IpAddr;

use dnsy_core::DnssecStatus;
use dnsy_proto::{Rcode, RecordType};
use dnsy_store::Store;
use rusqlite::params_from_iter;
use rusqlite::types::Value;

use crate::ObserveError;
use crate::event::{SourceKind, dnssec_str};

const MAX_LIMIT: usize = 1000;

/// Position after the last returned row; pass back to fetch the next page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub ts_ms: i64,
    pub id: i64,
}

/// Filters for [`search`]; results are newest first.
#[derive(Debug, Clone, Default)]
pub struct QueryLogQuery {
    /// Inclusive.
    pub from_ms: Option<i64>,
    /// Exclusive.
    pub to_ms: Option<i64>,
    /// Exact stored client address (the redacted network address when redaction is on).
    pub client: Option<IpAddr>,
    /// Case-insensitive substring of the query name.
    pub qname_contains: Option<String>,
    pub qtype: Option<RecordType>,
    pub rcode: Option<Rcode>,
    pub source: Option<SourceKind>,
    pub dnssec: Option<DnssecStatus>,
    /// Page size, clamped to 1..=1000.
    pub limit: usize,
    pub after: Option<Cursor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub id: i64,
    pub ts_ms: i64,
    pub client: String,
    pub transport: String,
    pub principal: Option<String>,
    pub qname: String,
    pub qtype: u16,
    pub rcode: u16,
    pub source: String,
    pub source_detail: Option<String>,
    pub dnssec: String,
    pub latency_us: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogPage {
    pub entries: Vec<LogEntry>,
    /// `Some` when more rows exist.
    pub next: Option<Cursor>,
}

fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Keyset-paginated query-log search, ordered by `(ts_ms, id)` descending.
pub async fn search(store: &Store, q: QueryLogQuery) -> Result<LogPage, ObserveError> {
    let limit = q.limit.clamp(1, MAX_LIMIT);
    let mut clauses: Vec<&str> = Vec::new();
    let mut args: Vec<Value> = Vec::new();
    let mut add = |clause: &'static str, vals: &[Value]| {
        clauses.push(clause);
        args.extend_from_slice(vals);
    };
    if let Some(v) = q.from_ms {
        add("ts_ms >= ?", &[v.into()]);
    }
    if let Some(v) = q.to_ms {
        add("ts_ms < ?", &[v.into()]);
    }
    if let Some(v) = q.client {
        add("client = ?", &[v.to_string().into()]);
    }
    if let Some(v) = &q.qname_contains {
        let pat = format!("%{}%", like_escape(&v.to_ascii_lowercase()));
        add("qname LIKE ? ESCAPE '\\'", &[pat.into()]);
    }
    if let Some(v) = q.qtype {
        add("qtype = ?", &[i64::from(u16::from(v)).into()]);
    }
    if let Some(v) = q.rcode {
        add("rcode = ?", &[i64::from(u16::from(v)).into()]);
    }
    if let Some(v) = q.source {
        add("source = ?", &[v.as_str().to_owned().into()]);
    }
    if let Some(v) = q.dnssec {
        add("dnssec = ?", &[dnssec_str(v).to_owned().into()]);
    }
    if let Some(c) = q.after {
        add(
            "(ts_ms < ? OR (ts_ms = ? AND id < ?))",
            &[c.ts_ms.into(), c.ts_ms.into(), c.id.into()],
        );
    }
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    let sql = format!(
        "SELECT id, ts_ms, client, transport, principal, qname, qtype, rcode, source,
                source_detail, dnssec, latency_us
         FROM query_log {where_sql} ORDER BY ts_ms DESC, id DESC LIMIT {}",
        limit + 1
    );
    let mut entries = store
        .read(move |c| {
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(args), |r| {
                Ok(LogEntry {
                    id: r.get(0)?,
                    ts_ms: r.get(1)?,
                    client: r.get(2)?,
                    transport: r.get(3)?,
                    principal: r.get(4)?,
                    qname: r.get(5)?,
                    qtype: r.get(6)?,
                    rcode: r.get(7)?,
                    source: r.get(8)?,
                    source_detail: r.get(9)?,
                    dnssec: r.get(10)?,
                    latency_us: r.get(11)?,
                })
            })?;
            Ok(rows.collect::<Result<Vec<_>, _>>()?)
        })
        .await?;
    let next = if entries.len() > limit {
        entries.truncate(limit);
        entries.last().map(|e| Cursor {
            ts_ms: e.ts_ms,
            id: e.id,
        })
    } else {
        None
    };
    Ok(LogPage { entries, next })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnswerSource;
    use crate::testutil::{event, ingest, open_store};

    #[tokio::test]
    async fn pagination_is_stable() {
        let (store, _d) = open_store();
        // Equal timestamps exercise the id tiebreak.
        let evs: Vec<_> = (0..25)
            .map(|i| event(&format!("h{i}.example."), 1000 + i64::from(i / 5)))
            .collect();
        ingest(&store, evs).await;

        let mut seen = Vec::new();
        let mut after = None;
        let mut pages = 0;
        loop {
            let page = search(
                &store,
                QueryLogQuery {
                    limit: 7,
                    after,
                    ..QueryLogQuery::default()
                },
            )
            .await
            .unwrap();
            pages += 1;
            seen.extend(page.entries.iter().map(|e| e.id));
            // Rows inserted mid-iteration must not shift later pages.
            if pages == 1 {
                ingest(&store, vec![event("late.example.", 9999)]).await;
            }
            match page.next {
                Some(c) => after = Some(c),
                None => break,
            }
        }
        assert_eq!(pages, 4);
        assert_eq!(seen.len(), 25);
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 25, "no duplicates");
        let first = search(
            &store,
            QueryLogQuery {
                limit: 1,
                ..QueryLogQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(first.entries[0].ts_ms, 9999);
    }

    #[tokio::test]
    async fn filters_combine() {
        let (store, _d) = open_store();
        let mut blocked = event("Ads.Tracker.example.", 2000);
        blocked.source = AnswerSource::Blocked { list: "ads".into() };
        blocked.rcode = Rcode::NxDomain;
        blocked.qtype = RecordType::Aaaa;
        blocked.dnssec = DnssecStatus::Secure;
        blocked.client = "192.0.2.9".parse().unwrap();
        let mut under = event("100%_literal.example.", 3000);
        under.principal = Some("tok".into());
        ingest(&store, vec![event("plain.example.", 1000), blocked, under]).await;

        let q = |f: fn(&mut QueryLogQuery)| {
            let store = store.clone();
            async move {
                let mut q = QueryLogQuery {
                    limit: 50,
                    ..QueryLogQuery::default()
                };
                f(&mut q);
                search(&store, q).await.unwrap().entries
            }
        };
        assert_eq!(q(|_| {}).await.len(), 3);
        assert_eq!(
            q(|q| q.qname_contains = Some("TRACKER".into())).await.len(),
            1
        );
        assert_eq!(q(|q| q.qname_contains = Some("%_".into())).await.len(), 1);
        assert_eq!(q(|q| q.qname_contains = Some("%".into())).await.len(), 1);
        assert_eq!(
            q(|q| q.client = Some("192.0.2.9".parse().unwrap()))
                .await
                .len(),
            1
        );
        assert_eq!(q(|q| q.qtype = Some(RecordType::Aaaa)).await.len(), 1);
        assert_eq!(q(|q| q.rcode = Some(Rcode::NxDomain)).await.len(), 1);
        assert_eq!(q(|q| q.source = Some(SourceKind::Blocked)).await.len(), 1);
        assert_eq!(q(|q| q.dnssec = Some(DnssecStatus::Secure)).await.len(), 1);
        assert_eq!(
            q(|q| {
                q.from_ms = Some(1500);
                q.to_ms = Some(3000);
            })
            .await
            .len(),
            1
        );
        let e = &q(|q| q.source = Some(SourceKind::Blocked)).await[0];
        assert_eq!(e.qname, "ads.tracker.example.");
        assert_eq!(e.source_detail.as_deref(), Some("ads"));
        assert_eq!(
            q(|q| q.qname_contains = Some("literal".into())).await[0]
                .principal
                .as_deref(),
            Some("tok")
        );
    }
}
