use std::net::IpAddr;

use dnsy_core::DnssecStatus;
use dnsy_proto::{Rcode, RecordType};
use dnsy_store::Store;
use rusqlite::params_from_iter;
use rusqlite::types::Value;

use crate::ObserveError;
use crate::event::{
    DNSSEC, SOURCES, SourceKind, TRANSPORTS, client_bytes, client_from_bytes, dnssec_code, name_of,
};

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

/// The predicate of `query_log_rare` (migrations 0011, 0015; source codes 4 to 6 are blocked,
/// refused, error), verbatim: SQLite uses a partial index only
/// when the query's WHERE clause contains the index's predicate.
const RARE_PREDICATE: &str = "(source IN (4, 5, 6) OR rcode NOT IN (0, 3))";

fn is_rare(q: &QueryLogQuery) -> bool {
    q.source.is_some_and(|s| {
        matches!(
            s,
            SourceKind::Blocked | SourceKind::Refused | SourceKind::Error
        )
    }) || q.rcode.is_some_and(|r| !matches!(u16::from(r), 0 | 3))
}

/// The statement and its arguments for `q`.
fn build(q: &QueryLogQuery, limit: usize) -> (String, Vec<Value>) {
    let mut clauses: Vec<&str> = Vec::new();
    let mut args: Vec<Value> = Vec::new();
    if is_rare(q) {
        clauses.push(RARE_PREDICATE);
    }
    let mut add = |clause: &'static str, vals: &[Value]| {
        clauses.push(clause);
        args.extend_from_slice(vals);
    };
    if let Some(v) = q.from_ms {
        add("ts_ms >= ?", &[v.into()]);
    }
    // The cursor also bounds the time range from above (`ts_ms <= cursor.ts_ms`), so the planner
    // starts at the cursor instead of walking every newer row. It is folded into the one upper
    // bound: with `to_ms` present SQLite uses only one of two upper bounds and prefers `to_ms`.
    let upper = match (q.to_ms, q.after) {
        (Some(to), Some(c)) => Some(to.min(c.ts_ms.saturating_add(1))),
        (Some(v), None) => Some(v),
        (None, Some(c)) => Some(c.ts_ms.saturating_add(1)),
        (None, None) => None,
    };
    if let Some(v) = upper {
        add("ts_ms < ?", &[v.into()]);
    }
    if let Some(v) = q.client {
        let mut buf = [0; 16];
        let n = client_bytes(&v, &mut buf);
        add("client = ?", &[buf[..n].to_vec().into()]);
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
        add("source = ?", &[i64::from(v.code()).into()]);
    }
    if let Some(v) = q.dnssec {
        add("dnssec = ?", &[i64::from(dnssec_code(v)).into()]);
    }
    if let Some(c) = q.after {
        // The tie-break; the time bound above is what lets the index start at the cursor.
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
    (sql, args)
}

fn bad_column(idx: usize, what: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        idx,
        rusqlite::types::Type::Blob,
        format!("stored {what} is not valid").into(),
    )
}

/// The text name of the stored code in column `idx`.
fn code_name(
    r: &rusqlite::Row<'_>,
    idx: usize,
    table: &'static [&'static str],
    what: &str,
) -> rusqlite::Result<String> {
    name_of(table, r.get(idx)?)
        .map(str::to_owned)
        .ok_or_else(|| bad_column(idx, what))
}

/// Keyset-paginated query-log search, ordered by `(ts_ms, id)` descending.
pub async fn search(store: &Store, q: QueryLogQuery) -> Result<LogPage, ObserveError> {
    let limit = q.limit.clamp(1, MAX_LIMIT);
    let (sql, args) = build(&q, limit);
    let mut entries = store
        .read(move |c| {
            let mut stmt = c.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(args), |r| {
                let client: Vec<u8> = r.get(2)?;
                Ok(LogEntry {
                    id: r.get(0)?,
                    ts_ms: r.get(1)?,
                    client: client_from_bytes(&client)
                        .ok_or_else(|| bad_column(2, "client address"))?
                        .to_string(),
                    transport: code_name(r, 3, &TRANSPORTS, "transport")?,
                    principal: r.get(4)?,
                    qname: r.get(5)?,
                    qtype: r.get(6)?,
                    rcode: r.get(7)?,
                    source: code_name(r, 8, &SOURCES, "source")?,
                    source_detail: r.get(9)?,
                    dnssec: code_name(r, 10, &DNSSEC, "dnssec status")?,
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

    #[tokio::test]
    async fn compact_columns_read_back_as_the_same_text() {
        let (store, _d) = open_store();
        let mut e = event("v6.example.", 10);
        e.client = "2001:db8::8a2e:370:7334".parse().unwrap();
        e.transport = dnsy_core::Transport::Doh;
        e.dnssec = DnssecStatus::Indeterminate;
        e.source = AnswerSource::CacheStale;
        ingest(&store, vec![e, event("v4.example.", 11)]).await;
        let page = search(
            &store,
            QueryLogQuery {
                limit: 10,
                client: Some("2001:db8::8a2e:370:7334".parse().unwrap()),
                dnssec: Some(DnssecStatus::Indeterminate),
                source: Some(SourceKind::CacheStale),
                ..QueryLogQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(page.entries.len(), 1);
        let got = &page.entries[0];
        assert_eq!(got.client, "2001:db8::8a2e:370:7334");
        assert_eq!(got.transport, "doh");
        assert_eq!(got.dnssec, "indeterminate");
        assert_eq!(got.source, "cache_stale");
        let all = search(
            &store,
            QueryLogQuery {
                limit: 10,
                ..QueryLogQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(all.entries[0].client, "192.0.2.77");
        assert_eq!(all.entries[0].transport, "udp");
        assert_eq!(all.entries[0].source, "upstream");
    }

    #[tokio::test]
    async fn an_unknown_stored_code_is_an_error_not_a_guess() {
        let (store, _d) = open_store();
        ingest(&store, vec![event("a.example.", 1)]).await;
        store
            .write(|t| {
                // The CHECK constraints refuse a bad code; this simulates a newer writer.
                t.execute_batch(
                    "PRAGMA ignore_check_constraints = ON; UPDATE query_log SET source = 99;",
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let r = search(
            &store,
            QueryLogQuery {
                limit: 10,
                ..QueryLogQuery::default()
            },
        )
        .await;
        assert!(r.is_err());
    }

    /// 10 000 rows over 10 clients, a rare row every 97th; ts = i / 3 so timestamps repeat.
    async fn generated(store: &Store) {
        store
            .write(|t| {
                t.execute_batch(
                    "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 9999)
                     INSERT INTO query_log (ts_ms, client, transport, principal, qname, qtype, rcode,
                                            source, source_detail, dnssec, latency_us)
                     SELECT i / 3, unhex('C00002' || printf('%02x', i % 10)), 0, NULL, 'h' || i || '.example.', 1,
                            CASE WHEN i % 97 = 0 THEN 2 ELSE 0 END,
                            CASE WHEN i % 97 = 1 THEN 5 ELSE 3 END,
                            NULL, 0, 10 FROM n;
                     ANALYZE;",
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }

    async fn plan(store: &Store, q: &QueryLogQuery) -> String {
        let (sql, args) = build(q, q.limit.clamp(1, MAX_LIMIT));
        store
            .read(move |c| {
                let mut st = c.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
                let rows = st.query_map(params_from_iter(args), |r| r.get::<_, String>(3))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn cursor_page_plan_uses_index_bound() {
        let (store, _d) = open_store();
        generated(&store).await;
        let q = QueryLogQuery {
            limit: 50,
            after: Some(Cursor {
                ts_ms: 1500,
                id: 4000,
            }),
            ..QueryLogQuery::default()
        };
        let p = plan(&store, &q).await;
        assert!(
            p.contains("SEARCH query_log USING INDEX query_log_ts"),
            "{p}"
        );
        assert!(
            p.contains("ts_ms<?"),
            "the cursor must bound the index range: {p}"
        );
    }

    /// The UI sends a range and a cursor together; SQLite uses only one upper bound, so the one
    /// it gets must be the cursor's.
    #[test]
    fn the_cursor_is_the_upper_bound_even_with_a_range() {
        let after = Some(Cursor {
            ts_ms: 1500,
            id: 4000,
        });
        let ts_bounds = |q: &QueryLogQuery| {
            let (sql, args) = build(q, 10);
            assert_eq!(sql.matches("ts_ms < ?").count(), 2, "{sql}");
            args
        };
        let base = QueryLogQuery {
            limit: 10,
            after,
            ..QueryLogQuery::default()
        };
        let args = ts_bounds(&base);
        assert_eq!(args[0], Value::Integer(1501));
        let wide = QueryLogQuery {
            from_ms: Some(100),
            to_ms: Some(900_000),
            ..base.clone()
        };
        let args = ts_bounds(&wide);
        assert_eq!(
            args[1],
            Value::Integer(1501),
            "a later `to` must not win: {args:?}"
        );
        let narrow = QueryLogQuery {
            to_ms: Some(1000),
            ..base
        };
        assert_eq!(
            ts_bounds(&narrow)[0],
            Value::Integer(1000),
            "an earlier `to` stays"
        );
    }

    #[tokio::test]
    async fn paging_ten_thousand_rows_matches_a_plain_ordered_scan() {
        let (store, _d) = open_store();
        generated(&store).await;
        let expected: Vec<i64> = store
            .read(|c| {
                let mut st = c.prepare("SELECT id FROM query_log ORDER BY ts_ms DESC, id DESC")?;
                Ok(st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
            })
            .await
            .unwrap();
        assert_eq!(expected.len(), 10_000);
        let mut seen = Vec::new();
        let mut after = None;
        loop {
            let page = search(
                &store,
                QueryLogQuery {
                    limit: 997,
                    after,
                    ..QueryLogQuery::default()
                },
            )
            .await
            .unwrap();
            seen.extend(page.entries.iter().map(|e| e.id));
            match page.next {
                Some(c) => after = Some(c),
                None => break,
            }
        }
        assert_eq!(seen, expected);
    }

    #[tokio::test]
    async fn client_filter_uses_the_client_index_without_a_sort() {
        let (store, _d) = open_store();
        generated(&store).await;
        let p = plan(
            &store,
            &QueryLogQuery {
                limit: 50,
                client: Some("192.0.2.3".parse().unwrap()),
                ..QueryLogQuery::default()
            },
        )
        .await;
        assert!(p.contains("USING INDEX query_log_client (client=?"), "{p}");
        assert!(!p.contains("TEMP B-TREE"), "{p}");
    }

    #[tokio::test]
    async fn rare_outcomes_use_the_partial_index() {
        let (store, _d) = open_store();
        generated(&store).await;
        for f in [
            (|q: &mut QueryLogQuery| q.source = Some(SourceKind::Refused))
                as fn(&mut QueryLogQuery),
            |q| q.source = Some(SourceKind::Blocked),
            |q| q.source = Some(SourceKind::Error),
            |q| q.rcode = Some(Rcode::ServFail),
        ] {
            let mut q = QueryLogQuery {
                limit: 50,
                ..QueryLogQuery::default()
            };
            f(&mut q);
            let p = plan(&store, &q).await;
            assert!(p.contains("USING INDEX query_log_rare"), "{q:?}: {p}");
            assert!(!p.contains("TEMP B-TREE"), "{p}");
        }
        // Common values are not rewritten: the predicate would only add work.
        let (sql, _) = build(
            &QueryLogQuery {
                source: Some(SourceKind::Upstream),
                rcode: Some(Rcode::NxDomain),
                ..QueryLogQuery::default()
            },
            10,
        );
        assert!(!sql.contains("NOT IN (0, 3)"), "{sql}");
    }

    #[tokio::test]
    async fn rare_filters_return_the_same_rows_as_without_the_predicate() {
        let (store, _d) = open_store();
        generated(&store).await;
        let page = search(
            &store,
            QueryLogQuery {
                limit: 1000,
                source: Some(SourceKind::Refused),
                ..QueryLogQuery::default()
            },
        )
        .await
        .unwrap();
        let expected: i64 = store
            .read(|c| {
                Ok(
                    c.query_row("SELECT count(*) FROM query_log WHERE source = 5", [], |r| {
                        r.get(0)
                    })?,
                )
            })
            .await
            .unwrap();
        assert_eq!(i64::try_from(page.entries.len()).unwrap(), expected);
        assert!(expected > 100);
    }
}
