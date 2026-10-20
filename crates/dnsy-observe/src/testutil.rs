use std::time::Duration;

use dnsy_core::{DnssecStatus, Transport};
use dnsy_proto::{Name, Rcode, RecordType};
use dnsy_store::Store;

use crate::{AnswerSource, QueryEvent};

pub fn open_store() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("t.db")).unwrap();
    (store, dir)
}

pub fn event(qname: &str, ts_ms: i64) -> QueryEvent {
    QueryEvent {
        ts_unix_ms: ts_ms,
        client: "192.0.2.77".parse().unwrap(),
        transport: Transport::Udp,
        principal: None,
        qname: Name::from_ascii(qname).unwrap(),
        qtype: RecordType::A,
        rcode: Rcode::NoError,
        source: AnswerSource::Upstream("198.51.100.1:53".parse().unwrap()),
        dnssec: DnssecStatus::Unchecked,
        latency_us: 1000,
    }
}

pub async fn count_rows(store: &Store, table: &'static str) -> i64 {
    store
        .read(move |c| Ok(c.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?))
        .await
        .unwrap()
}

pub async fn wait_for_rows(store: &Store, n: i64) {
    for _ in 0..500 {
        if count_rows(store, "query_log").await == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("query_log never reached {n} rows");
}

/// Insert events directly through the writer path and wait for them.
pub async fn ingest(store: &Store, events: Vec<QueryEvent>) {
    let n = events.len();
    let (w, task) = crate::QueryLogWriter::spawn(
        store.clone(),
        crate::WriterConfig {
            flush_interval: Duration::from_millis(10),
            ..crate::WriterConfig::default()
        },
    );
    for e in events {
        crate::QueryEventSink::record(&w, e);
    }
    assert_eq!(w.dropped(), 0, "ingest of {n} events dropped some");
    drop(w);
    task.await.unwrap();
}
