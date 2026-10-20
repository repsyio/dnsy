use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dnsy_store::{Store, StoreError};
use rusqlite::{Transaction, params};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};

use crate::event::{
    QueryEvent, QueryEventSink, SourceKind, dnssec_str, redact_client_ip, transport_str,
};

/// Query-log writer tuning.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    pub channel_capacity: usize,
    pub max_batch: usize,
    pub flush_interval: Duration,
    /// Store /24 (IPv4) or /48 (IPv6) instead of the full client address.
    pub redact_client_ip: bool,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 10_000,
            max_batch: 500,
            flush_interval: Duration::from_secs(1),
            redact_client_ip: false,
        }
    }
}

/// Non-blocking sink feeding a batched SQLite writer task. Cloning shares the
/// channel and the dropped counter.
#[derive(Clone)]
pub struct QueryLogWriter {
    tx: mpsc::Sender<QueryEvent>,
    dropped: Arc<AtomicU64>,
}

impl QueryLogWriter {
    /// Start the writer task. It flushes remaining events and exits once every
    /// clone of the returned writer is dropped.
    #[must_use]
    pub fn spawn(store: Store, config: WriterConfig) -> (QueryLogWriter, JoinHandle<()>) {
        let (writer, rx) = Self::channel(config.channel_capacity);
        let task = tokio::spawn(run(store, config, rx));
        (writer, task)
    }

    pub(crate) fn channel(capacity: usize) -> (QueryLogWriter, mpsc::Receiver<QueryEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        let writer = QueryLogWriter {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        (writer, rx)
    }

    /// Events dropped because the channel was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl QueryEventSink for QueryLogWriter {
    fn record(&self, ev: QueryEvent) {
        if self.tx.try_send(ev).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn run(store: Store, config: WriterConfig, mut rx: mpsc::Receiver<QueryEvent>) {
    let max_batch = config.max_batch.max(1);
    while let Some(first) = rx.recv().await {
        let deadline = Instant::now() + config.flush_interval;
        let mut batch = vec![first];
        while batch.len() < max_batch {
            match timeout_at(deadline, rx.recv()).await {
                Ok(Some(ev)) => batch.push(ev),
                Ok(None) | Err(_) => break,
            }
        }
        let redact = config.redact_client_ip;
        let n = batch.len();
        if let Err(e) = store.write(move |tx| flush(tx, &batch, redact)).await {
            tracing::warn!(error = %e, dropped = n, "query log flush failed");
        }
    }
}

#[derive(Default)]
struct Agg {
    count: i64,
    latency_sum: i64,
    latency_max: u32,
}

impl Agg {
    fn add(&mut self, latency: u32) {
        self.count += 1;
        self.latency_sum += i64::from(latency);
        self.latency_max = self.latency_max.max(latency);
    }
}

fn flush(tx: &mut Transaction, batch: &[QueryEvent], redact: bool) -> Result<(), StoreError> {
    let mut minute: BTreeMap<(i64, &'static str, String), Agg> = BTreeMap::new();
    let mut top: BTreeMap<(i64, &'static str, String), i64> = BTreeMap::new();
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO query_log (ts_ms, client, transport, principal, qname, qtype, rcode,
                                    source, source_detail, dnssec, latency_us)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?;
        for ev in batch {
            let client: IpAddr = if redact {
                redact_client_ip(ev.client)
            } else {
                ev.client
            };
            let qname = ev.qname.to_string().to_ascii_lowercase();
            let kind = ev.source.kind();
            let rcode = u16::from(ev.rcode);
            insert.execute(params![
                ev.ts_unix_ms,
                client.to_string(),
                transport_str(ev.transport),
                ev.principal,
                qname,
                u16::from(ev.qtype),
                rcode,
                kind.as_str(),
                ev.source.detail(),
                dnssec_str(ev.dnssec),
                ev.latency_us,
            ])?;

            let m = ev.ts_unix_ms.div_euclid(60_000) * 60;
            let h = ev.ts_unix_ms.div_euclid(3_600_000) * 3600;
            for (dim, key) in [
                ("total", String::new()),
                ("rcode", rcode.to_string()),
                ("source", kind.as_str().to_owned()),
                ("dnssec", dnssec_str(ev.dnssec).to_owned()),
            ] {
                minute.entry((m, dim, key)).or_default().add(ev.latency_us);
            }
            if kind == SourceKind::Blocked {
                *top.entry((h, "blocked", qname.clone())).or_default() += 1;
            }
            *top.entry((h, "qname", qname)).or_default() += 1;
            *top.entry((h, "client", client.to_string())).or_default() += 1;
        }
    }
    let mut up_min = tx.prepare_cached(
        "INSERT INTO stats_minute (minute, dimension, key, count, latency_sum_us, latency_max_us)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (minute, dimension, key) DO UPDATE SET
             count = count + excluded.count,
             latency_sum_us = latency_sum_us + excluded.latency_sum_us,
             latency_max_us = max(latency_max_us, excluded.latency_max_us)",
    )?;
    for ((m, dim, key), a) in &minute {
        up_min.execute(params![m, dim, key, a.count, a.latency_sum, a.latency_max])?;
    }
    let mut up_top = tx.prepare_cached(
        "INSERT INTO stats_top_hour (hour, kind, key, count) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (hour, kind, key) DO UPDATE SET count = count + excluded.count",
    )?;
    for ((h, kind, key), c) in &top {
        up_top.execute(params![h, kind, key, c])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{count_rows, event, open_store, wait_for_rows};

    #[tokio::test]
    async fn batch_flushes_on_size_and_time() {
        let (store, _d) = open_store();
        // Size trigger: interval is far away, so only reaching max_batch can flush.
        let (w, _t) = QueryLogWriter::spawn(
            store.clone(),
            WriterConfig {
                max_batch: 3,
                flush_interval: Duration::from_secs(3600),
                ..WriterConfig::default()
            },
        );
        for _ in 0..3 {
            w.record(event("a.example.", 1_000));
        }
        wait_for_rows(&store, 3).await;
        drop(w);

        // Time trigger: batch size is far away, so only the interval can flush.
        let (w, _t) = QueryLogWriter::spawn(
            store.clone(),
            WriterConfig {
                max_batch: 500,
                flush_interval: Duration::from_millis(100),
                ..WriterConfig::default()
            },
        );
        w.record(event("b.example.", 2_000));
        wait_for_rows(&store, 4).await;
    }

    #[tokio::test]
    async fn full_channel_drops_and_counts() {
        let (w, mut rx) = QueryLogWriter::channel(2);
        for _ in 0..5 {
            w.record(event("a.example.", 1));
        }
        assert_eq!(w.dropped(), 3);
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn shutdown_flushes_remaining_and_redacts() {
        let (store, _d) = open_store();
        let (w, task) = QueryLogWriter::spawn(
            store.clone(),
            WriterConfig {
                redact_client_ip: true,
                ..WriterConfig::default()
            },
        );
        w.record(event("a.example.", 1));
        drop(w);
        task.await.unwrap();
        assert_eq!(count_rows(&store, "query_log").await, 1);
        let client = store
            .read(|c| {
                Ok(c.query_row("SELECT client FROM query_log", [], |r| {
                    r.get::<_, String>(0)
                })?)
            })
            .await
            .unwrap();
        assert_eq!(client, "192.0.2.0");
    }
}
