use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    /// Keep one raw row in `sample` events (values below 2 keep all). Rollups and top-N counts
    /// always include every event.
    pub sample: u32,
    /// Cap on live database data in MiB for the retention task (0 = unlimited).
    pub max_size_mb: u64,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 10_000,
            max_batch: 500,
            flush_interval: Duration::from_secs(1),
            redact_client_ip: false,
            sample: 1,
            max_size_mb: 0,
        }
    }
}

#[derive(Default)]
struct Counters {
    dropped: AtomicU64,
    flush_errors: AtomicU64,
    /// The last flush failed with `SQLITE_FULL`.
    disk_full: AtomicBool,
    /// Events seen, for sampling.
    seen: AtomicU64,
    /// `[querylog] max_size_mb` in bytes (0 = unlimited), read by the retention task.
    max_size_bytes: AtomicU64,
}

/// The counters of the most recently started writer: one query log per process, readable by the
/// API without a handle on the writer.
static CURRENT: Mutex<Option<Arc<Counters>>> = Mutex::new(None);

/// Events lost by the query log since the writer started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryLogCounters {
    /// Events dropped because the channel was full or a flush failed.
    pub dropped: u64,
    /// Batches that failed to write.
    pub flush_errors: u64,
    /// The last flush failed because the disk is full (cleared by the next successful flush).
    pub disk_full: bool,
}

/// Loss counters of the running query-log writer (zero when none was started).
#[must_use]
pub fn querylog_counters() -> QueryLogCounters {
    let current = CURRENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    current.map_or_else(QueryLogCounters::default, |c| QueryLogCounters {
        dropped: c.dropped.load(Ordering::Relaxed),
        flush_errors: c.flush_errors.load(Ordering::Relaxed),
        disk_full: c.disk_full.load(Ordering::Relaxed),
    })
}

/// The configured size cap of the running writer in bytes (0 = unlimited or no writer).
pub(crate) fn max_size_bytes() -> u64 {
    CURRENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .map_or(0, |c| c.max_size_bytes.load(Ordering::Relaxed))
}

/// One queued event; `raw` is false when sampling keeps it out of `query_log` (it still feeds the
/// rollups).
type Queued = (QueryEvent, bool);

/// Non-blocking sink feeding a batched SQLite writer task. Cloning shares the
/// channel and the loss counters.
#[derive(Clone)]
pub struct QueryLogWriter {
    tx: mpsc::Sender<Queued>,
    counters: Arc<Counters>,
    sample: u64,
}

impl QueryLogWriter {
    /// Start the writer task. It flushes remaining events and exits once every
    /// clone of the returned writer is dropped.
    #[must_use]
    pub fn spawn(store: Store, config: WriterConfig) -> (QueryLogWriter, JoinHandle<()>) {
        let (mut writer, rx) = Self::channel(config.channel_capacity);
        writer.sample = u64::from(config.sample.max(1));
        writer.counters.max_size_bytes.store(
            config.max_size_mb.saturating_mul(1024 * 1024),
            Ordering::Relaxed,
        );
        *CURRENT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Arc::clone(&writer.counters));
        let task = tokio::spawn(run(store, config, rx, Arc::clone(&writer.counters)));
        (writer, task)
    }

    pub(crate) fn channel(capacity: usize) -> (QueryLogWriter, mpsc::Receiver<Queued>) {
        let (tx, rx) = mpsc::channel(capacity);
        let writer = QueryLogWriter {
            tx,
            counters: Arc::new(Counters::default()),
            sample: 1,
        };
        (writer, rx)
    }

    /// Events dropped because the channel was full or their batch failed to write.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.counters.dropped.load(Ordering::Relaxed)
    }

    /// Batches that failed to write.
    #[must_use]
    pub fn flush_errors(&self) -> u64 {
        self.counters.flush_errors.load(Ordering::Relaxed)
    }
}

impl QueryEventSink for QueryLogWriter {
    fn record(&self, ev: QueryEvent) {
        // A full channel is the common overload case: decide before doing any other work.
        if self.tx.capacity() == 0 {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let raw = self.sample <= 1
            || self
                .counters
                .seen
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(self.sample);
        if self.tx.try_send((ev, raw)).is_err() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn run(
    store: Store,
    config: WriterConfig,
    mut rx: mpsc::Receiver<Queued>,
    counters: Arc<Counters>,
) {
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
        match store.write(move |tx| flush(tx, &batch, redact)).await {
            Ok(()) => {
                if counters.disk_full.swap(false, Ordering::Relaxed) {
                    tracing::info!("query log writes recovered after a full disk");
                }
            }
            Err(e) => {
                counters.flush_errors.fetch_add(1, Ordering::Relaxed);
                counters.dropped.fetch_add(n as u64, Ordering::Relaxed);
                if !is_disk_full(&e) {
                    tracing::warn!(error = %e, dropped = n, "query log flush failed");
                } else if !counters.disk_full.swap(true, Ordering::Relaxed) {
                    tracing::warn!(error = %e, "query log cannot write: the disk is full");
                }
            }
        }
    }
}

fn is_disk_full(e: &StoreError) -> bool {
    matches!(
        e,
        StoreError::Sqlite(rusqlite::Error::SqliteFailure(f, _))
            if f.code == rusqlite::ErrorCode::DiskFull
    )
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

/// `map[(bucket, dimension)][key]`, allocating the key only the first time it is seen.
fn slot<'a, V: Default>(
    map: &'a mut BTreeMap<(i64, &'static str), BTreeMap<String, V>>,
    bucket: i64,
    dim: &'static str,
    key: &str,
) -> &'a mut V {
    let inner = map.entry((bucket, dim)).or_default();
    if !inner.contains_key(key) {
        inner.insert(key.to_owned(), V::default());
    }
    inner.get_mut(key).expect("inserted above")
}

fn flush(tx: &mut Transaction, batch: &[Queued], redact: bool) -> Result<(), StoreError> {
    type Rollup<V> = BTreeMap<(i64, &'static str), BTreeMap<String, V>>;
    let mut minute: Rollup<Agg> = BTreeMap::new();
    let mut top: Rollup<i64> = BTreeMap::new();
    // Strings are built into these buffers, reused for the whole batch.
    let mut qname = String::new();
    let mut client_s = String::new();
    let mut rcode_s = String::new();
    {
        let mut insert = tx.prepare_cached(
            "INSERT INTO query_log (ts_ms, client, transport, principal, qname, qtype, rcode,
                                    source, source_detail, dnssec, latency_us)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?;
        for (ev, raw) in batch {
            let client: IpAddr = if redact {
                redact_client_ip(ev.client)
            } else {
                ev.client
            };
            qname.clear();
            let _ = write!(qname, "{}", ev.qname);
            qname.make_ascii_lowercase();
            client_s.clear();
            let _ = write!(client_s, "{client}");
            let kind = ev.source.kind();
            let rcode = u16::from(ev.rcode);
            rcode_s.clear();
            let _ = write!(rcode_s, "{rcode}");
            if *raw {
                insert.execute(params![
                    ev.ts_unix_ms,
                    client_s,
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
            }

            let m = ev.ts_unix_ms.div_euclid(60_000) * 60;
            let h = ev.ts_unix_ms.div_euclid(3_600_000) * 3600;
            for (dim, key) in [
                ("total", ""),
                ("rcode", rcode_s.as_str()),
                ("source", kind.as_str()),
                ("dnssec", dnssec_str(ev.dnssec)),
            ] {
                slot(&mut minute, m, dim, key).add(ev.latency_us);
            }
            if kind == SourceKind::Blocked {
                *slot(&mut top, h, "blocked", &qname) += 1;
            }
            *slot(&mut top, h, "qname", &qname) += 1;
            *slot(&mut top, h, "client", &client_s) += 1;
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
    for ((m, dim), keys) in &minute {
        for (key, a) in keys {
            up_min.execute(params![m, dim, key, a.count, a.latency_sum, a.latency_max])?;
        }
    }
    let mut up_top = tx.prepare_cached(
        "INSERT INTO stats_top_hour (hour, kind, key, count) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (hour, kind, key) DO UPDATE SET count = count + excluded.count",
    )?;
    for ((h, kind), keys) in &top {
        for (key, c) in keys {
            up_top.execute(params![h, kind, key, c])?;
        }
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

    #[tokio::test]
    async fn failed_flushes_are_counted() {
        let (store, _d) = open_store();
        store
            .write(|t| Ok(t.execute_batch("DROP TABLE query_log")?))
            .await
            .unwrap();
        let (w, task) = QueryLogWriter::spawn(store.clone(), WriterConfig::default());
        for _ in 0..3 {
            w.record(event("a.example.", 1));
        }
        let counters = Arc::clone(&w.counters);
        drop(w);
        task.await.unwrap();
        assert_eq!(counters.flush_errors.load(Ordering::Relaxed), 1);
        assert_eq!(
            counters.dropped.load(Ordering::Relaxed),
            3,
            "every event of the failed batch is lost"
        );
        assert_eq!(
            querylog_counters(),
            QueryLogCounters {
                dropped: 3,
                flush_errors: 1,
                disk_full: false
            }
        );
    }

    async fn rows_and_rollup_total(store: &Store) -> (i64, i64) {
        let rows = count_rows(store, "query_log").await;
        let total = store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT coalesce(sum(count), 0) FROM stats_minute WHERE dimension = 'total'",
                    [],
                    |r| r.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap();
        (rows, total)
    }

    #[tokio::test]
    async fn sampling_keeps_rollups_exact() {
        let (store, _d) = open_store();
        let (w, task) = QueryLogWriter::spawn(
            store.clone(),
            WriterConfig {
                sample: 10,
                ..WriterConfig::default()
            },
        );
        for i in 0..100 {
            w.record(event("a.example.", 1_000 + i));
        }
        drop(w);
        task.await.unwrap();
        let (rows, total) = rows_and_rollup_total(&store).await;
        assert_eq!(rows, 10, "one raw row in ten");
        assert_eq!(total, 100, "rollups count every event");
        let top: i64 = store
            .read(|c| {
                Ok(c.query_row(
                    "SELECT count FROM stats_top_hour WHERE kind = 'qname'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(top, 100);
    }

    #[tokio::test]
    async fn sample_zero_or_one_keeps_every_row() {
        for sample in [0, 1] {
            let (store, _d) = open_store();
            let (w, task) = QueryLogWriter::spawn(
                store.clone(),
                WriterConfig {
                    sample,
                    ..WriterConfig::default()
                },
            );
            for i in 0..5 {
                w.record(event("a.example.", i));
            }
            drop(w);
            task.await.unwrap();
            assert_eq!(count_rows(&store, "query_log").await, 5);
        }
    }

    #[tokio::test]
    async fn disk_full_sets_and_clears_the_warning() {
        let (store, _d) = open_store();
        let pages: i64 = store
            .write(|t| Ok(t.query_row("PRAGMA page_count", [], |r| r.get(0))?))
            .await
            .unwrap();
        store
            .write(move |t| Ok(t.execute_batch(&format!("PRAGMA max_page_count = {pages}"))?))
            .await
            .unwrap();
        let (w, task) = QueryLogWriter::spawn(
            store.clone(),
            WriterConfig {
                flush_interval: Duration::from_millis(10),
                ..WriterConfig::default()
            },
        );
        let mut i = 0;
        for _ in 0..500 {
            if querylog_counters().disk_full {
                break;
            }
            for _ in 0..200 {
                i += 1;
                w.record(event(&format!("host{i}.example."), i));
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert!(querylog_counters().disk_full, "SQLITE_FULL raises the flag");
        assert!(w.flush_errors() > 0);
        store
            .write(|t| Ok(t.execute_batch("PRAGMA max_page_count = 1073741823")?))
            .await
            .unwrap();
        for _ in 0..500 {
            if !querylog_counters().disk_full {
                break;
            }
            w.record(event("ok.example.", 1));
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert!(!querylog_counters().disk_full, "a good flush clears it");
        drop(w);
        task.await.unwrap();
    }
}
