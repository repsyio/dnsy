use std::future::Future;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dnsy_store::Store;
use rusqlite::params;
use tokio::task::JoinHandle;

use crate::ObserveError;

/// Rows deleted per transaction, so the single writer is never held for long and the query-log
/// writer interleaves between batches.
const PURGE_BATCH: usize = 50_000;
/// Minute rollups are kept at least this long (the stats range is capped at 366 days).
const MINUTE_ROLLUP_KEEP_MS: i64 = 400 * 24 * 3_600 * 1000;
/// Session lifetimes of `dnsy-auth` (`IDLE_TIMEOUT_SECS`, `ABSOLUTE_TIMEOUT_SECS`); keep in sync.
const SESSION_IDLE_SECS: i64 = 30 * 60;
const SESSION_ABSOLUTE_SECS: i64 = 12 * 60 * 60;
/// `PRAGMA optimize` runs at most this often from the retention task.
const OPTIMIZE_EVERY: Duration = Duration::from_hours(24);

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Delete in transactions of at most `batch` rows until fewer are found. `sql` takes the cutoff
/// as `?1` and the batch size as `?2`; `between` runs after every full batch.
async fn delete_batched<F, Fut>(
    store: &Store,
    sql: &'static str,
    cutoff: i64,
    batch: usize,
    between: &mut F,
) -> Result<usize, ObserveError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let limit = i64::try_from(batch).unwrap_or(i64::MAX);
    let mut total = 0;
    loop {
        let n = store
            .write(move |tx| Ok(tx.execute(sql, params![cutoff, limit])?))
            .await?;
        total += n;
        if n < batch {
            return Ok(total);
        }
        between().await;
    }
}

/// Delete query-log rows older than `cutoff_ms`, hourly top-N rows that end before it, minute
/// rollups older than the longer of the retention and 400 days, and expired sessions. Deletes
/// run in batches of at most 50 000 rows per transaction. Returns the query-log rows removed.
pub async fn purge_before(store: &Store, cutoff_ms: i64) -> Result<usize, ObserveError> {
    purge_at(store, cutoff_ms, now_ms(), PURGE_BATCH, || async {}).await
}

async fn purge_at<F, Fut>(
    store: &Store,
    cutoff_ms: i64,
    now_ms: i64,
    batch: usize,
    mut between: F,
) -> Result<usize, ObserveError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let rows = delete_batched(
        store,
        "DELETE FROM query_log WHERE rowid IN
             (SELECT rowid FROM query_log WHERE ts_ms < ?1 LIMIT ?2)",
        cutoff_ms,
        batch,
        &mut between,
    )
    .await?;
    delete_batched(
        store,
        "DELETE FROM stats_top_hour WHERE (hour, kind, key) IN
             (SELECT hour, kind, key FROM stats_top_hour WHERE hour < ?1 - 3600 LIMIT ?2)",
        cutoff_ms.div_euclid(1000),
        batch,
        &mut between,
    )
    .await?;
    let minute_cutoff = cutoff_ms
        .min(now_ms - MINUTE_ROLLUP_KEEP_MS)
        .div_euclid(1000);
    delete_batched(
        store,
        "DELETE FROM stats_minute WHERE (minute, dimension, key) IN
             (SELECT minute, dimension, key FROM stats_minute WHERE minute < ?1 LIMIT ?2)",
        minute_cutoff,
        batch,
        &mut between,
    )
    .await?;
    let unix_secs = now_ms.div_euclid(1000);
    store
        .write(move |tx| {
            tx.execute(
                "DELETE FROM sessions WHERE last_seen_at < ?1 OR created_at < ?2",
                params![
                    unix_secs - SESSION_IDLE_SECS,
                    unix_secs - SESSION_ABSOLUTE_SECS
                ],
            )?;
            Ok(())
        })
        .await?;
    Ok(rows)
}

/// Runs `PRAGMA optimize` at most once per `every`, starting with the first call.
struct Optimizer {
    every: Duration,
    last: Option<Instant>,
}

impl Optimizer {
    fn daily() -> Self {
        Self {
            every: OPTIMIZE_EVERY,
            last: None,
        }
    }

    async fn maybe(&mut self, store: &Store) {
        if self.last.is_some_and(|t| t.elapsed() < self.every) {
            return;
        }
        self.last = Some(Instant::now());
        if let Err(e) = store.optimize().await {
            tracing::warn!(error = %e, "PRAGMA optimize failed");
        }
    }
}

const DAY_MS: i64 = 24 * 3_600 * 1000;

/// Live database bytes: used pages, not the file size (freed pages are reused, not returned).
async fn used_bytes(store: &Store) -> Result<u64, ObserveError> {
    Ok(store
        .read(|c| {
            let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            let free: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
            let size: i64 = c.query_row("PRAGMA page_size", [], |r| r.get(0))?;
            Ok(u64::try_from((pages - free).max(0) * size).unwrap_or(0))
        })
        .await?)
}

/// While the live data exceeds `max_bytes`, delete the oldest UTC day of raw query-log rows.
/// Rollups are kept. The current day is never purged (a warning is logged when the cap cannot be
/// met). Returns the rows removed.
async fn enforce_size_cap(
    store: &Store,
    max_bytes: u64,
    now_ms: i64,
) -> Result<usize, ObserveError> {
    let today = now_ms.div_euclid(DAY_MS);
    let mut removed = 0;
    while used_bytes(store).await? > max_bytes {
        let oldest: Option<i64> = store
            .read(|c| Ok(c.query_row("SELECT min(ts_ms) FROM query_log", [], |r| r.get(0))?))
            .await?;
        let Some(oldest) = oldest else { break };
        let day = oldest.div_euclid(DAY_MS);
        if day >= today {
            tracing::warn!(
                max_bytes,
                "query log is over max_size_mb but only today's rows remain"
            );
            break;
        }
        removed += delete_batched(
            store,
            "DELETE FROM query_log WHERE rowid IN
                 (SELECT rowid FROM query_log WHERE ts_ms < ?1 LIMIT ?2)",
            (day + 1) * DAY_MS,
            PURGE_BATCH,
            &mut || async {},
        )
        .await?;
    }
    Ok(removed)
}

async fn pass(store: &Store, keep: Duration, optimizer: &mut Optimizer) {
    let now = now_ms();
    let cutoff = now.saturating_sub(i64::try_from(keep.as_millis()).unwrap_or(i64::MAX));
    if let Err(e) = purge_before(store, cutoff).await {
        tracing::warn!(error = %e, "query log retention purge failed");
    }
    let cap = crate::writer::max_size_bytes();
    if cap > 0 {
        match enforce_size_cap(store, cap, now).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(rows = n, "query log size cap purged old days"),
            Err(e) => tracing::warn!(error = %e, "query log size cap purge failed"),
        }
    }
    optimizer.maybe(store).await;
}

/// Purge once now and then every `interval`, keeping `retention` of history; also runs
/// `PRAGMA optimize` once a day. Abort the returned handle to stop it.
#[must_use]
pub fn spawn_retention(store: Store, retention: Duration, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        let mut optimizer = Optimizer::daily();
        loop {
            tick.tick().await;
            pass(&store, retention, &mut optimizer).await;
        }
    })
}

/// Like [`spawn_retention`], but the retention is read from `retention` on every pass, so
/// changing it takes effect at the next purge.
#[must_use]
pub fn spawn_retention_watch(
    store: Store,
    retention: tokio::sync::watch::Receiver<Duration>,
    interval: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        let mut optimizer = Optimizer::daily();
        loop {
            tick.tick().await;
            let keep = *retention.borrow();
            pass(&store, keep, &mut optimizer).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{count_rows, event, ingest, open_store, wait_for_rows};

    const DAY_MS: i64 = 24 * 3_600 * 1000;
    const NOW: i64 = 1_000 * DAY_MS;

    async fn exec(store: &Store, sql: &'static str) {
        store
            .write(move |t| Ok(t.execute_batch(sql)?))
            .await
            .unwrap();
    }

    async fn minutes(store: &Store) -> Vec<i64> {
        store
            .read(|c| {
                let mut st = c.prepare("SELECT minute FROM stats_minute ORDER BY minute")?;
                Ok(st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn retention_purges_old_rows() {
        let (store, _d) = open_store();
        ingest(
            &store,
            vec![
                event("old.example.", 1_000),
                event("new.example.", 10_000_000),
            ],
        )
        .await;
        assert_eq!(purge_before(&store, 5_000_000).await.unwrap(), 1);
        assert_eq!(count_rows(&store, "query_log").await, 1);
        // The hour holding only the old event is gone, the recent one stays.
        assert_eq!(count_rows(&store, "stats_top_hour").await, 2);
        assert!(count_rows(&store, "stats_minute").await > 0);
    }

    #[tokio::test]
    async fn size_cap_purges_the_oldest_day_and_keeps_today() {
        let (store, _d) = open_store();
        let now = 100 * DAY_MS + 3_600_000;
        let mut events = Vec::new();
        for day in [97, 98, 99, 100] {
            for i in 0..2_000 {
                events.push(event(&format!("host{i}.example."), day * DAY_MS + i));
            }
        }
        ingest(&store, events).await;
        wait_for_rows(&store, 8_000).await;
        let used = used_bytes(&store).await.unwrap();
        // Unlimited-ish cap: nothing happens.
        assert_eq!(enforce_size_cap(&store, used, now).await.unwrap(), 0);
        // A cap slightly below the current use drops exactly the oldest day.
        let removed = enforce_size_cap(&store, used - 1, now).await.unwrap();
        assert_eq!(removed, 2_000);
        let oldest: i64 = store
            .read(|c| Ok(c.query_row("SELECT min(ts_ms) FROM query_log", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(oldest.div_euclid(DAY_MS), 98);
        // An impossible cap purges every past day but never today.
        enforce_size_cap(&store, 0, now).await.unwrap();
        assert_eq!(count_rows(&store, "query_log").await, 2_000);
        assert!(count_rows(&store, "stats_minute").await > 0, "rollups stay");
    }

    #[tokio::test]
    async fn retention_task_purges_on_schedule() {
        let (store, _d) = open_store();
        ingest(&store, vec![event("old.example.", 1_000)]).await;
        wait_for_rows(&store, 1).await;
        let h = spawn_retention(
            store.clone(),
            Duration::from_secs(60),
            Duration::from_millis(20),
        );
        wait_for_rows(&store, 0).await;
        h.abort();
    }

    #[tokio::test]
    async fn watched_retention_applies_changes() {
        let (store, _d) = open_store();
        ingest(&store, vec![event("old.example.", 1_000)]).await;
        wait_for_rows(&store, 1).await;
        let (tx, rx) = tokio::sync::watch::channel(Duration::from_secs(u64::MAX / 4_000));
        let h = spawn_retention_watch(store.clone(), rx, Duration::from_millis(20));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(count_rows(&store, "query_log").await, 1);
        tx.send(Duration::from_secs(60)).unwrap();
        wait_for_rows(&store, 0).await;
        h.abort();
    }

    /// 120k expired rows go in batches of 50k: at least three commits, and a concurrent writer
    /// gets in between them instead of waiting for one long transaction.
    #[tokio::test]
    async fn purge_runs_in_batches_and_lets_the_writer_interleave() {
        let (store, _d) = open_store();
        exec(
            &store,
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 119999)
             INSERT INTO query_log (ts_ms, client, transport, qname, qtype, rcode, source, dnssec, latency_us)
             SELECT i, '192.0.2.1', 'udp', 'a.example.', 1, 0, 'upstream', 'unchecked', 1 FROM n;
             WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 119999)
             INSERT INTO stats_top_hour (hour, kind, key, count)
             SELECT 0, 'qname', 'k' || i, 1 FROM n",
        )
        .await;
        let before = store.write_count();
        let inserted = std::cell::Cell::new(0_u64);
        let purged = purge_at(&store, 5_000_000, 5_000_000, PURGE_BATCH, || {
            inserted.set(inserted.get() + 1);
            let store = store.clone();
            async move {
                exec(
                    &store,
                    "INSERT INTO query_log (ts_ms, client, transport, qname, qtype, rcode, source, dnssec, latency_us)
                     VALUES (9000000, '192.0.2.2', 'udp', 'new.example.', 1, 0, 'upstream', 'unchecked', 1)",
                )
                .await;
            }
        })
        .await
        .unwrap();
        assert_eq!(purged, 120_000);
        assert_eq!(count_rows(&store, "stats_top_hour").await, 0);
        assert!(
            inserted.get() >= 4,
            "the writer ran between batches: {}",
            inserted.get()
        );
        let commits = store.write_count() - before - inserted.get();
        assert!(commits >= 3, "one transaction per batch, got {commits}");
        assert_eq!(
            count_rows(&store, "query_log").await,
            i64::try_from(inserted.get()).unwrap(),
            "rows inserted between batches survive"
        );
    }

    #[tokio::test]
    async fn top_hour_purge_is_a_range_search_on_the_primary_key() {
        let (store, _d) = open_store();
        let plan: String = store
            .read(|c| {
                let mut st = c.prepare(
                    "EXPLAIN QUERY PLAN SELECT hour, kind, key FROM stats_top_hour WHERE hour < ?1 - 3600 LIMIT ?2",
                )?;
                let rows = st.query_map([5000_i64, 10], |r| r.get::<_, String>(3))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?.join("\n"))
            })
            .await
            .unwrap();
        assert!(
            plan.contains("SEARCH stats_top_hour USING PRIMARY KEY (hour<?)"),
            "{plan}"
        );
    }

    #[tokio::test]
    async fn minute_rollups_are_kept_for_400_days() {
        let (store, _d) = open_store();
        let min = |ago_days: i64| (NOW - ago_days * DAY_MS) / 60_000 * 60;
        for ago in [500, 399, 100] {
            let m = min(ago);
            store
                .write(move |t| {
                    Ok(t.execute(
                        "INSERT INTO stats_minute VALUES (?1, 'total', '', 1, 1, 1)",
                        [m],
                    )
                    .map(drop)?)
                })
                .await
                .unwrap();
        }
        // 30 days of retention: only what is older than 400 days goes.
        purge_at(&store, NOW - 30 * DAY_MS, NOW, PURGE_BATCH, || async {})
            .await
            .unwrap();
        assert_eq!(minutes(&store).await, [min(399), min(100)]);
        // Retention longer than 400 days wins.
        purge_at(&store, NOW - 450 * DAY_MS, NOW, PURGE_BATCH, || async {})
            .await
            .unwrap();
        assert_eq!(minutes(&store).await, [min(399), min(100)]);
        purge_at(&store, NOW - 50 * DAY_MS, NOW, PURGE_BATCH, || async {})
            .await
            .unwrap();
        assert_eq!(minutes(&store).await, [min(399), min(100)]);
    }

    #[tokio::test]
    async fn retention_deletes_expired_sessions_only() {
        let (store, _d) = open_store();
        let now_s = NOW / 1000;
        store
            .write(move |t| {
                t.execute("INSERT INTO users (id, username, role, password_hash) VALUES (1, 'u', 'admin', 'x')", [])?;
                for (id, created, seen) in [
                    (1_u8, now_s - 100, now_s - 10),            // live
                    (2, now_s - 100, now_s - 31 * 60),          // idle
                    (3, now_s - 13 * 3600, now_s - 10),         // past the absolute lifetime
                ] {
                    t.execute(
                        "INSERT INTO sessions (id_sha256, user_id, created_at, last_seen_at) VALUES (?1, 1, ?2, ?3)",
                        rusqlite::params![vec![id], created, seen],
                    )?;
                }
                Ok(())
            })
            .await
            .unwrap();
        purge_at(&store, 0, NOW, PURGE_BATCH, || async {})
            .await
            .unwrap();
        let left: Vec<Vec<u8>> = store
            .read(|c| {
                let mut st = c.prepare("SELECT id_sha256 FROM sessions")?;
                Ok(st.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?)
            })
            .await
            .unwrap();
        assert_eq!(left, [vec![1_u8]]);
    }

    #[tokio::test]
    async fn optimize_runs_once_per_interval() {
        let (store, _d) = open_store();
        let mut daily = Optimizer::daily();
        let before = store.write_count();
        daily.maybe(&store).await;
        daily.maybe(&store).await;
        assert_eq!(
            store.write_count(),
            before + 1,
            "first call runs, second is within a day"
        );
        let mut always = Optimizer {
            every: Duration::ZERO,
            last: None,
        };
        always.maybe(&store).await;
        always.maybe(&store).await;
        assert_eq!(store.write_count(), before + 3);
    }
}
