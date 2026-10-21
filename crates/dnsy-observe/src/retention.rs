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
/// Completed UTC days older than this are folded into the daily rollups.
const FOLD_AFTER_MS: i64 = 48 * 3_600 * 1000;
/// Keys kept per (day, kind) in `stats_top_day`.
const TOP_PER_DAY: i64 = 5000;
const DAY_S: i64 = 86_400;
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

/// Delete query-log rows older than `cutoff_ms`, hourly and daily top-N rows that end before it,
/// minute and daily counter rollups older than the longer of the retention and 400 days, and expired sessions. Deletes
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
    delete_batched(
        store,
        "DELETE FROM stats_top_day WHERE (day, kind, key) IN
             (SELECT day, kind, key FROM stats_top_day WHERE day < ?1 - 86400 LIMIT ?2)",
        cutoff_ms.div_euclid(1000),
        batch,
        &mut between,
    )
    .await?;
    delete_batched(
        store,
        "DELETE FROM stats_day WHERE (day, dimension, key) IN
             (SELECT day, dimension, key FROM stats_day WHERE day < ?1 LIMIT ?2)",
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

/// Fold every completed UTC day that ended more than 48 hours before `now_ms` into
/// `stats_day` (from `stats_minute`) and `stats_top_day` (the top 5000 keys per kind, from
/// `stats_top_hour`), one write transaction per day, then delete the folded minute and hour
/// rows in batches. A day that already has daily rows is not folded again, so a crash between
/// the fold and the delete is repaired by the next pass without double counting or rebuilding
/// from half-deleted rows. Returns the number of days folded.
pub async fn fold_rollups(store: &Store, now_ms: i64) -> Result<usize, ObserveError> {
    fold_at(store, now_ms, PURGE_BATCH, || async {}).await
}

async fn fold_at<F, Fut>(
    store: &Store,
    now_ms: i64,
    batch: usize,
    mut between: F,
) -> Result<usize, ObserveError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let boundary = (now_ms - FOLD_AFTER_MS).div_euclid(1000).div_euclid(DAY_S) * DAY_S;
    let mut folded = 0;
    let mut next = 0_i64;
    loop {
        let first: Option<i64> = store
            .read(move |c| {
                Ok(c.query_row(
                    "SELECT min(m) FROM (
                         SELECT min(minute) AS m FROM stats_minute WHERE minute >= ?1 AND minute < ?2
                         UNION ALL
                         SELECT min(hour) FROM stats_top_hour WHERE hour >= ?1 AND hour < ?2)",
                    params![next, boundary],
                    |r| r.get(0),
                )?)
            })
            .await?;
        let Some(first) = first else { break };
        let day = first.div_euclid(DAY_S) * DAY_S;
        store
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO stats_day (day, dimension, key, count, latency_sum_us, latency_max_us)
                     SELECT ?1, dimension, key, sum(count), sum(latency_sum_us), max(latency_max_us)
                     FROM stats_minute WHERE minute >= ?1 AND minute < ?1 + 86400
                       AND NOT EXISTS (SELECT 1 FROM stats_day WHERE day = ?1)
                     GROUP BY dimension, key",
                    [day],
                )?;
                tx.execute(
                    "INSERT INTO stats_top_day (day, kind, key, count)
                     SELECT ?1, kind, key, c FROM (
                         SELECT kind, key, sum(count) AS c,
                                row_number() OVER (PARTITION BY kind ORDER BY sum(count) DESC, key ASC) AS rn
                         FROM stats_top_hour WHERE hour >= ?1 AND hour < ?1 + 86400
                         GROUP BY kind, key)
                     WHERE rn <= ?2 AND NOT EXISTS (SELECT 1 FROM stats_top_day WHERE day = ?1)",
                    params![day, TOP_PER_DAY],
                )?;
                Ok(())
            })
            .await?;
        folded += 1;
        next = day + DAY_S;
    }
    delete_batched(
        store,
        "DELETE FROM stats_top_hour WHERE (hour, kind, key) IN
             (SELECT hour, kind, key FROM stats_top_hour WHERE hour < ?1 LIMIT ?2)",
        boundary,
        batch,
        &mut between,
    )
    .await?;
    delete_batched(
        store,
        "DELETE FROM stats_minute WHERE (minute, dimension, key) IN
             (SELECT minute, dimension, key FROM stats_minute WHERE minute < ?1 LIMIT ?2)",
        boundary,
        batch,
        &mut between,
    )
    .await?;
    Ok(folded)
}

async fn pass(store: &Store, keep: Duration, optimizer: &mut Optimizer) {
    let now = now_ms();
    let cutoff = now.saturating_sub(i64::try_from(keep.as_millis()).unwrap_or(i64::MAX));
    match fold_rollups(store, now).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(days = n, "folded stats rollups into daily rows"),
        Err(e) => tracing::warn!(error = %e, "stats rollup fold failed"),
    }
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
             SELECT i, X'C0000201', 0, 'a.example.', 1, 0, 3, 0, 1 FROM n;
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
                     VALUES (9000000, X'C0000202', 0, 'new.example.', 1, 0, 3, 0, 1)",
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

    async fn dump(store: &Store, sql: &'static str) -> Vec<String> {
        store
            .read(move |c| {
                let mut st = c.prepare(sql)?;
                let n = st.column_count();
                let rows = st.query_map([], |r| {
                    (0..n)
                        .map(|i| Ok(format!("{:?}", r.get_ref(i)?)))
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .map(|v| v.join(","))
                })?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .await
            .unwrap()
    }

    /// Events on both sides of a UTC midnight: summary, top lists and the daily timeseries are
    /// the same before and after the fold, and the folded minute and hour rows are gone.
    #[tokio::test]
    async fn fold_matches_the_raw_log_across_midnight() {
        use crate::{AnswerSource, StatsService, TimeRange};
        let (store, _d) = open_store();
        let mut evs = Vec::new();
        for (i, (name, off)) in [
            ("a.example.", 3 * DAY_MS + DAY_MS - 1_000),
            ("a.example.", 3 * DAY_MS + DAY_MS - 1_000),
            ("b.example.", 3 * DAY_MS + DAY_MS - 1),
            ("a.example.", 4 * DAY_MS),
            ("c.example.", 4 * DAY_MS + 1_000),
            ("c.example.", 4 * DAY_MS + 3_600_000),
            ("c.example.", 9 * DAY_MS + 5_000),
        ]
        .into_iter()
        .enumerate()
        {
            let mut e = event(name, off);
            e.latency_us = 100 * (u32::try_from(i).unwrap() + 1);
            if i == 2 {
                e.source = AnswerSource::Blocked { list: "ads".into() };
            }
            if i == 3 {
                e.source = AnswerSource::Cache;
            }
            evs.push(e);
        }
        ingest(&store, evs).await;
        let stats = StatsService::new(store.clone());
        let range = TimeRange {
            from_ms: 3 * DAY_MS,
            to_ms: 10 * DAY_MS,
        };
        let day = Duration::from_hours(24);
        let before = (
            stats.summary(range).await.unwrap(),
            stats.top_domains(range, 10).await.unwrap(),
            stats.top_blocked(range, 10).await.unwrap(),
            stats.top_clients(range, 10).await.unwrap(),
            stats.timeseries(range, day).await.unwrap(),
        );
        assert_eq!(before.0.total, 7);

        let now = 10 * DAY_MS + 3_600_000;
        assert_eq!(fold_rollups(&store, now).await.unwrap(), 2);
        let after = (
            stats.summary(range).await.unwrap(),
            stats.top_domains(range, 10).await.unwrap(),
            stats.top_blocked(range, 10).await.unwrap(),
            stats.top_clients(range, 10).await.unwrap(),
            stats.timeseries(range, day).await.unwrap(),
        );
        assert_eq!(before, after);
        // Day 3 and 4 are folded away, day 9 stays raw.
        assert_eq!(
            dump(
                &store,
                "SELECT DISTINCT day / 86400 FROM stats_day ORDER BY 1"
            )
            .await,
            ["Integer(3)", "Integer(4)"]
        );
        assert_eq!(
            dump(&store, "SELECT DISTINCT minute / 86400 FROM stats_minute").await,
            ["Integer(9)"]
        );
        assert_eq!(
            dump(&store, "SELECT DISTINCT hour / 86400 FROM stats_top_hour").await,
            ["Integer(9)"]
        );
        // Midnight split: a.example. is 2 on day 3 and 1 on day 4.
        assert_eq!(
            dump(
                &store,
                "SELECT day / 86400, count FROM stats_top_day WHERE kind = 'qname' AND key = 'a.example.' ORDER BY day"
            )
            .await,
            ["Integer(3),Integer(2)", "Integer(4),Integer(1)"]
        );
        // Only day 4 asked for: whole day, nothing of day 3.
        let day4 = TimeRange {
            from_ms: 4 * DAY_MS,
            to_ms: 5 * DAY_MS,
        };
        assert_eq!(stats.summary(day4).await.unwrap().total, 3);
    }

    #[tokio::test]
    async fn fold_is_idempotent_and_repairs_an_interrupted_delete() {
        let (store, _d) = open_store();
        ingest(
            &store,
            vec![
                event("a.example.", 3 * DAY_MS + 5_000),
                event("b.example.", 3 * DAY_MS + 7_200_000),
            ],
        )
        .await;
        let now = 10 * DAY_MS;
        let raw_min = dump(&store, "SELECT * FROM stats_minute").await;
        assert_eq!(fold_rollups(&store, now).await.unwrap(), 1);
        let day = dump(&store, "SELECT * FROM stats_day").await;
        let top = dump(&store, "SELECT * FROM stats_top_day").await;
        assert_eq!(day.len(), 4, "total, rcode, source, dnssec");
        assert!(raw_min.len() > day.len());
        // Crash after the fold commit but before the deletes: the raw rows come back.
        exec(
            &store,
            "INSERT INTO stats_minute SELECT day, dimension, key, count, latency_sum_us, latency_max_us FROM stats_day",
        )
        .await;
        exec(
            &store,
            "INSERT INTO stats_top_hour SELECT day, kind, key, count FROM stats_top_day",
        )
        .await;
        assert_eq!(fold_rollups(&store, now).await.unwrap(), 1);
        assert_eq!(dump(&store, "SELECT * FROM stats_day").await, day);
        assert_eq!(dump(&store, "SELECT * FROM stats_top_day").await, top);
        assert_eq!(count_rows(&store, "stats_minute").await, 0);
        assert_eq!(count_rows(&store, "stats_top_hour").await, 0);
        // A clean re-run changes nothing.
        assert_eq!(fold_rollups(&store, now).await.unwrap(), 0);
        assert_eq!(dump(&store, "SELECT * FROM stats_day").await, day);
    }

    #[tokio::test]
    async fn days_inside_the_48_hour_window_are_not_folded() {
        let (store, _d) = open_store();
        ingest(&store, vec![event("a.example.", 8 * DAY_MS + 5_000)]).await;
        // Day 8 is complete at 9 d; it is folded once 48 h have passed since then (11 d).
        for now in [
            10 * DAY_MS + 3_600_000,
            10 * DAY_MS + 86_399_000,
            11 * DAY_MS - 1,
        ] {
            assert_eq!(fold_rollups(&store, now).await.unwrap(), 0, "{now}");
        }
        assert_eq!(count_rows(&store, "stats_day").await, 0);
        assert_eq!(fold_rollups(&store, 11 * DAY_MS).await.unwrap(), 1);
        assert_eq!(count_rows(&store, "stats_minute").await, 0);
    }

    /// The top 5000 per (day, kind) survive; ties break on the key. A key just below the cut on
    /// every day is missing from the day rows, which bounds the approximation: a key's total can
    /// only be under-counted by what it scored below the 5000th place of a day.
    #[tokio::test]
    async fn fold_keeps_the_top_5000_per_day_and_kind() {
        let (store, _d) = open_store();
        exec(
            &store,
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < 5000)
             INSERT INTO stats_top_hour (hour, kind, key, count)
             SELECT 3 * 86400, 'qname', printf('k%05d', i), 1 + i / 100 FROM n;
             INSERT INTO stats_top_hour VALUES (3 * 86400 + 3600, 'client', 'only', 1)",
        )
        .await;
        assert_eq!(fold_rollups(&store, 10 * DAY_MS).await.unwrap(), 1);
        let kept = dump(
            &store,
            "SELECT count(*), min(count), max(count) FROM stats_top_day WHERE kind = 'qname'",
        )
        .await;
        assert_eq!(kept, ["Integer(5000),Integer(1),Integer(51)"]);
        // 100 keys have count 1 and ties sort by key, so the last of them is the one dropped.
        assert_eq!(
            dump(
                &store,
                "SELECT count(*) FROM stats_top_day WHERE key = 'k00099'"
            )
            .await,
            ["Integer(0)"]
        );
        assert_eq!(
            dump(
                &store,
                "SELECT count(*) FROM stats_top_day WHERE kind = 'client'"
            )
            .await,
            ["Integer(1)"]
        );
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
