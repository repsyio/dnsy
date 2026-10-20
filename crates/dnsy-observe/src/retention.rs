use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnsy_store::Store;
use tokio::task::JoinHandle;

use crate::ObserveError;

/// Delete query-log rows older than `cutoff_ms` and hourly top-N rows that end
/// before it. Minute rollups are tiny and kept. Returns the query-log rows removed.
pub async fn purge_before(store: &Store, cutoff_ms: i64) -> Result<usize, ObserveError> {
    Ok(store
        .write(move |tx| {
            let rows = tx.execute("DELETE FROM query_log WHERE ts_ms < ?1", [cutoff_ms])?;
            tx.execute(
                "DELETE FROM stats_top_hour WHERE hour + 3600 <= ?1",
                [cutoff_ms.div_euclid(1000)],
            )?;
            Ok(rows)
        })
        .await?)
}

/// Purge once now and then every `interval`, keeping `retention` of history.
/// Abort the returned handle to stop it.
#[must_use]
pub fn spawn_retention(store: Store, retention: Duration, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
            let cutoff =
                now_ms.saturating_sub(i64::try_from(retention.as_millis()).unwrap_or(i64::MAX));
            if let Err(e) = purge_before(&store, cutoff).await {
                tracing::warn!(error = %e, "query log retention purge failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{count_rows, event, ingest, open_store, wait_for_rows};

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
}
