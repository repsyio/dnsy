use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use dnsy_store::Store;
use rusqlite::{Connection, params};

use crate::ObserveError;

/// Half-open time range `[from_ms, to_ms)` in unix milliseconds. Rollups are
/// minute (counters) and hour (top-N) granular, and day granular once the
/// hourly retention task has folded a UTC day (older than 48 hours), so
/// partially covered buckets are included whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeRange {
    pub from_ms: i64,
    pub to_ms: i64,
}

impl TimeRange {
    /// Bucket starts (unix seconds) `[lo, hi)` for buckets of `unit_s` seconds.
    fn buckets(self, unit_s: i64) -> (i64, i64) {
        let width_ms = unit_s * 1000;
        let first = self.from_ms.div_euclid(width_ms) * unit_s;
        let end = (self.to_ms + width_ms - 1).div_euclid(width_ms) * unit_s;
        (first, end)
    }
}

const DAY_S: i64 = 86_400;

/// First second after the last folded day of `table` (`stats_day` or `stats_top_day`), 0 when
/// nothing is folded. Folding goes oldest first, so every day below it is folded; its raw
/// minute and hour rows are deleted (or about to be) and must not be read next to the day rows.
fn folded_until(c: &Connection, table: &str) -> rusqlite::Result<i64> {
    let last: Option<i64> =
        c.query_row(&format!("SELECT max(day) FROM {table}"), [], |r| r.get(0))?;
    Ok(last.map_or(0, |d| d + DAY_S))
}

/// Aggregate over a range.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    pub total: u64,
    pub by_rcode: BTreeMap<u16, u64>,
    pub by_source: BTreeMap<String, u64>,
    pub by_dnssec: BTreeMap<String, u64>,
    pub avg_latency_us: u64,
    pub max_latency_us: u64,
    /// Answers served from cache, fresh or stale.
    pub cache_hits: u64,
    /// Answers that needed an upstream.
    pub cache_misses: u64,
    /// `cache_hits / (cache_hits + cache_misses)`, 0 when there were no lookups.
    pub cache_hit_ratio: f64,
    pub stale_answers: u64,
    pub secure: u64,
    pub bogus: u64,
}

/// One timeseries bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimePoint {
    pub start_ms: i64,
    pub total: u64,
    pub blocked: u64,
    pub cache_hits: u64,
    pub max_latency_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopEntry {
    pub key: String,
    pub count: u64,
}

/// Read side of the rollups.
#[derive(Clone)]
pub struct StatsService {
    store: Store,
}

impl StatsService {
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    pub async fn summary(&self, range: TimeRange) -> Result<Summary, ObserveError> {
        let (lo, hi) = range.buckets(60);
        let rows = self
            .store
            .read(move |c| Ok(summary_rows(c, lo, hi)?))
            .await?;
        let mut s = Summary {
            total: 0,
            by_rcode: BTreeMap::new(),
            by_source: BTreeMap::new(),
            by_dnssec: BTreeMap::new(),
            avg_latency_us: 0,
            max_latency_us: 0,
            cache_hits: 0,
            cache_misses: 0,
            cache_hit_ratio: 0.0,
            stale_answers: 0,
            secure: 0,
            bogus: 0,
        };
        let mut latency_sum = 0u64;
        for (_, dim, key, count, sum, max) in rows {
            match dim.as_str() {
                "total" => {
                    s.total += count;
                    latency_sum += sum;
                    s.max_latency_us = s.max_latency_us.max(max);
                }
                "rcode" => {
                    if let Ok(code) = key.parse() {
                        *s.by_rcode.entry(code).or_default() += count;
                    }
                }
                "source" => *s.by_source.entry(key).or_default() += count,
                "dnssec" => *s.by_dnssec.entry(key).or_default() += count,
                _ => {}
            }
        }
        let src = |k: &str| s.by_source.get(k).copied().unwrap_or(0);
        s.stale_answers = src("cache_stale");
        s.cache_hits = src("cache") + src("cache_stale");
        s.cache_misses = src("upstream");
        let lookups = s.cache_hits + s.cache_misses;
        if lookups > 0 {
            #[expect(
                clippy::cast_precision_loss,
                reason = "ratio of counters, precision loss is irrelevant"
            )]
            {
                s.cache_hit_ratio = s.cache_hits as f64 / lookups as f64;
            }
        }
        s.secure = s.by_dnssec.get("secure").copied().unwrap_or(0);
        s.bogus = s.by_dnssec.get("bogus").copied().unwrap_or(0);
        s.avg_latency_us = latency_sum.checked_div(s.total).unwrap_or(0);
        Ok(s)
    }

    /// Buckets of `bucket` (a non-zero multiple of 60 s) that contain data, oldest first.
    /// Minute rows only exist for the last two to three days; buckets of a day or more also
    /// read the daily rollups (a day belongs to the bucket holding its first second), shorter
    /// buckets see nothing older.
    pub async fn timeseries(
        &self,
        range: TimeRange,
        bucket: Duration,
    ) -> Result<Vec<TimePoint>, ObserveError> {
        let secs = i64::try_from(bucket.as_secs()).map_err(|_| ObserveError::InvalidBucket)?;
        if secs == 0 || secs % 60 != 0 || bucket.subsec_nanos() != 0 {
            return Err(ObserveError::InvalidBucket);
        }
        let (lo, hi) = range.buckets(60);
        let daily = secs >= DAY_S;
        let rows = self
            .store
            .read(move |c| Ok(counter_rows(c, lo, hi, daily)?))
            .await?;
        let mut points: BTreeMap<i64, TimePoint> = BTreeMap::new();
        for (minute, dim, key, count, _, max) in rows {
            let start = minute.div_euclid(secs) * secs;
            let p = points.entry(start).or_insert(TimePoint {
                start_ms: start * 1000,
                total: 0,
                blocked: 0,
                cache_hits: 0,
                max_latency_us: 0,
            });
            match (dim.as_str(), key.as_str()) {
                ("total", _) => {
                    p.total += count;
                    p.max_latency_us = p.max_latency_us.max(max);
                }
                ("source", "blocked") => p.blocked += count,
                ("source", "cache" | "cache_stale") => p.cache_hits += count,
                _ => {}
            }
        }
        Ok(points.into_values().collect())
    }

    pub async fn top_domains(
        &self,
        range: TimeRange,
        n: usize,
    ) -> Result<Vec<TopEntry>, ObserveError> {
        self.top("qname", range, n).await
    }

    pub async fn top_blocked(
        &self,
        range: TimeRange,
        n: usize,
    ) -> Result<Vec<TopEntry>, ObserveError> {
        self.top("blocked", range, n).await
    }

    pub async fn top_clients(
        &self,
        range: TimeRange,
        n: usize,
    ) -> Result<Vec<TopEntry>, ObserveError> {
        self.top("client", range, n).await
    }

    async fn top(
        &self,
        kind: &'static str,
        range: TimeRange,
        n: usize,
    ) -> Result<Vec<TopEntry>, ObserveError> {
        let (lo, hi) = range.buckets(3600);
        let limit = i64::try_from(n).unwrap_or(i64::MAX);
        Ok(self
            .store
            .read(move |c| {
                let folded = folded_until(c, "stats_top_day")?;
                let mut counts: HashMap<String, u64> = HashMap::new();
                let mut add =
                    |sql: &str, params: &[&dyn rusqlite::ToSql]| -> rusqlite::Result<()> {
                        let mut stmt = c.prepare_cached(sql)?;
                        let mut rows = stmt.query(params)?;
                        while let Some(r) = rows.next()? {
                            let key = r.get_ref(0)?.as_str()?;
                            let n = r.get::<_, i64>(1)?.cast_unsigned();
                            if let Some(v) = counts.get_mut(key) {
                                *v += n;
                            } else {
                                counts.insert(key.to_owned(), n);
                            }
                        }
                        Ok(())
                    };
                // Whole folded days overlapping the range (an edge day counts whole), then
                // hour rows from the first unfolded second.
                let mut day = lo.div_euclid(DAY_S) * DAY_S;
                while day < folded.min(hi) {
                    add(
                        "SELECT key, count FROM stats_top_day WHERE day = ?1 AND kind = ?2",
                        &[&day, &kind],
                    )?;
                    day += DAY_S;
                }
                add(
                    "SELECT key, count FROM stats_top_hour
                     WHERE kind = ?1 AND hour >= ?2 AND hour < ?3",
                    &[&kind, &lo.max(folded), &hi],
                )?;
                let mut top: Vec<TopEntry> = counts
                    .into_iter()
                    .map(|(key, count)| TopEntry { key, count })
                    .collect();
                top.sort_unstable_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
                top.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                Ok(top)
            })
            .await?)
    }
}

type MinuteRow = (i64, String, String, u64, u64, u64);

fn minute_rows(c: &Connection, lo: i64, hi: i64) -> rusqlite::Result<Vec<MinuteRow>> {
    let mut stmt = c.prepare_cached(
        "SELECT minute, dimension, key, count, latency_sum_us, latency_max_us
         FROM stats_minute WHERE minute >= ?1 AND minute < ?2 ORDER BY minute",
    )?;
    let rows = stmt.query_map(params![lo, hi], row_of)?;
    rows.collect()
}

/// Counter rows for `[lo, hi)` seconds: the daily rollups of folded days that overlap the range
/// when `daily` is set (an edge day counts whole), then minute rows from the first unfolded
/// second. The first column is the minute or day start.
fn counter_rows(c: &Connection, lo: i64, hi: i64, daily: bool) -> rusqlite::Result<Vec<MinuteRow>> {
    if !daily {
        return minute_rows(c, lo, hi);
    }
    let folded = folded_until(c, "stats_day")?;
    let mut rows = Vec::new();
    let day_lo = lo.div_euclid(DAY_S) * DAY_S;
    if day_lo < folded.min(hi) {
        let mut stmt = c.prepare_cached(
            "SELECT day, dimension, key, count, latency_sum_us, latency_max_us
             FROM stats_day WHERE day >= ?1 AND day < ?2 ORDER BY day",
        )?;
        let found = stmt.query_map(params![day_lo, folded.min(hi)], row_of)?;
        for r in found {
            rows.push(r?);
        }
    }
    rows.extend(minute_rows(c, lo.max(folded), hi)?);
    Ok(rows)
}

/// Like [`counter_rows`] but summed per (dimension, key) while reading, so a long range costs
/// no allocation per minute or day row. The first column is 0.
fn summary_rows(c: &Connection, lo: i64, hi: i64) -> rusqlite::Result<Vec<MinuteRow>> {
    let folded = folded_until(c, "stats_day")?;
    let day_lo = lo.div_euclid(DAY_S) * DAY_S;
    let mut sums: Vec<MinuteRow> = Vec::new();
    let mut run = |sql: &str, from: i64, to: i64| -> rusqlite::Result<()> {
        if from >= to {
            return Ok(());
        }
        let mut stmt = c.prepare_cached(sql)?;
        let mut rows = stmt.query(params![from, to])?;
        while let Some(r) = rows.next()? {
            let dim = r.get_ref(0)?.as_str()?;
            let key = r.get_ref(1)?.as_str()?;
            let count = r.get::<_, i64>(2)?.cast_unsigned();
            let sum = r.get::<_, i64>(3)?.cast_unsigned();
            let max = r.get::<_, i64>(4)?.cast_unsigned();
            if let Some(e) = sums.iter_mut().find(|e| e.1 == dim && e.2 == key) {
                e.3 += count;
                e.4 += sum;
                e.5 = e.5.max(max);
            } else {
                sums.push((0, dim.to_owned(), key.to_owned(), count, sum, max));
            }
        }
        Ok(())
    };
    run(
        "SELECT dimension, key, count, latency_sum_us, latency_max_us
         FROM stats_day WHERE day >= ?1 AND day < ?2",
        day_lo,
        folded.min(hi),
    )?;
    run(
        "SELECT dimension, key, count, latency_sum_us, latency_max_us
         FROM stats_minute WHERE minute >= ?1 AND minute < ?2",
        lo.max(folded),
        hi,
    )?;
    Ok(sums)
}

fn row_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<MinuteRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get::<_, i64>(3)?.cast_unsigned(),
        r.get::<_, i64>(4)?.cast_unsigned(),
        r.get::<_, i64>(5)?.cast_unsigned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnswerSource;
    use crate::testutil::{event, ingest, open_store};
    use dnsy_core::DnssecStatus;

    const RANGE: TimeRange = TimeRange {
        from_ms: 0,
        to_ms: 10 * 3_600_000,
    };

    #[tokio::test]
    async fn top_domains_orders_by_count() {
        let (store, _d) = open_store();
        let mut evs = Vec::new();
        for (name, n) in [
            ("a.example.", 1),
            ("b.example.", 3),
            ("c.example.", 2),
            ("d.example.", 2),
        ] {
            for _ in 0..n {
                evs.push(event(name, 1_000));
            }
        }
        // Spread across two hours: counts are summed.
        evs.push(event("a.example.", 3_700_000));
        evs.push(event("a.example.", 3_700_000));
        let mut blocked = event("ads.example.", 1_000);
        blocked.source = AnswerSource::Blocked { list: "ads".into() };
        evs.push(blocked);
        ingest(&store, evs).await;

        let stats = StatsService::new(store);
        let top = stats.top_domains(RANGE, 3).await.unwrap();
        let got: Vec<_> = top.iter().map(|t| (t.key.as_str(), t.count)).collect();
        assert_eq!(
            got,
            [("a.example.", 3), ("b.example.", 3), ("c.example.", 2)]
        );
        let blocked = stats.top_blocked(RANGE, 10).await.unwrap();
        assert_eq!(
            blocked,
            [TopEntry {
                key: "ads.example.".into(),
                count: 1
            }]
        );
        let clients = stats.top_clients(RANGE, 10).await.unwrap();
        assert_eq!(
            clients,
            [TopEntry {
                key: "192.0.2.77".into(),
                count: 11
            }]
        );
        let first_hour = TimeRange {
            from_ms: 0,
            to_ms: 3_600_000,
        };
        assert_eq!(
            stats.top_domains(first_hour, 1).await.unwrap()[0].key,
            "b.example."
        );
    }

    #[tokio::test]
    async fn summary_cache_hit_ratio() {
        let (store, _d) = open_store();
        let mut evs = Vec::new();
        for (src, n) in [
            (AnswerSource::Cache, 5),
            (AnswerSource::CacheStale, 2),
            (
                AnswerSource::Upstream("198.51.100.1:53".parse().unwrap()),
                3,
            ),
            (AnswerSource::Authoritative, 4),
        ] {
            for i in 0..n {
                let mut e = event("x.example.", 60_000 + i);
                e.source = src.clone();
                e.latency_us = 100 * u32::try_from(i + 1).unwrap();
                if matches!(src, AnswerSource::Cache) {
                    e.dnssec = DnssecStatus::Secure;
                }
                if matches!(src, AnswerSource::CacheStale) {
                    e.dnssec = DnssecStatus::Bogus;
                }
                evs.push(e);
            }
        }
        ingest(&store, evs).await;
        let s = StatsService::new(store).summary(RANGE).await.unwrap();
        assert_eq!(s.total, 14);
        assert_eq!((s.cache_hits, s.cache_misses, s.stale_answers), (7, 3, 2));
        assert!((s.cache_hit_ratio - 0.7).abs() < 1e-9);
        assert_eq!((s.secure, s.bogus), (5, 2));
        assert_eq!(s.by_rcode.get(&0), Some(&14));
        assert_eq!(s.max_latency_us, 500);
        assert_eq!(s.avg_latency_us, (1500 + 300 + 600 + 1000) / 14);
    }

    #[tokio::test]
    async fn empty_summary_and_timeseries() {
        let (store, _d) = open_store();
        let stats = StatsService::new(store);
        let s = stats.summary(RANGE).await.unwrap();
        assert_eq!((s.total, s.avg_latency_us), (0, 0));
        assert!(s.cache_hit_ratio.abs() < f64::EPSILON);
        let none = stats
            .timeseries(RANGE, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(none, []);
        for bad in [Duration::ZERO, Duration::from_secs(90)] {
            assert!(matches!(
                stats.timeseries(RANGE, bad).await,
                Err(ObserveError::InvalidBucket)
            ));
        }
    }

    #[tokio::test]
    async fn timeseries_buckets_events() {
        let (store, _d) = open_store();
        let mut blocked = event("b.example.", 400_000);
        blocked.source = AnswerSource::Blocked { list: "l".into() };
        let mut cached = event("c.example.", 410_000);
        cached.source = AnswerSource::Cache;
        ingest(&store, vec![event("a.example.", 61_000), blocked, cached]).await;
        let pts = StatsService::new(store)
            .timeseries(RANGE, Duration::from_secs(300))
            .await
            .unwrap();
        assert_eq!(
            pts,
            [
                TimePoint {
                    start_ms: 0,
                    total: 1,
                    blocked: 0,
                    cache_hits: 0,
                    max_latency_us: 1000
                },
                TimePoint {
                    start_ms: 300_000,
                    total: 2,
                    blocked: 1,
                    cache_hits: 1,
                    max_latency_us: 1000
                },
            ]
        );
    }

    /// 30 days of rollups for 10 M logged queries (2 000 distinct names per hour with 7 queries each on average, 720 hours: 1.4 M hour rows):
    /// `top` and `summary` read the daily rows once the hourly fold ran. Run with
    /// `cargo nextest run --release -p dnsy-observe --run-ignored only --no-capture daily_rollup_benchmark`
    /// (the bundled SQLite is only optimised in release builds); the asserts are the targets:
    /// 30-day top domains under 50 ms and 30-day summary under 10 ms.
    #[tokio::test]
    #[ignore = "benchmark: generates 1.4 M hour and 690 k minute rows, takes a few seconds"]
    async fn daily_rollup_benchmark() {
        use std::time::Instant;
        let (store, _d) = open_store();
        let now_ms: i64 = 1_000 * 86_400_000 + 12 * 3_600_000;
        let start_s = now_ms / 1000 / 3600 * 3600 - 30 * 86_400;
        store
            .write(move |t| {
                t.execute_batch(&format!(
                    "WITH RECURSIVE h(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM h WHERE i < 719),
                          k(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM k WHERE i < 1999)
                     INSERT INTO stats_top_hour (hour, kind, key, count)
                     SELECT {start_s} + h.i * 3600, 'qname',
                            printf('d%d.example.', (h.i * 977 + k.i * 31) % 150000), 1 + (k.i * 7) % 13
                     FROM h, k;
                     WITH RECURSIVE m(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM m WHERE i < 43199),
                          d(dim, key) AS (VALUES ('total', ''), ('rcode', '0'), ('rcode', '3'), ('rcode', '2'),
                              ('source', 'cache'), ('source', 'upstream'), ('source', 'blocked'), ('source', 'authoritative'),
                              ('source', 'cache_stale'), ('source', 'rate_limited'), ('source', 'refused'), ('source', 'error'),
                              ('dnssec', 'secure'), ('dnssec', 'insecure'), ('dnssec', 'bogus'), ('dnssec', 'unchecked'))
                     INSERT INTO stats_minute (minute, dimension, key, count, latency_sum_us, latency_max_us)
                     SELECT {start_s} + m.i * 60, dim, key, 230, 230 * 900, 5000 FROM m, d"
                ))?;
                Ok(())
            })
            .await
            .unwrap();
        let stats = StatsService::new(store.clone());
        let range = TimeRange {
            from_ms: now_ms - 30 * 86_400_000,
            to_ms: now_ms,
        };
        let time = |label: &'static str, start: Instant| {
            println!("{label}: {:?}", start.elapsed());
            start.elapsed()
        };
        let t = Instant::now();
        let raw_top = stats.top_domains(range, 20).await.unwrap();
        time("top domains, 30 days, raw hour rows", t);
        let t = Instant::now();
        let raw_sum = stats.summary(range).await.unwrap();
        time("summary, 30 days, raw minute rows", t);

        let t = Instant::now();
        let days = crate::retention::fold_rollups(&store, now_ms)
            .await
            .unwrap();
        time("fold", t);
        println!("folded {days} days");
        let mut best_top = std::time::Duration::MAX;
        let mut best_sum = std::time::Duration::MAX;
        for _ in 0..5 {
            let t = Instant::now();
            let top = stats.top_domains(range, 20).await.unwrap();
            best_top = best_top.min(time("top domains, 30 days, daily rows", t));
            let t = Instant::now();
            let sum = stats.summary(range).await.unwrap();
            best_sum = best_sum.min(time("summary, 30 days, daily rows", t));
            assert_eq!(sum.total, raw_sum.total);
            assert_eq!(top.len(), raw_top.len());
        }
        // The same range without the unfolded two to three days at its end: daily rows only.
        let folded_range = TimeRange {
            from_ms: range.from_ms,
            to_ms: (now_ms - 48 * 3_600_000) / 86_400_000 * 86_400_000,
        };
        let t = Instant::now();
        stats.top_domains(folded_range, 20).await.unwrap();
        time("top domains, folded days only", t);
        let t = Instant::now();
        stats.summary(folded_range).await.unwrap();
        time("summary, folded days only", t);
        assert!(best_top.as_millis() < 50, "top took {best_top:?}");
        assert!(best_sum.as_millis() < 10, "summary took {best_sum:?}");
    }
}
