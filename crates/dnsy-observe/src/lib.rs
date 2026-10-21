//! Query events, the batched query-log writer, per-minute/hour rollups, stats
//! queries, keyset-paginated log search and retention.

#![expect(
    clippy::missing_errors_doc,
    reason = "every fallible function returns ObserveError, documented on the type"
)]

mod event;
mod query;
mod retention;
mod stats;
mod writer;

pub use event::{AnswerSource, QueryEvent, QueryEventSink, SourceKind, redact_client_ip};
pub use query::{Cursor, LogEntry, LogPage, QueryLogQuery, search};
pub use retention::{purge_before, spawn_retention, spawn_retention_watch};
pub use stats::{StatsService, Summary, TimePoint, TimeRange, TopEntry};
pub use writer::{QueryLogCounters, QueryLogWriter, WriterConfig, querylog_counters};

/// Failure of an observe operation.
#[derive(Debug, thiserror::Error)]
pub enum ObserveError {
    #[error(transparent)]
    Store(#[from] dnsy_store::StoreError),
    #[error("timeseries bucket must be a non-zero multiple of 60 seconds")]
    InvalidBucket,
}

impl From<rusqlite::Error> for ObserveError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Store(e.into())
    }
}

#[cfg(test)]
mod testutil;
