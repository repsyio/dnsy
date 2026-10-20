//! Structured logging with `tracing`. Secrets never reach the log: the transports and the API
//! log client addresses, names and outcomes only, and the configuration is never printed.

use dnsy_config::{LogFormat, LogLevel};
use tracing::level_filters::LevelFilter;

/// Installs the global subscriber (stderr). A second call is a no-op.
pub fn init(level: LogLevel, format: LogFormat) {
    let level = match level {
        LogLevel::Trace => LevelFilter::TRACE,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Error => LevelFilter::ERROR,
    };
    let builder = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr);
    let _ = match format {
        LogFormat::Pretty => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
}
