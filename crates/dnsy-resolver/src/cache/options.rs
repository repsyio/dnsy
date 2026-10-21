//! Cache tuning, owned by the resolver. The engine builder fills it from `[cache]`.

/// Cache tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheOptions {
    /// Master switch.
    pub enabled: bool,
    /// Entry bound.
    pub max_entries: usize,
    /// TTL floor, seconds.
    pub min_ttl: u32,
    /// TTL ceiling, seconds.
    pub max_ttl: u32,
    /// Ceiling for negative answers, seconds.
    pub negative_max_ttl: u32,
    /// How long SERVFAIL is cached, seconds.
    pub servfail_ttl: u32,
    /// How long Bogus results are cached, seconds.
    pub bogus_ttl: u32,
    /// Serve-stale (RFC 8767).
    pub serve_stale: ServeStaleOptions,
    /// Prefetch of popular entries.
    pub prefetch: PrefetchOptions,
}

impl Default for CacheOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 100_000,
            min_ttl: 0,
            max_ttl: 86_400,
            negative_max_ttl: 3600,
            servfail_ttl: 5,
            bogus_ttl: 60,
            serve_stale: ServeStaleOptions::default(),
            prefetch: PrefetchOptions::default(),
        }
    }
}

/// Serve-stale tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeStaleOptions {
    /// Enable serving stale answers.
    pub enabled: bool,
    /// How long stale entries are kept, seconds.
    pub max_stale: u32,
    /// TTL placed on stale answers, seconds.
    pub answer_ttl: u32,
    /// Wait for the refresh this long before answering stale.
    pub client_timeout_ms: u64,
}

impl Default for ServeStaleOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            max_stale: 86_400,
            answer_ttl: 30,
            client_timeout_ms: 1800,
        }
    }
}

/// Prefetch tuning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchOptions {
    /// Enable prefetch.
    pub enabled: bool,
    /// Hits an entry needs to qualify.
    pub min_hits: u32,
    /// Prefetch when this percentage of the TTL remains.
    pub remaining_ttl_pct: u8,
}

impl Default for PrefetchOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            min_hits: 5,
            remaining_ttl_pct: 10,
        }
    }
}
