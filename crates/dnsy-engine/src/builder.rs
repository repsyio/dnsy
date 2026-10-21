//! [`EngineBuilder`]: the one place that assembles the pipeline's components.

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use dnsy_config::Config;
use dnsy_filter::{
    Acl, AclAction, BlockMode, FilterError, FilterLimits, FilterSet, FilterSetBuilder, ListManager,
    RateLimiter, RefreshError, RuleStore,
};
use dnsy_observe::QueryEventSink;
use dnsy_resolver::forward::{
    DnssecConfigError, DnssecOptions, DnssecPolicy, MAX_CONCURRENT_FETCHES, unix_now,
};
use dnsy_resolver::groups::{Exchange, GroupError, GroupSet, GroupStoreError};
use dnsy_resolver::{
    Cache, CacheOptions, PrefetchOptions, Refreshes, ServeStaleOptions, UpstreamClient,
    UpstreamConfig, UpstreamError,
};
use dnsy_store::Store;
use dnsy_zone::{KeyStoreError, ZoneError, ZoneStore};
use std::sync::atomic::AtomicBool;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::engine::{Engine, Filters, Now, PREFETCH_QUEUE, RATE_LIMIT_KEYS};
use crate::response::ResponseIpPolicy;
use crate::services::{GroupsHandle, Services};

/// Why the engine could not be assembled.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("zones: {0}")]
    Zones(#[from] ZoneError),
    #[error("dnssec keys: {0}")]
    Keys(#[from] KeyStoreError),
    #[error("upstream client: {0}")]
    Upstream(#[from] UpstreamError),
    #[error("upstream groups: {0}")]
    Groups(#[from] GroupError),
    #[error("upstream group store: {0}")]
    GroupStore(#[from] GroupStoreError),
    #[error("filter rules: {0}")]
    Filter(#[from] FilterError),
    #[error("blocklists: {0}")]
    Lists(#[from] RefreshError),
    #[error("dnssec: {0}")]
    Dnssec(#[from] DnssecConfigError),
}

/// The resolver's DNSSEC settings from `[dnssec]`.
#[must_use]
pub fn dnssec_options(cfg: &dnsy_config::Dnssec) -> DnssecOptions {
    DnssecOptions {
        validation: cfg.validation,
        trust_anchors: cfg.trust_anchors.clone(),
        trust_anchor_file: cfg.trust_anchor_file.clone(),
        negative_trust_anchors: cfg.negative_trust_anchors.clone(),
        clock_skew_s: cfg.clock_skew_s,
    }
}

/// The cache tuning from `[cache]`.
#[must_use]
pub fn cache_options(cfg: &dnsy_config::Cache) -> CacheOptions {
    CacheOptions {
        enabled: cfg.enabled,
        max_entries: cfg.max_entries,
        min_ttl: cfg.min_ttl,
        max_ttl: cfg.max_ttl,
        negative_max_ttl: cfg.negative_max_ttl,
        servfail_ttl: cfg.servfail_ttl,
        bogus_ttl: cfg.bogus_ttl,
        serve_stale: ServeStaleOptions {
            enabled: cfg.serve_stale.enabled,
            max_stale: cfg.serve_stale.max_stale,
            answer_ttl: cfg.serve_stale.answer_ttl,
            client_timeout_ms: cfg.serve_stale.client_timeout_ms,
        },
        prefetch: PrefetchOptions {
            enabled: cfg.prefetch.enabled,
            min_hits: cfg.prefetch.min_hits,
            remaining_ttl_pct: cfg.prefetch.remaining_ttl_pct,
        },
    }
}

/// Assembles an [`Engine`]. [`EngineBuilder::from_config`] wires every component from the
/// configuration and the store; [`EngineBuilder::new`] starts from config defaults only (no
/// zones, no upstreams, no query log) and the setters replace individual components.
pub struct EngineBuilder<E = UpstreamClient> {
    acl: Acl,
    rate_qps: u32,
    rate_slip: u32,
    filter: Filters,
    block_mode: BlockMode,
    response_ip: ResponseIpPolicy,
    zones: Option<Arc<ZoneStore>>,
    cache: Arc<Cache>,
    groups: GroupsHandle,
    exchange: E,
    sink: Option<Arc<dyn QueryEventSink>>,
    attempts: u32,
    deadline: Duration,
    dnssec: DnssecPolicy,
    querylog_task: Option<JoinHandle<()>>,
    stale_wait: Duration,
    now: Now,
}

impl EngineBuilder<UpstreamClient> {
    /// Wires the full pipeline:
    /// - ACL rules (default allow) and the rate limit from the store, falling back to
    ///   `[limits] per_client_qps`;
    /// - the store-backed services (blocklists, zones and signing, upstream groups, query-log
    ///   writer) from [`Services::open`]; callers that need the handles (to run the background
    ///   tasks, share them with the API) use [`Services`] directly and [`EngineBuilder::services`];
    /// - an upstream client with a per-attempt timeout of `timeout_ms`; overall deadline
    ///   `timeout_ms * attempts`;
    /// - DNSSEC validation from `[dnssec]`: mode, trust anchors (inline and file), negative trust
    ///   anchors and clock skew; the clock-sanity floor defaults to
    ///   [`dnsy_resolver::forward::RELEASE_FLOOR_UNIX`] (the binary passes its build time with
    ///   [`EngineBuilder::build_time`]);
    /// - the query-log writer's task is available from [`EngineBuilder::take_querylog_task`].
    ///
    /// Must run inside a Tokio runtime.
    ///
    /// # Errors
    /// Unreadable zones directory, store failures, invalid stored groups, an unusable TLS
    /// setup for the upstream client, or bad trust anchors.
    pub async fn from_config(config: &Config, store: &Store) -> Result<Self, EngineError> {
        let mut services = Services::open(config, store).await?;
        let querylog_task = services.take_querylog_task();
        let mut builder = Self::from_services(config, store, &services).await?;
        builder.querylog_task = querylog_task;
        Ok(builder)
    }

    /// Like [`EngineBuilder::from_config`], with the store-backed services already opened (the
    /// binary shares them with the API and runs their background tasks).
    ///
    /// # Errors
    /// Store failures reading the ACL rules, an unusable TLS setup for the upstream client, or
    /// bad trust anchors.
    pub async fn from_services(
        config: &Config,
        store: &Store,
        services: &Services,
    ) -> Result<Self, EngineError> {
        let client = UpstreamClient::new(UpstreamConfig {
            timeout: Duration::from_millis(config.resolver.timeout_ms),
            case_randomization: config.resolver.case_randomization,
            own_addrs: config
                .dns
                .udp
                .iter()
                .chain(&config.dns.tcp)
                .copied()
                .collect(),
            ..UpstreamConfig::default()
        })?;
        let mut builder = Self::new(config, client).services(services);
        builder.dnssec = DnssecPolicy::from_options(&dnssec_options(&config.dnssec))?;

        let rules = RuleStore::new(store.clone());
        let stored = rules
            .list()
            .await?
            .into_iter()
            .map(|r| (r.matcher, r.action));
        builder.acl = if config.limits.open_resolver {
            Acl::new(AclAction::Allow, stored)
        } else {
            Acl::private_only(stored)
        };
        if let Some(qps) = rules.rate_limit_qps().await? {
            builder.rate_qps = qps;
        }
        if let Some(stored) = rules.response_ip_cidrs().await? {
            builder.response_ip = ResponseIpPolicy::from_strings(&stored);
        }
        Ok(builder)
    }
}

impl<E: Exchange> EngineBuilder<E> {
    /// Config-derived defaults: allow-all ACL (`from_config` applies the private-only base unless
    /// `[limits] open_resolver`), `[limits] per_client_qps`, empty blocklists in
    /// `[filter] block_mode` and `response_ip_blocklist`, cache from `[cache]`, deadline `timeout_ms * attempts`; no zones,
    /// upstream groups, event sink or DNSSEC validation.
    #[must_use]
    pub fn new(config: &Config, exchange: E) -> Self {
        let mode = config.filter.block_mode;
        let attempts = config.resolver.attempts.max(1);
        Self {
            acl: Acl::new(AclAction::Allow, []),
            rate_qps: config.limits.per_client_qps,
            rate_slip: config.limits.rate_limit_slip,
            filter: Filters::Fixed(Arc::new(
                FilterSetBuilder::new(mode, FilterLimits::default()).build(),
            )),
            block_mode: mode,
            response_ip: ResponseIpPolicy::from_strings(&config.filter.response_ip_blocklist),
            zones: None,
            cache: Arc::new(Cache::new(cache_options(&config.cache))),
            groups: Arc::new(ArcSwapOption::empty()),
            exchange,
            sink: None,
            attempts,
            deadline: Duration::from_millis(config.resolver.timeout_ms).saturating_mul(attempts),
            dnssec: DnssecPolicy::off(),
            querylog_task: None,
            stale_wait: Duration::from_millis(config.cache.serve_stale.client_timeout_ms),
            now: Arc::new(Instant::now),
        }
    }

    #[must_use]
    pub fn acl(mut self, acl: Acl) -> Self {
        self.acl = acl;
        self
    }

    #[must_use]
    pub fn rate_limit(mut self, qps: u32) -> Self {
        self.rate_qps = qps;
        self
    }

    /// Answers one over-limit UDP query in `slip` with a truncated reply (0 never does).
    #[must_use]
    pub fn rate_limit_slip(mut self, slip: u32) -> Self {
        self.rate_slip = slip;
        self
    }

    #[must_use]
    pub fn filter(mut self, filter: FilterSet) -> Self {
        self.filter = Filters::Fixed(Arc::new(filter));
        self
    }

    /// Takes the filter from persisted list sources instead of a fixed set.
    #[must_use]
    pub fn list_manager(mut self, manager: ListManager) -> Self {
        self.filter = Filters::Lists(manager);
        self
    }

    #[must_use]
    pub fn response_ip_policy(mut self, policy: ResponseIpPolicy) -> Self {
        self.response_ip = policy;
        self
    }

    #[must_use]
    pub fn zones(mut self, zones: Arc<ZoneStore>) -> Self {
        self.zones = Some(zones);
        self
    }

    /// Sets the upstream groups (in the handle the builder holds, which [`Services`] shares).
    #[must_use]
    pub fn groups(self, groups: GroupSet) -> Self {
        self.groups.store(Some(Arc::new(groups)));
        self
    }

    /// Takes the cache, upstream groups, zones, blocklists and query-log sink from `services`.
    #[must_use]
    pub fn services(mut self, services: &Services) -> Self {
        self.cache = Arc::clone(&services.cache);
        self.groups = Arc::clone(&services.groups);
        if let Some(zones) = &services.zones {
            self.zones = Some(Arc::clone(zones));
        }
        if let Some(lists) = &services.lists {
            self.filter = Filters::Lists(lists.clone());
        }
        if let Some(sink) = &services.sink {
            self.sink = Some(Arc::clone(sink));
        }
        self
    }

    #[must_use]
    pub fn sink(mut self, sink: Arc<dyn QueryEventSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Replaces the DNSSEC validation policy.
    #[must_use]
    pub fn dnssec(mut self, policy: DnssecPolicy) -> Self {
        self.dnssec = policy;
        self
    }

    /// Sets the clock-sanity floor to the binary's build time (seconds since the epoch): while
    /// the system clock is earlier, answers are not validated and are served without AD.
    #[must_use]
    pub fn build_time(mut self, unix: u64) -> Self {
        self.dnssec.not_before_unix = unix;
        self
    }

    /// Replaces the clock the cache is driven by (tests move it by hand).
    #[must_use]
    pub fn clock(mut self, now: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        self.now = Arc::new(now);
        self
    }

    /// The query-log writer task started by [`EngineBuilder::from_config`]; it finishes once the
    /// engine (holding the writer) is dropped and the remaining events are flushed.
    pub fn take_querylog_task(&mut self) -> Option<JoinHandle<()>> {
        self.querylog_task.take()
    }

    #[must_use]
    pub fn build(self) -> Engine<E> {
        let (prefetch_tx, prefetch_rx) = tokio::sync::mpsc::channel(PREFETCH_QUEUE);
        let clock_untrusted = self.dnssec.mode != dnsy_config::Validation::Off
            && !self.dnssec.clock_trusted(unix_now());
        if clock_untrusted {
            // The first validation would find the flag already set and stay silent.
            tracing::warn!("{}", crate::engine::CLOCK_UNTRUSTED_WARNING);
        }
        Engine {
            now: self.now,
            stale_wait: self.stale_wait,
            refreshes: Refreshes::new(),
            prefetch_workers: std::sync::atomic::AtomicUsize::new(0),
            prefetch_tx,
            prefetch_rx: tokio::sync::Mutex::new(prefetch_rx),
            acl: ArcSwap::from_pointee(self.acl),
            rate: ArcSwap::from_pointee(
                RateLimiter::new(self.rate_qps, RATE_LIMIT_KEYS).with_slip(self.rate_slip),
            ),
            filter: self.filter,
            response_ip: ArcSwap::from_pointee(self.response_ip),
            groups: self.groups,
            zones: self.zones,
            cache: self.cache,
            exchange: self.exchange,
            sink: self.sink,
            block_mode: ArcSwap::from_pointee(self.block_mode),
            attempts: self.attempts,
            deadline: self.deadline,
            fetch_permits: Semaphore::new(MAX_CONCURRENT_FETCHES),
            clock_untrusted: Arc::new(AtomicBool::new(clock_untrusted)),
            dnssec: ArcSwap::from_pointee(self.dnssec),
        }
    }
}
