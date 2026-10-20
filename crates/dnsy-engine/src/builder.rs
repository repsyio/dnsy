//! [`EngineBuilder`]: the one place that assembles the pipeline's components.

use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use dnsy_config::Config;
use dnsy_filter::{
    Acl, AclAction, BlockMode, FETCH_TIMEOUT, Fetcher, FilterError, FilterLimits, FilterSet,
    FilterSetBuilder, ListManager, MAX_LIST_BYTES, RateLimiter, RefreshError, RuleStore,
    SourceStore,
};
use dnsy_observe::{QueryEventSink, QueryLogWriter, WriterConfig};
use dnsy_resolver::forward::{DnssecConfigError, DnssecPolicy, MAX_CONCURRENT_FETCHES, unix_now};
use dnsy_resolver::groups::{
    Exchange, GroupError, GroupSet, GroupStore, GroupStoreError, SystemClock, ThreadRng,
};
use dnsy_resolver::{Cache, Refreshes, UpstreamClient, UpstreamConfig, UpstreamError};
use dnsy_store::Store;
use dnsy_zone::{
    KeyStore, KeyStoreError, ZoneError, ZoneSigning, ZoneStore, passphrase_from_environment,
};
use std::sync::atomic::AtomicBool;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::engine::{Engine, Filters, Now, PREFETCH_QUEUE, RATE_LIMIT_KEYS};
use crate::response::ResponseIpPolicy;

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

fn block_mode(mode: dnsy_config::BlockMode) -> BlockMode {
    match mode {
        dnsy_config::BlockMode::NullIp => BlockMode::NullIp,
        dnsy_config::BlockMode::Nxdomain => BlockMode::NxDomain,
        dnsy_config::BlockMode::Refused => BlockMode::Refused,
    }
}

/// Assembles an [`Engine`]. [`EngineBuilder::from_config`] wires every component from the
/// configuration and the store; [`EngineBuilder::new`] starts from config defaults only (no
/// zones, no upstreams, no query log) and the setters replace individual components.
pub struct EngineBuilder<E = UpstreamClient> {
    acl: Acl,
    rate_qps: u32,
    filter: Filters,
    block_mode: BlockMode,
    response_ip: ResponseIpPolicy,
    zones: Option<Arc<ZoneStore>>,
    zone_signing: Option<ZoneSigning>,
    cache: Arc<Cache>,
    groups: Option<GroupSet>,
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
    /// - blocklists from the persisted list sources (seeded from `[filter] blocklists` on first
    ///   start) answering in `[filter] block_mode`; the filter starts from the custom rules and
    ///   fills as the caller runs [`dnsy_filter::ListManager::run`] (via [`Engine::list_manager`]);
    /// - local zones from `[zones] dir` (the caller starts the watcher via
    ///   [`Engine::zone_store`]); zones with `dnssec.enabled` are signed before this returns,
    ///   with keys from the store's key table (passphrase from `DNSY_DNSSEC_PASSPHRASE` or
    ///   `[dnssec] key_passphrase_file`); the caller spawns the re-signing task via
    ///   [`Engine::zone_signing`];
    /// - the cache from `[cache]`;
    /// - upstream groups from the store, seeded from `[resolver] upstreams` on first start, and an
    ///   upstream client with a per-attempt timeout of `timeout_ms`; overall deadline
    ///   `timeout_ms * attempts`;
    /// - DNSSEC validation from `[dnssec]`: mode, trust anchors (inline and file), negative trust
    ///   anchors and clock skew; the clock-sanity floor defaults to
    ///   [`dnsy_resolver::forward::RELEASE_FLOOR_UNIX`] (the binary passes its build time with
    ///   [`EngineBuilder::build_time`]);
    /// - the batched query-log writer when `[querylog] enabled` (take its task with
    ///   [`EngineBuilder::take_querylog_task`] to await the final flush on shutdown).
    ///
    /// Must run inside a Tokio runtime.
    ///
    /// # Errors
    /// Unreadable zones directory, store failures, invalid stored groups, an unusable TLS
    /// setup for the upstream client, or bad trust anchors.
    pub async fn from_config(config: &Config, store: &Store) -> Result<Self, EngineError> {
        let client = UpstreamClient::new(UpstreamConfig {
            timeout: Duration::from_millis(config.resolver.timeout_ms),
            ..UpstreamConfig::default()
        })?;
        let mut builder = Self::new(config, client);
        builder.dnssec = DnssecPolicy::from_config(&config.dnssec)?;

        let rules = RuleStore::new(store.clone());
        builder.acl = Acl::new(
            AclAction::Allow,
            rules
                .list()
                .await?
                .into_iter()
                .map(|r| (r.matcher, r.action)),
        );
        if let Some(qps) = rules.rate_limit_qps().await? {
            builder.rate_qps = qps;
        }

        let sources = SourceStore::new(store.clone());
        sources
            .seed(&config.filter.blocklists, config.filter.refresh_interval)
            .await?;
        let lists = ListManager::new(
            sources,
            builder.block_mode,
            FilterLimits::default(),
            Fetcher::new(MAX_LIST_BYTES, FETCH_TIMEOUT),
            Arc::new(dnsy_filter::SystemClock),
        );
        lists.reload().await?;
        builder.filter = Filters::Lists(lists);

        let zones = ZoneStore::open(&config.zones.dir)?;
        let passphrase = passphrase_from_environment(config.dnssec.key_passphrase_file.as_deref())?;
        let keys = KeyStore::open(
            store.clone(),
            passphrase,
            Arc::new(dnsy_dnssec::SystemClock),
        );
        let signing = ZoneSigning::new(Arc::clone(&zones), keys);
        signing.sign_due().await;
        builder.zones = Some(zones);
        builder.zone_signing = Some(signing);

        let groups = GroupStore::new(store.clone());
        groups.seed_default(&config.resolver.upstreams).await?;
        let specs = groups.list().await?;
        if !specs.is_empty() {
            builder.groups = Some(GroupSet::new(
                specs,
                Arc::new(SystemClock::new()),
                Arc::new(ThreadRng),
            )?);
        }

        if config.querylog.enabled {
            let (writer, task) = QueryLogWriter::spawn(
                store.clone(),
                WriterConfig {
                    redact_client_ip: config.querylog.redact_client_ip,
                    ..WriterConfig::default()
                },
            );
            builder.sink = Some(Arc::new(writer));
            builder.querylog_task = Some(task);
        }
        Ok(builder)
    }
}

impl<E: Exchange> EngineBuilder<E> {
    /// Config-derived defaults: allow-all ACL, `[limits] per_client_qps`, empty blocklists in
    /// `[filter] block_mode`, cache from `[cache]`, deadline `timeout_ms * attempts`; no zones,
    /// upstream groups, event sink or DNSSEC validation.
    #[must_use]
    pub fn new(config: &Config, exchange: E) -> Self {
        let mode = block_mode(config.filter.block_mode);
        let attempts = config.resolver.attempts.max(1);
        Self {
            acl: Acl::new(AclAction::Allow, []),
            rate_qps: config.limits.per_client_qps,
            filter: Filters::Fixed(Arc::new(
                FilterSetBuilder::new(mode, FilterLimits::default()).build(),
            )),
            block_mode: mode,
            response_ip: ResponseIpPolicy::default(),
            zones: None,
            zone_signing: None,
            cache: Arc::new(Cache::new(&config.cache)),
            groups: None,
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

    #[must_use]
    pub fn groups(mut self, groups: GroupSet) -> Self {
        self.groups = Some(groups);
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
        Engine {
            now: self.now,
            stale_wait: self.stale_wait,
            refreshes: Refreshes::new(),
            prefetch_workers: std::sync::atomic::AtomicUsize::new(0),
            prefetch_tx,
            prefetch_rx: tokio::sync::Mutex::new(prefetch_rx),
            acl: ArcSwap::from_pointee(self.acl),
            rate: ArcSwap::from_pointee(RateLimiter::new(self.rate_qps, RATE_LIMIT_KEYS)),
            filter: self.filter,
            response_ip: ArcSwap::from_pointee(self.response_ip),
            groups: ArcSwapOption::from(self.groups.map(Arc::new)),
            zones: self.zones,
            zone_signing: self.zone_signing,
            cache: self.cache,
            exchange: self.exchange,
            sink: self.sink,
            block_mode: ArcSwap::from_pointee(self.block_mode),
            attempts: self.attempts,
            deadline: self.deadline,
            fetch_permits: Semaphore::new(MAX_CONCURRENT_FETCHES),
            clock_untrusted: Arc::new(AtomicBool::new(
                self.dnssec.mode != dnsy_config::Validation::Off
                    && !self.dnssec.clock_trusted(unix_now()),
            )),
            dnssec: ArcSwap::from_pointee(self.dnssec),
        }
    }
}
