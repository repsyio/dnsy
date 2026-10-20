//! [`EngineBuilder`]: the one place that assembles the pipeline's components.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use dnsy_config::Config;
use dnsy_filter::{
    Acl, AclAction, BlockMode, FETCH_TIMEOUT, Fetcher, FilterError, FilterLimits, FilterSet,
    FilterSetBuilder, ListManager, MAX_LIST_BYTES, RateLimiter, RefreshError, RuleStore,
    SourceStore,
};
use dnsy_observe::{QueryEventSink, QueryLogWriter, WriterConfig};
use dnsy_resolver::groups::{
    Exchange, GroupError, GroupSet, GroupStore, GroupStoreError, SystemClock, ThreadRng,
};
use dnsy_resolver::{Cache, UpstreamClient, UpstreamConfig, UpstreamError};
use dnsy_store::Store;
use dnsy_zone::{ZoneError, ZoneStore};
use tokio::task::JoinHandle;

use crate::engine::{Engine, Filters, RATE_LIMIT_KEYS};
use crate::response::ResponseIpPolicy;

/// Why the engine could not be assembled.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("zones: {0}")]
    Zones(#[from] ZoneError),
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
    cache: Arc<Cache>,
    groups: Option<GroupSet>,
    exchange: E,
    sink: Option<Arc<dyn QueryEventSink>>,
    attempts: u32,
    deadline: Duration,
    querylog_task: Option<JoinHandle<()>>,
}

impl EngineBuilder<UpstreamClient> {
    /// Wires the full pipeline:
    /// - ACL rules (default allow) and the rate limit from the store, falling back to
    ///   `[limits] per_client_qps`;
    /// - blocklists from the persisted list sources (seeded from `[filter] blocklists` on first
    ///   start) answering in `[filter] block_mode`; the filter starts from the custom rules and
    ///   fills as the caller runs [`dnsy_filter::ListManager::run`] (via [`Engine::list_manager`]);
    /// - local zones from `[zones] dir` (the caller starts the watcher via
    ///   [`Engine::zone_store`]);
    /// - the cache from `[cache]`;
    /// - upstream groups from the store, seeded from `[resolver] upstreams` on first start, and an
    ///   upstream client with a per-attempt timeout of `timeout_ms`; overall deadline
    ///   `timeout_ms * attempts`;
    /// - the batched query-log writer when `[querylog] enabled` (take its task with
    ///   [`EngineBuilder::take_querylog_task`] to await the final flush on shutdown).
    ///
    /// Must run inside a Tokio runtime.
    ///
    /// # Errors
    /// Unreadable zones directory, store failures, invalid stored groups, or an unusable TLS
    /// setup for the upstream client.
    pub async fn from_config(config: &Config, store: &Store) -> Result<Self, EngineError> {
        let client = UpstreamClient::new(UpstreamConfig {
            timeout: Duration::from_millis(config.resolver.timeout_ms),
            ..UpstreamConfig::default()
        })?;
        let mut builder = Self::new(config, client);

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

        builder.zones = Some(ZoneStore::open(&config.zones.dir)?);

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
    /// upstream groups or event sink.
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
            cache: Arc::new(Cache::new(&config.cache)),
            groups: None,
            exchange,
            sink: None,
            attempts,
            deadline: Duration::from_millis(config.resolver.timeout_ms).saturating_mul(attempts),
            querylog_task: None,
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

    /// The query-log writer task started by [`EngineBuilder::from_config`]; it finishes once the
    /// engine (holding the writer) is dropped and the remaining events are flushed.
    pub fn take_querylog_task(&mut self) -> Option<JoinHandle<()>> {
        self.querylog_task.take()
    }

    #[must_use]
    pub fn build(self) -> Engine<E> {
        Engine {
            acl: ArcSwap::from_pointee(self.acl),
            rate: ArcSwap::from_pointee(RateLimiter::new(self.rate_qps, RATE_LIMIT_KEYS)),
            filter: self.filter,
            response_ip: ArcSwap::from_pointee(self.response_ip),
            groups: ArcSwapOption::from(self.groups.map(Arc::new)),
            zones: self.zones,
            cache: self.cache,
            exchange: self.exchange,
            sink: self.sink,
            block_mode: self.block_mode,
            attempts: self.attempts,
            deadline: self.deadline,
        }
    }
}
