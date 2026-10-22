//! [`Services`]: the store-backed services the engine, the API and the binary share.
//!
//! [`Services::open`] builds each of them once; [`crate::EngineBuilder`] and the API state take
//! handles from it, so the engine no longer hands out its internals.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use dnsy_config::Config;
use dnsy_core::SystemClock;
use dnsy_dnssec::RolloverTimings;
use dnsy_filter::{FETCH_TIMEOUT, Fetcher, FilterLimits, ListManager, MAX_LIST_BYTES, SourceStore};
use dnsy_observe::{QueryEventSink, QueryLogWriter, WriterConfig};
use dnsy_proto::Name;
use dnsy_resolver::Cache;
use dnsy_resolver::groups::{GroupSet, GroupStore, ThreadRng};
use dnsy_store::Store;
use dnsy_zone::{
    KeyStore, ZoneError, ZoneSigning, ZoneStore, ZoneWatcher, passphrase_from_environment,
};
use tokio::task::JoinHandle;

use crate::builder::{EngineError, cache_options};

/// How often due zones are re-signed and key states advanced.
pub const SIGN_INTERVAL: Duration = Duration::from_secs(60);

/// The live upstream groups, shared by the engine (which forwards through them) and the API
/// (which swaps them and reports their health).
pub type GroupsHandle = Arc<ArcSwapOption<GroupSet>>;

/// The services built once per process.
pub struct Services {
    /// The resolver cache.
    pub cache: Arc<Cache>,
    /// The live upstream groups.
    pub groups: GroupsHandle,
    /// The local zones, when wired.
    pub zones: Option<Arc<ZoneStore>>,
    /// The signer of zones with `dnssec.enabled`, when wired.
    pub signing: Option<ZoneSigning>,
    /// The blocklist manager, when the filter comes from persisted list sources.
    pub lists: Option<ListManager>,
    pub(crate) sink: Option<Arc<dyn QueryEventSink>>,
    querylog_task: Option<JoinHandle<()>>,
}

/// Background tasks started by [`Services::spawn_background`]; the zone watcher stops on drop.
pub struct Background {
    /// Blocklist refresh, zone re-signing and key rollover.
    pub tasks: Vec<JoinHandle<()>>,
    _watcher: Option<ZoneWatcher>,
}

impl Services {
    /// A cache from `[cache]` and empty groups; no zones, lists, signing or query log. The
    /// public fields can be replaced afterwards (tests do).
    #[must_use]
    pub fn bare(config: &Config) -> Self {
        Self {
            cache: Arc::new(Cache::new(cache_options(&config.cache))),
            groups: Arc::new(ArcSwapOption::empty()),
            zones: None,
            signing: None,
            lists: None,
            sink: None,
            querylog_task: None,
        }
    }

    /// Builds every store-backed service:
    /// - blocklists from the persisted list sources (seeded from `[filter] blocklists` on first
    ///   start), loaded once;
    /// - local zones from `[zones] dir`, signed where `dnssec.enabled`, with keys from the
    ///   store (passphrase from `DNSY_DNSSEC_PASSPHRASE` or `[dnssec] key_passphrase_file`);
    /// - upstream groups from the store, seeded from `[resolver] upstreams` on first start;
    /// - the batched query-log writer when `[querylog] enabled`.
    ///
    /// Must run inside a Tokio runtime.
    ///
    /// # Errors
    /// Unreadable zones directory, store failures, invalid stored groups or key setup.
    pub async fn open(config: &Config, store: &Store) -> Result<Self, EngineError> {
        let mut services = Self::bare(config);

        let sources = SourceStore::new(store.clone());
        sources
            .seed(&config.filter.blocklists, config.filter.refresh_interval)
            .await?;
        let lists = ListManager::new(
            sources,
            config.filter.block_mode,
            FilterLimits::default(),
            Fetcher::new(MAX_LIST_BYTES, FETCH_TIMEOUT),
            Arc::new(SystemClock),
        );
        lists.reload().await?;
        services.lists = Some(lists);

        let zones = ZoneStore::open(&config.zones.dir)?;
        let passphrase = passphrase_from_environment(
            dnsy_config::PASSPHRASE_ENV,
            config.dnssec.key_passphrase_file.as_deref(),
        )?;
        let keys = KeyStore::open(store.clone(), passphrase, Arc::new(SystemClock));
        let signing = ZoneSigning::new(Arc::clone(&zones), keys);
        signing.sign_due().await;
        services.zones = Some(zones);
        services.signing = Some(signing);

        let groups = GroupStore::new(store.clone());
        groups.seed_default(&config.resolver.upstreams).await?;
        let specs = groups.list().await?;
        if !specs.is_empty() {
            let set = GroupSet::new(specs, Arc::new(SystemClock), Arc::new(ThreadRng))?;
            services.groups.store(Some(Arc::new(set)));
        }

        if config.querylog.enabled {
            let (writer, task) = QueryLogWriter::spawn(
                store.clone(),
                WriterConfig {
                    redact_client_ip: config.querylog.redact_client_ip,
                    sample: config.querylog.sample,
                    max_size_mb: config.querylog.max_size_mb,
                    ..WriterConfig::default()
                },
            );
            services.sink = Some(Arc::new(writer));
            services.querylog_task = Some(task);
        }
        Ok(services)
    }

    /// The query-log writer task started by [`Services::open`]; it finishes once every holder of
    /// the writer is dropped and the remaining events are flushed.
    pub fn take_querylog_task(&mut self) -> Option<JoinHandle<()>> {
        self.querylog_task.take()
    }

    /// Starts the zone watcher, the blocklist refresh loop, the zone re-signing task and the key
    /// rollover timer.
    ///
    /// # Errors
    /// The zones directory cannot be watched.
    pub fn spawn_background(&self) -> Result<Background, ZoneError> {
        let mut tasks = Vec::new();
        if let Some(lists) = self.lists.clone() {
            tasks.push(tokio::spawn(lists.run()));
        }
        let watcher = self.zones.as_ref().map(ZoneStore::watch).transpose()?;
        if let (Some(signing), Some(zones)) = (&self.signing, &self.zones) {
            tasks.push(signing.clone().spawn(SIGN_INTERVAL));
            let zones = Arc::clone(zones);
            tasks.push(
                signing
                    .keys()
                    .clone()
                    .spawn_timer(SIGN_INTERVAL, move |zone| rollover_timings(&zones, zone)),
            );
        }
        Ok(Background {
            tasks,
            _watcher: watcher,
        })
    }

    /// Re-reads what lives on disk or in the database: zones, blocklists, due signatures. A
    /// failure keeps the previous state and is logged.
    pub async fn reload(&self) {
        if let Some(zones) = &self.zones {
            match zones.reload() {
                Ok(()) => tracing::info!("zones reloaded"),
                Err(e) => tracing::error!(error = %e, "zone reload failed; keeping previous zones"),
            }
        }
        if let Some(lists) = &self.lists
            && let Err(e) = lists.reload().await
        {
            tracing::warn!(error = %e, "blocklist reload failed; keeping previous");
        }
        if let Some(signing) = &self.signing {
            signing.sign_due().await;
        }
    }
}

/// Rollover timings of `zone` from its signing policy; `None` skips zones that no longer exist.
fn rollover_timings(zones: &ZoneStore, zone: &str) -> Option<RolloverTimings> {
    let name = Name::from_ascii(zone).ok()?.to_lowercase();
    let snapshot = zones.snapshot();
    let policy = snapshot.get(&name)?.dnssec.as_ref()?;
    Some(policy.rollover_timings())
}
