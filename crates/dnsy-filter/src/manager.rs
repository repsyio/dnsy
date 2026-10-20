//! Keeps the active [`FilterSet`] in sync with the persisted list sources.
//!
//! Each refresh fetches one source, builds a complete new filter from every loaded list on a
//! blocking thread, and only then swaps it in. A failed fetch, a malformed list or a build error
//! leaves the previous filter (and the previous copy of that list) untouched, so queries never
//! see a half-built or emptier filter.

use std::collections::HashMap;
use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::Mutex;

use crate::BlockMode;
use crate::fetch::{FetchError, Fetched, Fetcher, Validators};
use crate::matcher::{BlocklistError, FilterLimits, FilterSet, FilterSetBuilder};
use crate::parse::{ListFormat, ParseStats};
use crate::rules::{FilterError, unix_now};
use crate::sources::{FetchRecord, ListSource, LoadedMeta, RuleKind, SourceStore};

/// Retry delay cap after a failed refresh, seconds.
const MAX_RETRY_SECS: u64 = 300;
/// Longest the scheduler sleeps, so added or enabled sources are noticed.
const MAX_IDLE: Duration = Duration::from_secs(60);

/// Time source for the scheduler.
pub trait Clock: Send + Sync + 'static {
    /// Unix seconds.
    fn now(&self) -> i64;
    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        unix_now()
    }

    fn sleep(&self, d: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(d))
    }
}

/// What a successful refresh did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// A new copy was loaded and the filter swapped; `entries` is block plus allow entries.
    Updated { entries: u64 },
    /// The server confirmed the held copy is current.
    NotModified,
}

/// Why a refresh failed. The previous filter stays active.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("source not found")]
    NotFound,
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(transparent)]
    Build(#[from] BlocklistError),
    #[error("list contains no usable entries")]
    Malformed,
    #[error(transparent)]
    Store(#[from] FilterError),
    #[error("build task failed")]
    Task,
}

struct Loaded {
    body: Arc<Vec<u8>>,
    validators: Validators,
}

#[derive(Default)]
struct State {
    loaded: HashMap<i64, Loaded>,
    next_due: HashMap<i64, i64>,
}

type BuildInput = (i64, String, ListFormat, Arc<Vec<u8>>);

struct Inner {
    store: SourceStore,
    filter: ArcSwap<FilterSet>,
    mode: ArcSwap<BlockMode>,
    limits: FilterLimits,
    fetcher: Fetcher,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}

/// Owns the active filter and refreshes it from the persisted sources. Cheap to clone.
#[derive(Clone)]
pub struct ListManager {
    inner: Arc<Inner>,
}

impl ListManager {
    /// A manager whose filter is empty until the first refresh or [`ListManager::reload`].
    #[must_use]
    pub fn new(
        store: SourceStore,
        mode: BlockMode,
        limits: FilterLimits,
        fetcher: Fetcher,
        clock: Arc<dyn Clock>,
    ) -> ListManager {
        let empty = FilterSetBuilder::new(mode, limits).build();
        ListManager {
            inner: Arc::new(Inner {
                store,
                filter: ArcSwap::from_pointee(empty),
                mode: ArcSwap::from_pointee(mode),
                limits,
                fetcher,
                clock,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// The active filter. Lock-free; hold the `Arc` only for one query.
    #[must_use]
    pub fn current(&self) -> Arc<FilterSet> {
        self.inner.filter.load_full()
    }

    /// Changes how blocked names are answered. Call [`ListManager::reload`] afterwards to
    /// rebuild the active filter with the new mode.
    pub fn set_block_mode(&self, mode: BlockMode) {
        self.inner.mode.store(Arc::new(mode));
    }

    /// Rebuilds from the lists already loaded plus the custom rules (after enabling, disabling
    /// or deleting a source, or changing rules). Does not fetch.
    ///
    /// # Errors
    /// Store or build failure; the previous filter stays active.
    pub async fn reload(&self) -> Result<(), RefreshError> {
        let sources = self.inner.store.list().await?;
        let mut state = self.inner.state.lock().await;
        Self::prune(&mut state, &sources);
        let lists = Self::inputs(&state, &sources, None);
        let (set, _) = self.build(lists).await?;
        self.inner.filter.store(Arc::new(set));
        Ok(())
    }

    /// Refreshes one source now, regardless of its schedule.
    ///
    /// # Errors
    /// See [`RefreshError`]; the previous filter stays active.
    pub async fn refresh_source(&self, id: i64) -> Result<RefreshOutcome, RefreshError> {
        let sources = self.inner.store.list().await?;
        let src = sources
            .iter()
            .find(|s| s.id == id)
            .ok_or(RefreshError::NotFound)?;
        let mut state = self.inner.state.lock().await;
        self.refresh_locked(&mut state, &sources, src).await
    }

    /// Refreshes every enabled source that is due and returns how long to sleep before the next
    /// one is.
    pub async fn tick(&self) -> Duration {
        let Ok(sources) = self.inner.store.list().await else {
            tracing::warn!("listing blocklist sources failed");
            return MAX_IDLE;
        };
        let mut state = self.inner.state.lock().await;
        let pruned = Self::prune(&mut state, &sources);
        if pruned {
            match self.build(Self::inputs(&state, &sources, None)).await {
                Ok((set, _)) => self.inner.filter.store(Arc::new(set)),
                Err(e) => {
                    tracing::warn!(error = %e, "rebuilding filter after source removal failed");
                }
            }
        }
        let now = self.inner.clock.now();
        for src in sources.iter().filter(|s| s.enabled) {
            if state.next_due.get(&src.id).is_none_or(|d| *d <= now) {
                match self.refresh_locked(&mut state, &sources, src).await {
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(list = %src.name, error = %e, "blocklist refresh failed");
                    }
                }
            }
        }
        let now = self.inner.clock.now();
        let next = sources
            .iter()
            .filter(|s| s.enabled)
            .filter_map(|s| state.next_due.get(&s.id))
            .min();
        next.map_or(MAX_IDLE, |d| {
            Duration::from_secs(
                u64::try_from(d - now)
                    .unwrap_or(0)
                    .clamp(1, MAX_IDLE.as_secs()),
            )
        })
    }

    /// Runs the schedule forever; spawn it on the runtime.
    pub async fn run(self) {
        loop {
            let wait = self.tick().await;
            self.inner.clock.sleep(wait).await;
        }
    }

    /// Drops state of deleted or disabled sources. Returns true if a loaded list was dropped.
    fn prune(state: &mut State, sources: &[ListSource]) -> bool {
        let live = |id: &i64| sources.iter().any(|s| s.id == *id && s.enabled);
        let before = state.loaded.len();
        state.loaded.retain(|id, _| live(id));
        state.next_due.retain(|id, _| live(id));
        state.loaded.len() != before
    }

    fn inputs(
        state: &State,
        sources: &[ListSource],
        replace: Option<(i64, &Arc<Vec<u8>>)>,
    ) -> Vec<BuildInput> {
        sources
            .iter()
            .filter(|s| s.enabled)
            .filter_map(|s| {
                let body = match replace {
                    Some((id, body)) if id == s.id => Arc::clone(body),
                    _ => Arc::clone(&state.loaded.get(&s.id)?.body),
                };
                Some((s.id, s.name.clone(), s.format, body))
            })
            .collect()
    }

    async fn build(
        &self,
        lists: Vec<BuildInput>,
    ) -> Result<(FilterSet, HashMap<i64, ParseStats>), RefreshError> {
        let rules = self.inner.store.custom_rules().await?;
        let (mode, limits) = (**self.inner.mode.load(), self.inner.limits);
        tokio::task::spawn_blocking(move || {
            let mut builder = FilterSetBuilder::new(mode, limits);
            let mut stats = HashMap::new();
            for (id, name, format, body) in lists {
                let s = builder.add_list(&name, format, Cursor::new(body.as_slice()))?;
                stats.insert(id, s);
            }
            for (kind, domain) in rules {
                let added = match kind {
                    RuleKind::Block => builder.add_block_rule(&domain),
                    RuleKind::Allow => builder.add_allow_rule(&domain),
                };
                match added {
                    Err(BlocklistError::InvalidDomain(d)) => {
                        tracing::warn!(domain = %d, "ignoring invalid custom rule");
                    }
                    other => other?,
                }
            }
            Ok((builder.build(), stats))
        })
        .await
        .map_err(|_| RefreshError::Task)?
    }

    async fn refresh_locked(
        &self,
        state: &mut State,
        sources: &[ListSource],
        src: &ListSource,
    ) -> Result<RefreshOutcome, RefreshError> {
        let result = self.try_refresh(state, sources, src).await;
        let now = self.inner.clock.now();
        let (status, loaded) = match &result {
            Ok(RefreshOutcome::Updated { entries }) => {
                let v = state.loaded.get(&src.id).map(|l| l.validators.clone());
                let v = v.unwrap_or_default();
                (
                    "ok".to_owned(),
                    Some(LoadedMeta {
                        etag: v.etag,
                        last_modified: v.last_modified,
                        entries: *entries,
                    }),
                )
            }
            Ok(RefreshOutcome::NotModified) => ("not modified".to_owned(), None),
            Err(e) => (format!("error: {e}"), None),
        };
        let retry = if result.is_ok() {
            src.interval_secs
        } else {
            src.interval_secs.min(MAX_RETRY_SECS)
        };
        state
            .next_due
            .insert(src.id, now.saturating_add(schedule_delay(retry)));
        self.inner
            .store
            .record(
                src.id,
                FetchRecord {
                    at: now,
                    status,
                    loaded,
                },
            )
            .await?;
        result
    }

    async fn try_refresh(
        &self,
        state: &mut State,
        sources: &[ListSource],
        src: &ListSource,
    ) -> Result<RefreshOutcome, RefreshError> {
        let prior = state.loaded.get(&src.id).map(|l| l.validators.clone());
        let fetched = self
            .inner
            .fetcher
            .fetch(&src.location, src.allow_private, prior.as_ref())
            .await?;
        let (bytes, validators) = match fetched {
            Fetched::NotModified => return Ok(RefreshOutcome::NotModified),
            Fetched::Body { bytes, validators } => (bytes, validators),
        };
        let body = Arc::new(bytes);
        let lists = Self::inputs(state, sources, Some((src.id, &body)));
        let (next, parsed) = self.build(lists).await?;
        let mine = parsed.get(&src.id).copied().unwrap_or_default();
        if mine.blocks + mine.allows == 0 && mine.invalid > 0 {
            return Err(RefreshError::Malformed);
        }
        self.inner.filter.store(Arc::new(next));
        state.loaded.insert(src.id, Loaded { body, validators });
        Ok(RefreshOutcome::Updated {
            entries: (mine.blocks + mine.allows) as u64,
        })
    }
}

/// `interval` plus up to 10% random jitter, so many sources do not refresh in lockstep.
fn schedule_delay(interval_secs: u64) -> i64 {
    let jitter = rand::random_range(0..=interval_secs / 10);
    i64::try_from(interval_secs.saturating_add(jitter)).unwrap_or(i64::MAX)
}
