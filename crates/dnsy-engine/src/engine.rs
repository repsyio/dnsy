//! The request pipeline (spec 5.2).
//!
//! ACL -> rate limit (both before any other reply, error replies included) -> FORMERR / NOTIMP /
//! BADVERS -> AXFR/IXFR refused -> blocklist/allowlist -> local zones (authoritative, never
//! cached; ANY gets the RFC 8482 minimal answer) -> ANY refused -> RD check -> cache (keyed by
//! the query's DO/CD bits) -> upstream groups (identical concurrent misses share one exchange,
//! bounded by the overall deadline) -> DNSSEC validation (per mode; the status is stored with
//! the cache entry) -> response-IP policy -> AD / EDE / DNSSEC-record shaping -> one
//! `QueryEvent`.
//!
//! Validation (modes `permissive` and `strict`, client CD=0): the query goes upstream with DO=1
//! and CD=1, the raw answer is validated (DS/DNSKEY fetched through the cache by
//! [`UpstreamFetcher`]), then scrubbed for the client (DNSSEC records only for DO=1), its TTLs
//! capped by the signatures' remaining validity and cached with its status. AD is set only for
//! `Secure` answers to clients that sent DO or AD (RFC 6840 5.7). `Bogus` answers become SERVFAIL
//! with the validator's EDE in strict mode and are served without AD (EDE attached) in
//! permissive mode. A client CD=1 skips validation: the upstream answer is returned as-is from
//! its own (CD) cache entry.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::acl::Acl;
use crate::ratelimit::{RateLimiter, RateVerdict};
use arc_swap::ArcSwap;
use dnsy_core::{Clock, DnssecStatus, Principal, Transport, Validation};
#[cfg(feature = "fetch")]
use dnsy_filter::ListManager;
use dnsy_filter::{AclAction, BlockMode, FilterSet, Verdict, block_response};
use dnsy_observe::{AnswerSource, QueryEvent, QueryEventSink};
use dnsy_proto::{EDNS_VERSION, Edns, Message, Name, Opcode, Question, Rcode, RecordType, ede};
use dnsy_resolver::forward::{DnssecPolicy, UpstreamFetcher, cap_ttls, dnssec_query};
use dnsy_resolver::groups::{Exchange, GroupError, GroupSet};
use dnsy_resolver::{
    Cache, CacheKey, CacheLookup, Joined, RefreshGuard, Refreshes, Upstream, UpstreamClient,
    UpstreamError,
};
use dnsy_zone::ZoneStore;

use crate::services::GroupsHandle;
use tokio::sync::{Semaphore, mpsc};

use crate::handler::{Admission, Handler, RequestContext};
use crate::response::{
    RESPONSE_IP_LIST, ResponseIpPolicy, answers_question, authoritative, bogus_servfail, dnssec_ok,
    error_response, finish, scrub,
};

/// Logged when the system clock is earlier than the build time.
pub(crate) const CLOCK_UNTRUSTED_WARNING: &str = "system clock is earlier than the build time: \
    DNSSEC validation is suspended and answers are served as indeterminate, without AD, until \
    the clock is set";

/// Clients tracked by the rate limiter.
pub(crate) const RATE_LIMIT_KEYS: usize = 100_000;
/// Prefetches waiting for a worker; further ones are dropped, the entry then just expires.
pub(crate) const PREFETCH_QUEUE: usize = 64;

/// Requests that may wait for one cache miss already being forwarded; further identical
/// misses are answered SERVFAIL (EDE 22) at once instead of holding a listener slot.
pub const MAX_MISS_WAITERS: usize = 256;

/// QTYPE AXFR (RFC 5936) and IXFR (RFC 1995): zone transfers are never served or forwarded.
const AXFR: u16 = 252;
const IXFR: u16 = 251;

/// What a forwarded (and validated) query resolved to: the message to serve, the upstream that
/// answered and the validation status. Shared with every request coalesced onto it.
pub(crate) type Resolved = Result<(Message, SocketAddr, DnssecStatus), UpstreamFailure>;

/// A queued job older than this is dropped unrun: the entry it meant to renew is long gone.
const PREFETCH_MAX_WAIT: Duration = Duration::from_secs(30);

/// One background refresh of a popular entry. It holds no refresh slot while it waits: the
/// worker claims the key's slot only when it starts, so a queued job never blocks a client.
pub(crate) struct PrefetchJob {
    key: CacheKey,
    queued_at: Instant,
}

/// Marks the prefetch workers as running for as long as it lives.
struct WorkersRunning<'a>(&'a AtomicUsize);

impl<'a> WorkersRunning<'a> {
    fn new(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count)
    }
}

impl Drop for WorkersRunning<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The request pipeline. Built by [`crate::EngineBuilder`]; policy snapshots (ACL,
/// response-IP policy, upstream groups, rate limit) can be swapped while serving.
pub struct Engine<E = UpstreamClient> {
    pub(crate) acl: ArcSwap<Acl>,
    pub(crate) rate: ArcSwap<RateLimiter>,
    pub(crate) filter: Filters,
    pub(crate) response_ip: ArcSwap<ResponseIpPolicy>,
    pub(crate) groups: GroupsHandle,
    pub(crate) zones: Option<Arc<ZoneStore>>,
    pub(crate) cache: Arc<Cache>,
    pub(crate) exchange: E,
    pub(crate) sink: Option<Arc<dyn QueryEventSink>>,
    pub(crate) block_mode: ArcSwap<BlockMode>,
    pub(crate) attempts: u32,
    pub(crate) deadline: Duration,
    pub(crate) dnssec: ArcSwap<DnssecPolicy>,
    /// Bounds the validation fetches in flight across all clients.
    pub(crate) fetch_permits: Semaphore,
    /// Set while the system clock is before the policy's floor (shown by `/readyz`).
    pub(crate) clock_untrusted: Arc<AtomicBool>,
    pub(crate) clock: Arc<dyn Clock>,
    /// How long a client waits for a refresh before it is answered from a stale entry.
    pub(crate) stale_wait: Duration,
    /// Upstream work in flight, per key (cache misses, serve-stale and prefetch share it).
    pub(crate) refreshes: Arc<Refreshes<Resolved>>,
    /// Running [`Engine::run_prefetch`] calls; with none, nothing is queued.
    pub(crate) prefetch_workers: AtomicUsize,
    pub(crate) prefetch_tx: mpsc::Sender<PrefetchJob>,
    pub(crate) prefetch_rx: tokio::sync::Mutex<mpsc::Receiver<PrefetchJob>>,
}

/// Where the active blocklist filter comes from.
pub(crate) enum Filters {
    Fixed(Arc<FilterSet>),
    /// Persisted list sources; the manager swaps in rebuilt filters.
    #[cfg(feature = "fetch")]
    Lists(ListManager),
}

impl Filters {
    fn current(&self) -> Arc<FilterSet> {
        match self {
            Self::Fixed(set) => Arc::clone(set),
            #[cfg(feature = "fetch")]
            Self::Lists(manager) => manager.current(),
        }
    }
}

/// What admission decided: an ACL-style action, or a truncated slip reply.
enum Gate {
    Act(AclAction),
    Slip,
}

/// What the pipeline decided, before the event is emitted.
struct Outcome {
    /// `None`: send nothing.
    response: Option<Message>,
    source: AnswerSource,
    dnssec: DnssecStatus,
}

impl Outcome {
    fn new(response: Message, source: AnswerSource) -> Self {
        Self {
            response: Some(response),
            source,
            dnssec: DnssecStatus::Unchecked,
        }
    }
}

/// An upstream failure, as the EDE we report for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamFailure {
    /// EDE 22: nothing answered in time or no upstream is available.
    Unreachable,
    /// EDE 23: upstreams answered with errors, garbage or a mismatching response.
    Network,
}

impl UpstreamFailure {
    fn ede(self) -> (u16, &'static str) {
        match self {
            Self::Unreachable => (ede::NO_REACHABLE_AUTHORITY, "no reachable upstream"),
            Self::Network => (ede::NETWORK_ERROR, "upstream network error"),
        }
    }

    fn from_group(e: &GroupError) -> Self {
        match e {
            GroupError::AllFailed(UpstreamError::Timeout)
            | GroupError::NoAvailableUpstream(_)
            | GroupError::Invalid(_)
            | GroupError::NoQuestion => Self::Unreachable,
            GroupError::AllFailed(_) => Self::Network,
        }
    }
}

/// Wraps an [`Exchange`] to remember which upstream answered.
struct Recording<'a, E> {
    inner: &'a E,
    answered: Mutex<Option<Upstream>>,
}

impl<E: Exchange> Exchange for Recording<'_, E> {
    async fn exchange(
        &self,
        upstream: &Upstream,
        query: &Message,
    ) -> Result<Message, UpstreamError> {
        let result = self.inner.exchange(upstream, query).await;
        if result.is_ok() {
            *self.answered.lock().unwrap_or_else(PoisonError::into_inner) = Some(upstream.clone());
        }
        result
    }
}

/// The socket address reported for an upstream; a hostname upstream reports the unspecified
/// address with its port.
fn upstream_addr(u: &Upstream) -> SocketAddr {
    let ip = u
        .host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    SocketAddr::new(ip, u.port)
}

fn principal_label(p: &Principal) -> String {
    match p {
        Principal::Token { token, .. } => format!("token:{}", token.0),
        Principal::ClientCert { subject, .. } => format!("cert:{subject}"),
    }
}

impl<E: Exchange> Engine<E> {
    #[cfg(test)]
    pub(crate) fn cache(&self) -> &Arc<Cache> {
        &self.cache
    }

    /// The current ACL snapshot.
    #[must_use]
    pub fn acl(&self) -> Arc<Acl> {
        self.acl.load_full()
    }

    pub fn set_acl(&self, acl: Acl) {
        self.acl.store(Arc::new(acl));
    }

    /// Replaces the rate limiter (`qps == 0` disables limiting, the slip interval is kept); client
    /// buckets start fresh.
    pub fn set_rate_limit(&self, qps: u32) {
        let slip = self.rate.load().slip();
        self.rate.store(Arc::new(
            RateLimiter::new(qps, RATE_LIMIT_KEYS).with_slip(slip),
        ));
    }

    /// Changes how blocked names are answered. With persisted list sources, also call
    /// [`ListManager::set_block_mode`] and reload it (the filter bakes the mode in).
    pub fn set_block_mode(&self, mode: BlockMode) {
        self.block_mode.store(Arc::new(mode));
    }

    pub fn set_response_ip_policy(&self, policy: ResponseIpPolicy) {
        self.response_ip.store(Arc::new(policy));
    }

    /// Replaces the upstream groups; `None` leaves the server without upstreams (SERVFAIL, EDE 22).
    pub fn set_groups(&self, groups: Option<GroupSet>) {
        self.groups.store(groups.map(Arc::new));
    }

    /// The DNSSEC validation mode.
    #[must_use]
    pub fn dnssec_mode(&self) -> Validation {
        self.dnssec.load().mode
    }

    /// The current DNSSEC policy: mode, trust anchors and negative trust anchors.
    #[must_use]
    pub fn dnssec_policy(&self) -> Arc<DnssecPolicy> {
        self.dnssec.load_full()
    }

    /// Switches the validation mode; a change flushes the cache, whose entries carry statuses
    /// computed under the old mode.
    pub fn set_dnssec_mode(&self, mode: Validation) {
        let current = self.dnssec.load_full();
        if current.mode == mode {
            return;
        }
        self.dnssec.store(Arc::new(DnssecPolicy {
            mode,
            ..(*current).clone()
        }));
        self.cache.flush_all();
    }

    /// Replaces the negative trust anchors (RFC 7646) and flushes the cache.
    pub fn set_negative_trust_anchors(&self, names: Vec<Name>) {
        let current = self.dnssec.load_full();
        self.dnssec
            .store(Arc::new(current.with_negative_trust_anchors(names)));
        self.cache.flush_all();
    }

    /// Replaces the negative trust anchors with `entries`: names with an optional expiry (Unix
    /// seconds, after which the anchor no longer applies). Flushes the cache.
    pub fn set_negative_trust_anchor_entries(&self, entries: Vec<(Name, Option<u32>)>) {
        let current = self.dnssec.load_full();
        self.dnssec
            .store(Arc::new(current.with_negative_entries(entries)));
        self.cache.flush_all();
    }

    /// Re-reads the trust anchors (`[dnssec] trust_anchors` and `trust_anchor_file`) and swaps
    /// them in, keeping the current mode, negative trust anchors and clock floor; flushes the
    /// cache. On error the previous anchors stay in effect.
    ///
    /// # Errors
    /// A malformed anchor or an unreadable anchor file.
    pub fn reload_trust_anchors(
        &self,
        cfg: &dnsy_resolver::forward::DnssecOptions,
    ) -> Result<(), dnsy_resolver::forward::DnssecConfigError> {
        let fresh = DnssecPolicy::from_options(cfg)?;
        let current = self.dnssec.load_full();
        let policy = DnssecPolicy {
            mode: current.mode,
            validator: fresh.validator,
            not_before_unix: current.not_before_unix,
        }
        .with_negative_entries(current.validator.anchors().negative_entries().to_vec());
        self.dnssec.store(Arc::new(policy));
        self.cache.flush_all();
        Ok(())
    }

    /// True while the system clock is earlier than the build time: answers are served as
    /// `Indeterminate`, without AD.
    #[must_use]
    pub fn dnssec_clock_untrusted(&self) -> bool {
        self.clock_untrusted.load(Ordering::Relaxed)
    }

    /// The shared flag behind [`Engine::dnssec_clock_untrusted`], for the readiness probe.
    #[must_use]
    pub fn dnssec_clock_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.clock_untrusted)
    }

    /// Runs the pipeline. `None` means the request is dropped without a reply (ACL `drop`, or
    /// rate-limited over UDP); transports that can drop use this instead of [`Handler::handle`].
    /// Emits exactly one `QueryEvent` either way.
    pub async fn process(&self, ctx: &RequestContext, query: &Message) -> Option<Message> {
        let outcome = self.pipeline(ctx, query).await;
        self.emit(ctx, query, &outcome);
        outcome.response
    }

    async fn pipeline(&self, ctx: &RequestContext, query: &Message) -> Outcome {
        let refused = || {
            Outcome::new(
                finish(query, error_response(query, Rcode::Refused, None)),
                AnswerSource::Refused,
            )
        };
        // Admission first: a client set to `drop` gets nothing, not even an error reply, and
        // every reply (error replies too) consumes rate-limit tokens.
        match self.admission(ctx.client.ip(), ctx.principal.as_ref(), ctx.transport) {
            Gate::Act(AclAction::Allow) => {}
            Gate::Act(AclAction::Refuse) => return refused(),
            Gate::Slip => {
                // A minimal truncated reply: a real client behind a spoofed address retries
                // over TCP, while the reply stays no larger than the query.
                let mut response = Message::response_to(query);
                response.header.tc = true;
                response.edns = None;
                return Outcome::new(response, AnswerSource::Refused);
            }
            Gate::Act(AclAction::Drop) => {
                return Outcome {
                    response: None,
                    source: AnswerSource::Refused,
                    dnssec: DnssecStatus::Unchecked,
                };
            }
        }

        let Some(question) = query.questions.first() else {
            return Outcome::new(
                error_response(query, Rcode::FormErr, None),
                AnswerSource::Error,
            );
        };
        if query.header.opcode != Opcode::Query {
            return Outcome::new(
                error_response(query, Rcode::NotImp, None),
                AnswerSource::Error,
            );
        }
        if query
            .edns
            .as_ref()
            .is_some_and(|e| e.version != EDNS_VERSION)
        {
            return Outcome::new(Message::badvers_for(query), AnswerSource::Error);
        }
        // Zone transfers are refused outright, for local zones and forwarded names alike.
        if matches!(u16::from(question.qtype), AXFR | IXFR) {
            return refused();
        }

        // Lowercased once: the filter and the cache key both want the canonical form.
        let qname = question.name.to_lowercase();
        if let Verdict::Block { list, mode } = self.filter.current().check_lowercase(&qname)
            && let Some(blocked) = block_response(query, mode, &list)
        {
            return Outcome::new(finish(query, blocked), AnswerSource::Blocked { list });
        }

        let do_bit = dnssec_ok(query);
        if let Some(zones) = &self.zones {
            let snapshot = zones.snapshot();
            // With DO, signed zones answer with RRSIGs and denial proofs. AA only: AD is never
            // set on authoritative data (`response_to` clears it).
            if let Some(result) = snapshot.lookup(question, do_bit) {
                let msg = authoritative(query, question, &snapshot, result, do_bit);
                return Outcome::new(finish(query, msg), AnswerSource::Authoritative);
            }
        }

        // ANY is answered minimally for local zones only (RFC 8482); forwarding it would turn
        // the server into an amplifier for whatever the upstream returns.
        if !query.header.rd || question.qtype == RecordType::Any {
            return refused();
        }

        let key = CacheKey {
            name: qname,
            qtype: question.qtype,
            qclass: question.qclass,
            do_bit,
            cd_bit: query.header.cd,
        };
        let (msg, source, dnssec) = match self.answer(ctx, query, question, key).await {
            Ok(found) => found,
            Err(failure) => {
                let msg = error_response(query, Rcode::ServFail, Some(failure.ede()));
                return Outcome::new(finish(query, msg), AnswerSource::Error);
            }
        };

        if self.response_ip.load().blocks(&msg)
            && let Some(blocked) = block_response(query, **self.block_mode.load(), RESPONSE_IP_LIST)
        {
            return Outcome {
                dnssec,
                ..Outcome::new(
                    finish(query, blocked),
                    AnswerSource::Blocked {
                        list: RESPONSE_IP_LIST.into(),
                    },
                )
            };
        }
        let mut response = finish(query, msg);
        // RFC 6840 5.7: AD only for validated data, and only to clients that asked for it.
        response.header.ad =
            dnssec == DnssecStatus::Secure && !query.header.cd && (do_bit || query.header.ad);
        Outcome {
            dnssec,
            ..Outcome::new(response, source)
        }
    }

    /// The cache entry for `key`, or a forwarded and validated answer (then cached). In strict
    /// mode Bogus data never reaches a validating client: it becomes SERVFAIL with its EDE.
    async fn answer(
        &self,
        ctx: &RequestContext,
        query: &Message,
        question: &Question,
        key: CacheKey,
    ) -> Result<(Message, AnswerSource, DnssecStatus), UpstreamFailure> {
        let policy = self.dnssec.load_full();
        let validating = policy.mode != Validation::Off && !query.header.cd;
        let serve_bogus = policy.mode == Validation::Permissive;
        let (msg, source, dnssec) =
            match self.cache.get_for(&key, self.clock.instant(), serve_bogus) {
                CacheLookup::Fresh { msg, dnssec } => {
                    self.queue_prefetch(&key);
                    (msg, AnswerSource::Cache, dnssec)
                }
                CacheLookup::Stale { msg, dnssec, .. } => {
                    if let Some((fresh, from, status)) = self
                        .refresh_stale(ctx, query, question, &key, &policy, validating)
                        .await
                    {
                        (fresh, AnswerSource::Upstream(from), status)
                    } else {
                        self.cache.note_stale_served();
                        (stale_answer(msg), AnswerSource::CacheStale, dnssec)
                    }
                }
                CacheLookup::Miss => {
                    let (msg, from, dnssec) = self
                        .coalesced_miss(ctx, query, question, &key, &policy, validating)
                        .await?;
                    (msg, AnswerSource::Upstream(from), dnssec)
                }
            };
        if dnssec == DnssecStatus::Bogus
            && validating
            && policy.mode == Validation::Strict
            && msg.header.rcode != Rcode::ServFail
        {
            return Ok((bogus_servfail(query, &msg), source, dnssec));
        }
        Ok((msg, source, dnssec))
    }

    /// Refreshes an expired entry for a waiting client (RFC 8767): one in-flight refresh per
    /// key, the others answer stale at once. `None` means answer from the stale entry: the
    /// refresh is coalesced away, failed, came back SERVFAIL or took longer than `stale_wait`.
    async fn refresh_stale(
        &self,
        ctx: &RequestContext,
        query: &Message,
        question: &Question,
        key: &CacheKey,
        policy: &DnssecPolicy,
        validating: bool,
    ) -> Option<(Message, SocketAddr, DnssecStatus)> {
        let slot = self.refreshes.begin(key)?;
        // Past `stale_wait` the refresh is abandoned: dropping the slot lets a coalesced miss
        // of the same key take over.
        let resolved = tokio::time::timeout(
            self.stale_wait,
            self.resolve(ctx.received_at, query, question, policy, validating),
        )
        .await
        .ok()?;
        let resolved = self.store_refresh(key, resolved);
        slot.finish(|| resolved.clone());
        resolved
            .ok()
            .filter(|(msg, _, _)| msg.header.rcode != Rcode::ServFail)
    }

    /// Caches a refreshed answer unless it is a failure or SERVFAIL (the entry being refreshed
    /// stays), returning it as served.
    fn store_refresh(&self, key: &CacheKey, resolved: Resolved) -> Resolved {
        match resolved {
            Ok((msg, from, dnssec)) if msg.header.rcode != Rcode::ServFail => Ok((
                self.cache.store(key, msg, dnssec, self.clock.instant()),
                from,
                dnssec,
            )),
            other => other,
        }
    }

    /// Resolves a cache miss as a single flight per key: the first request forwards and caches,
    /// identical requests arriving meanwhile wait for its result (success or failure alike; it
    /// is not remembered once the flight ends). A waiter whose leader is cancelled takes over;
    /// none waits longer than its own forwarding and validation deadlines, and at most
    /// [`MAX_MISS_WAITERS`] wait per key.
    async fn coalesced_miss(
        &self,
        ctx: &RequestContext,
        query: &Message,
        question: &Question,
        key: &CacheKey,
        policy: &DnssecPolicy,
        validating: bool,
    ) -> Resolved {
        let give_up = tokio::time::Instant::from_std(ctx.received_at + self.deadline * 2);
        loop {
            match self.refreshes.join(key, MAX_MISS_WAITERS) {
                Joined::Leader(slot) => {
                    let resolved = self
                        .resolve(ctx.received_at, query, question, policy, validating)
                        .await
                        .map(|(msg, from, dnssec)| {
                            let served = self.cache.store(key, msg, dnssec, self.clock.instant());
                            (served, from, dnssec)
                        });
                    slot.finish(|| resolved.clone());
                    return resolved;
                }
                Joined::Waiter(wait) => match tokio::time::timeout_at(give_up, wait.wait()).await {
                    Ok(Some(resolved)) => return resolved,
                    // The leader was cancelled: join again, leading if nobody else does.
                    Ok(None) => {}
                    Err(_) => return Err(UpstreamFailure::Unreachable),
                },
                Joined::Busy => {
                    tracing::debug!(qname = %key.name, "too many requests waiting for this miss");
                    return Err(UpstreamFailure::Unreachable);
                }
            }
        }
    }

    /// Queues a background refresh when the live entry for `key` is popular and close to expiry.
    fn queue_prefetch(&self, key: &CacheKey) {
        if !self.prefetch_running() || !self.cache.prefetch_due(key, self.clock.instant()) {
            return;
        }
        // A full queue drops the job: the entry simply expires. No slot is held meanwhile.
        let _ = self.prefetch_tx.try_send(PrefetchJob {
            key: key.clone(),
            queued_at: Instant::now(),
        });
    }

    /// Whether a [`Engine::run_prefetch`] loop is running (prefetches are queued only then).
    #[must_use]
    pub fn prefetch_running(&self) -> bool {
        self.prefetch_workers.load(Ordering::SeqCst) > 0
    }

    /// Runs the prefetch workers: four refreshes at a time, forever. The
    /// binary spawns this once next to the listeners; dropping the future stops it. Each refresh
    /// takes the normal path (validation included), so a prefetch never stores more than a
    /// client-driven miss would.
    pub async fn run_prefetch(&self) {
        let _running = WorkersRunning::new(&self.prefetch_workers);
        tokio::join!(
            self.prefetch_worker(),
            self.prefetch_worker(),
            self.prefetch_worker(),
            self.prefetch_worker(),
        );
    }

    async fn prefetch_worker(&self) {
        loop {
            let job = self.prefetch_rx.lock().await.recv().await;
            let Some(job) = job else {
                return;
            };
            if job.queued_at.elapsed() > PREFETCH_MAX_WAIT {
                continue;
            }
            // A client-driven refresh of the same key is already in flight: nothing to add.
            let Some(slot) = self.refreshes.begin(&job.key) else {
                continue;
            };
            self.prefetch(&job.key, slot).await;
        }
    }

    async fn prefetch(&self, key: &CacheKey, slot: RefreshGuard<Resolved>) {
        let question = Question {
            name: key.name.clone(),
            qtype: key.qtype,
            qclass: key.qclass,
        };
        let mut query = dnssec_query(&question);
        query.header.cd = key.cd_bit;
        if let Some(edns) = &mut query.edns {
            edns.dnssec_ok = key.do_bit;
        }
        let policy = self.dnssec.load_full();
        let validating = policy.mode != Validation::Off && !key.cd_bit;
        self.cache.note_prefetch();
        let resolved = self
            .resolve(Instant::now(), &query, &question, &policy, validating)
            .await;
        match &resolved {
            Ok((msg, _, _)) if msg.header.rcode == Rcode::ServFail => {
                tracing::debug!(qname = %key.name, "prefetch answered SERVFAIL; kept the entry");
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(qname = %key.name, failure = ?e, "prefetch failed"),
        }
        let resolved = self.store_refresh(key, resolved);
        slot.finish(|| resolved.clone());
    }

    /// Forwards, validates (when `validating`) and scrubs one cache miss. Returns the message to
    /// cache and serve, the upstream that answered and the validation status.
    async fn resolve(
        &self,
        received_at: Instant,
        query: &Message,
        question: &Question,
        policy: &DnssecPolicy,
        validating: bool,
    ) -> Result<(Message, SocketAddr, DnssecStatus), UpstreamFailure> {
        let Some(groups) = self.groups.load_full() else {
            return Err(UpstreamFailure::Unreachable);
        };
        let do_bit = dnssec_ok(query);
        let (raw, from) = self
            .forward(received_at, &groups, query, question, do_bit, validating)
            .await?;
        if !answers_question(question, &raw) {
            return Err(UpstreamFailure::Network);
        }
        let outcome = if validating {
            Some(self.validate(&groups, policy, question, &raw).await)
        } else {
            None
        };
        let mut msg = scrub(question, raw, do_bit).ok_or(UpstreamFailure::Network)?;
        let Some(outcome) = outcome else {
            return Ok((msg, from, DnssecStatus::Unchecked));
        };
        if outcome.fetch_failed && policy.mode == Validation::Strict {
            // The chain could not be fetched: strict mode never hands on data it could not
            // validate. SERVFAIL with EDE 5, cached for `servfail_ttl` so a blip is retried soon.
            let (code, text) = outcome
                .ede
                .unwrap_or((ede::DNSSEC_INDETERMINATE, String::new()));
            let servfail = error_response(query, Rcode::ServFail, Some((code, &text)));
            return Ok((servfail, from, outcome.status));
        }
        if let Some(cap) = outcome.min_ttl {
            cap_ttls(&mut msg, cap);
        }
        if outcome.status == DnssecStatus::Bogus {
            let (code, text) = outcome.ede.unwrap_or((ede::DNSSEC_BOGUS, String::new()));
            if policy.mode == Validation::Permissive {
                tracing::warn!(
                    qname = %question.name, qtype = ?question.qtype, ede = code, reason = %text,
                    "DNSSEC bogus answer served without AD (permissive mode)"
                );
            } else {
                tracing::info!(
                    qname = %question.name, qtype = ?question.qtype, ede = code, reason = %text,
                    "DNSSEC bogus answer refused"
                );
            }
            // Stored with the entry, so cached replies carry the same EDE.
            msg.edns = None;
            msg.set_ede(code, &text);
        }
        Ok((msg, from, outcome.status))
    }

    /// Validates `raw`, fetching DS/DNSKEY through the cache. Fetches share a fresh deadline
    /// of the same length as the upstream one, so validation cannot hang a client either.
    async fn validate(
        &self,
        groups: &GroupSet,
        policy: &DnssecPolicy,
        question: &Question,
        raw: &Message,
    ) -> dnsy_dnssec::ValidationOutcome {
        let now = u64::try_from(self.clock.unix_secs()).unwrap_or(0);
        self.note_clock(policy.clock_trusted(now));
        let fetcher = UpstreamFetcher {
            groups,
            exchange: &self.exchange,
            cache: &self.cache,
            permits: &self.fetch_permits,
            deadline: tokio::time::Instant::now() + self.deadline,
        };
        policy.validate(&fetcher, question, raw, now).await
    }

    /// Tracks the clock-sanity state, warning once when the clock becomes untrusted. When it
    /// becomes plausible again the cache (full of `Indeterminate` entries) is flushed.
    fn note_clock(&self, trusted: bool) {
        let was_untrusted = self.clock_untrusted.swap(!trusted, Ordering::Relaxed);
        if !trusted && !was_untrusted {
            tracing::warn!("{CLOCK_UNTRUSTED_WARNING}");
        } else if trusted && was_untrusted {
            tracing::info!("system clock is plausible again: DNSSEC validation resumed");
            self.cache.flush_all();
        }
    }

    /// Forwards a clean copy of the question (no client EDNS options) to the upstream groups,
    /// retrying up to `attempts` times, all within the overall deadline measured from receipt.
    /// With `validating` the query carries DO=1 and CD=1 (we validate ourselves); otherwise the
    /// client's DO and CD bits. Returns the raw (unscrubbed) answer.
    async fn forward(
        &self,
        received_at: Instant,
        groups: &GroupSet,
        query: &Message,
        question: &Question,
        do_bit: bool,
        validating: bool,
    ) -> Result<(Message, SocketAddr), UpstreamFailure> {
        let mut upstream_query = Message::response_to(query);
        upstream_query.header.qr = false;
        upstream_query.header.rd = true;
        upstream_query.header.ad = false;
        upstream_query.header.cd = validating || query.header.cd;
        upstream_query.questions = vec![question.clone()];
        upstream_query.edns = Some(Edns {
            dnssec_ok: validating || do_bit,
            ..Edns::default()
        });
        let recording = Recording {
            inner: &self.exchange,
            answered: Mutex::new(None),
        };
        let attempts = async {
            let mut failure = UpstreamFailure::Unreachable;
            for _ in 0..self.attempts.max(1) {
                match groups.resolve(&recording, &upstream_query).await {
                    Ok(resp) => return Ok(resp),
                    Err(e @ GroupError::NoAvailableUpstream(_)) => {
                        return Err(UpstreamFailure::from_group(&e));
                    }
                    Err(e) => failure = UpstreamFailure::from_group(&e),
                }
            }
            Err(failure)
        };
        let deadline = tokio::time::Instant::from_std(received_at + self.deadline);
        let resp = tokio::time::timeout_at(deadline, attempts)
            .await
            .map_err(|_| UpstreamFailure::Unreachable)??;
        let from = recording
            .answered
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .map_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), |u| {
                upstream_addr(&u)
            });
        Ok((resp, from))
    }

    /// ACL, then rate limit (which takes a token): the checks that need only the client.
    fn admission(&self, ip: IpAddr, principal: Option<&Principal>, transport: Transport) -> Gate {
        match self.acl.load().check(ip, principal) {
            AclAction::Allow => {}
            other => return Gate::Act(other),
        }
        match self.rate.load().check(ip, transport, Instant::now()) {
            RateVerdict::Allow => Gate::Act(AclAction::Allow),
            RateVerdict::Refuse => Gate::Act(AclAction::Refuse),
            RateVerdict::Drop => Gate::Act(AclAction::Drop),
            RateVerdict::Slip => Gate::Slip,
        }
    }

    fn emit(&self, ctx: &RequestContext, query: &Message, outcome: &Outcome) {
        let Some(sink) = &self.sink else {
            return;
        };
        let (qname, qtype) = query
            .questions
            .first()
            .map_or((Name::root(), RecordType::Unknown(0)), |q| {
                (q.name.clone(), q.qtype)
            });
        let ts_unix_ms = self.clock.unix_millis();
        sink.record(QueryEvent {
            ts_unix_ms,
            client: ctx.client.ip(),
            transport: ctx.transport,
            principal: ctx.principal.as_ref().map(principal_label),
            qname,
            qtype,
            rcode: outcome
                .response
                .as_ref()
                .map_or(Rcode::Refused, |r| r.header.rcode),
            source: outcome.source.clone(),
            dnssec: outcome.dnssec,
            latency_us: u32::try_from(ctx.received_at.elapsed().as_micros()).unwrap_or(u32::MAX),
        });
    }
}

/// A stale cache answer, labelled with EDE 3 (stale answer) or 19 (stale NXDOMAIN).
fn stale_answer(mut msg: Message) -> Message {
    let (code, text) = if msg.header.rcode == Rcode::NxDomain {
        (ede::STALE_NXDOMAIN, "stale NXDOMAIN answer")
    } else {
        (ede::STALE_ANSWER, "stale answer")
    };
    msg.set_ede(code, text);
    msg
}

impl<E: Exchange + 'static> Handler for Engine<E> {
    /// Dropped requests are answered REFUSED here: the `Handler` contract always returns a
    /// response. Transports that can stay silent call [`Engine::process`].
    async fn handle(&self, ctx: RequestContext, query: &Message) -> Message {
        match self.process(&ctx, query).await {
            Some(response) => response,
            None => finish(query, error_response(query, Rcode::Refused, None)),
        }
    }

    async fn respond(&self, ctx: RequestContext, query: &Message) -> Option<Message> {
        self.process(&ctx, query).await
    }

    /// The ACL (without a principal: the listener has none for a packet it cannot decode) and
    /// the rate limit; only an outright drop suppresses the listener's reply.
    fn admit(&self, client: SocketAddr, transport: Transport) -> Admission {
        match self.admission(client.ip(), None, transport) {
            // A listener-built FORMERR is not worth a slip reply: stay silent.
            Gate::Act(AclAction::Drop) | Gate::Slip => Admission::Drop,
            Gate::Act(AclAction::Allow | AclAction::Refuse) => Admission::Answer,
        }
    }
}
