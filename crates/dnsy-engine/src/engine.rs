//! The request pipeline (spec 5.2).
//!
//! ACL -> rate limit -> blocklist/allowlist -> local zones (authoritative, never cached) ->
//! RD check -> cache (keyed by the query's DO/CD bits) -> upstream groups (bounded by the overall
//! deadline) -> DNSSEC validation seam -> response-IP policy -> shaping -> one `QueryEvent`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::{ArcSwap, ArcSwapOption};
use dnsy_core::{DnssecStatus, Principal};
use dnsy_filter::{
    Acl, AclAction, BlockMode, FilterSet, ListManager, RateLimiter, RateVerdict, Verdict,
    block_response,
};
use dnsy_observe::{AnswerSource, QueryEvent, QueryEventSink};
use dnsy_proto::{EDNS_VERSION, Edns, Message, Name, Opcode, Question, Rcode, RecordType, ede};
use dnsy_resolver::groups::{Exchange, GroupError, GroupSet};
use dnsy_resolver::{Cache, CacheKey, CacheLookup, Upstream, UpstreamClient, UpstreamError};
use dnsy_zone::{ZoneSigning, ZoneStore};

use crate::handler::{Handler, RequestContext};
use crate::response::{
    RESPONSE_IP_LIST, ResponseIpPolicy, authoritative, dnssec_ok, error_response, finish, scrub,
};

/// Clients tracked by the rate limiter.
pub(crate) const RATE_LIMIT_KEYS: usize = 100_000;

/// The request pipeline. Built by [`crate::EngineBuilder`]; policy snapshots (ACL,
/// response-IP policy, upstream groups, rate limit) can be swapped while serving.
pub struct Engine<E = UpstreamClient> {
    pub(crate) acl: ArcSwap<Acl>,
    pub(crate) rate: ArcSwap<RateLimiter>,
    pub(crate) filter: Filters,
    pub(crate) response_ip: ArcSwap<ResponseIpPolicy>,
    pub(crate) groups: ArcSwapOption<GroupSet>,
    pub(crate) zones: Option<Arc<ZoneStore>>,
    pub(crate) zone_signing: Option<ZoneSigning>,
    pub(crate) cache: Arc<Cache>,
    pub(crate) exchange: E,
    pub(crate) sink: Option<Arc<dyn QueryEventSink>>,
    pub(crate) block_mode: BlockMode,
    pub(crate) attempts: u32,
    pub(crate) deadline: Duration,
}

/// Where the active blocklist filter comes from.
pub(crate) enum Filters {
    Fixed(Arc<FilterSet>),
    /// Persisted list sources; the manager swaps in rebuilt filters.
    Lists(ListManager),
}

impl Filters {
    fn current(&self) -> Arc<FilterSet> {
        match self {
            Self::Fixed(set) => Arc::clone(set),
            Self::Lists(manager) => manager.current(),
        }
    }
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
enum UpstreamFailure {
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
    /// The cache, for flushing and statistics.
    #[must_use]
    pub fn cache(&self) -> &Arc<Cache> {
        &self.cache
    }

    /// The zone store answering local zones, if any.
    #[must_use]
    pub fn zone_store(&self) -> Option<&Arc<ZoneStore>> {
        self.zones.as_ref()
    }

    /// The signer of zones with `dnssec.enabled`, when wired by
    /// [`crate::EngineBuilder::from_config`] (spawn its re-signing task; share its key store).
    #[must_use]
    pub fn zone_signing(&self) -> Option<&ZoneSigning> {
        self.zone_signing.as_ref()
    }

    /// Current upstream groups (for health reporting).
    #[must_use]
    pub fn groups(&self) -> Option<Arc<GroupSet>> {
        self.groups.load_full()
    }

    pub fn set_acl(&self, acl: Acl) {
        self.acl.store(Arc::new(acl));
    }

    /// Replaces the rate limiter (`qps == 0` disables limiting); client buckets start fresh.
    pub fn set_rate_limit(&self, qps: u32) {
        self.rate
            .store(Arc::new(RateLimiter::new(qps, RATE_LIMIT_KEYS)));
    }

    /// The blocklist manager, when the filter comes from persisted list sources (spawn its
    /// `run` loop, refresh sources, reload after rule changes).
    #[must_use]
    pub fn list_manager(&self) -> Option<&ListManager> {
        match &self.filter {
            Filters::Lists(manager) => Some(manager),
            Filters::Fixed(_) => None,
        }
    }

    pub fn set_response_ip_policy(&self, policy: ResponseIpPolicy) {
        self.response_ip.store(Arc::new(policy));
    }

    /// Replaces the upstream groups; `None` leaves the server without upstreams (SERVFAIL, EDE 22).
    pub fn set_groups(&self, groups: Option<GroupSet>) {
        self.groups.store(groups.map(Arc::new));
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

        let refused = || {
            Outcome::new(
                finish(query, error_response(query, Rcode::Refused, None)),
                AnswerSource::Refused,
            )
        };
        let dropped = Outcome {
            response: None,
            source: AnswerSource::Refused,
            dnssec: DnssecStatus::Unchecked,
        };
        let ip = ctx.client.ip();
        match self.acl.load().check(ip, ctx.principal.as_ref()) {
            AclAction::Allow => {}
            AclAction::Refuse => return refused(),
            AclAction::Drop => return dropped,
        }
        match self.rate.load().check(ip, ctx.transport, Instant::now()) {
            RateVerdict::Allow => {}
            RateVerdict::Refuse => return refused(),
            RateVerdict::Drop => return dropped,
        }

        if let Verdict::Block { list, mode } = self.filter.current().check(&question.name)
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

        if !query.header.rd {
            return refused();
        }

        let key = CacheKey {
            name: question.name.to_lowercase(),
            qtype: question.qtype,
            qclass: question.qclass,
            do_bit,
            cd_bit: query.header.cd,
        };
        let (msg, source, dnssec) = match self.cache.get(&key, Instant::now()) {
            CacheLookup::Fresh { msg, dnssec } => (msg, AnswerSource::Cache, dnssec),
            CacheLookup::Miss => match self.forward(ctx, query, question, do_bit).await {
                Ok((msg, from)) => {
                    let dnssec = self.validate(question, &msg);
                    self.cache.insert(key, &msg, dnssec, Instant::now());
                    (msg, AnswerSource::Upstream(from), dnssec)
                }
                Err(failure) => {
                    let msg = error_response(query, Rcode::ServFail, Some(failure.ede()));
                    return Outcome::new(finish(query, msg), AnswerSource::Error);
                }
            },
        };

        if self.response_ip.load().blocks(&msg)
            && let Some(blocked) = block_response(query, self.block_mode, RESPONSE_IP_LIST)
        {
            return Outcome {
                dnssec,
                ..Outcome::new(
                    finish(query, blocked),
                    AnswerSource::Blocked {
                        list: RESPONSE_IP_LIST.to_owned(),
                    },
                )
            };
        }
        Outcome {
            dnssec,
            ..Outcome::new(finish(query, msg), source)
        }
    }

    /// DNSSEC validation seam (DNSY-37): forwarded answers are not validated yet.
    #[expect(
        clippy::unused_self,
        reason = "seam for the validating forwarder (DNSY-37), which needs engine state"
    )]
    fn validate(&self, _question: &Question, _msg: &Message) -> DnssecStatus {
        DnssecStatus::Unchecked
    }

    /// Forwards a clean copy of the question (no client EDNS options) to the upstream groups,
    /// retrying up to `attempts` times, all within the overall deadline measured from receipt.
    async fn forward(
        &self,
        ctx: &RequestContext,
        query: &Message,
        question: &Question,
        do_bit: bool,
    ) -> Result<(Message, SocketAddr), UpstreamFailure> {
        let Some(groups) = self.groups.load_full() else {
            return Err(UpstreamFailure::Unreachable);
        };
        let mut upstream_query = Message::response_to(query);
        upstream_query.header.qr = false;
        upstream_query.header.rd = true;
        upstream_query.questions = vec![question.clone()];
        upstream_query.edns = Some(Edns {
            dnssec_ok: do_bit,
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
        let deadline = tokio::time::Instant::from_std(ctx.received_at + self.deadline);
        let resp = tokio::time::timeout_at(deadline, attempts)
            .await
            .map_err(|_| UpstreamFailure::Unreachable)??;
        let msg = scrub(question, resp, do_bit).ok_or(UpstreamFailure::Network)?;
        let from = recording
            .answered
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .map_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), |u| {
                upstream_addr(&u)
            });
        Ok((msg, from))
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
        let ts_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
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

impl<E: Exchange + 'static> Handler for Engine<E> {
    /// Dropped requests are answered REFUSED here: the `Handler` contract always returns a
    /// response. Transports that can stay silent call [`Engine::process`].
    async fn handle(&self, ctx: RequestContext, query: Message) -> Message {
        match self.process(&ctx, &query).await {
            Some(response) => response,
            None => finish(&query, error_response(&query, Rcode::Refused, None)),
        }
    }
}
