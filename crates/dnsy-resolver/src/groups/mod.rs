//! Upstream groups: load-balancing strategies, per-domain routing and upstream health.
//!
//! A [`GroupSet`] holds named groups of upstreams. A query is routed to the group whose domain
//! pattern is the longest suffix of the query name (else the default group). The group's
//! [`Strategy`] orders its healthy members and the query walks that order until one answers.
//! Health is tracked passively (3 consecutive transport failures eject an upstream for 5 s,
//! doubling to 5 min) and recovered by an active probe ([`GroupSet::run_probes`]).
//!
//! Time and randomness are injected ([`Clock`], [`Rng`]) so behaviour is deterministic in tests.

mod health;
mod store;
#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use dnsy_core::{Clock, SystemClock};

use dnsy_proto::{Class, Header, Message, Name, Opcode, Question, Rcode, RecordType};

use crate::upstream::{Upstream, UpstreamClient, UpstreamError};
use health::Health;

pub use health::{EJECT_AFTER_FAILURES, MAX_BACKOFF, MIN_BACKOFF};
pub use store::{DEFAULT_GROUP, GroupStore, GroupStoreError};

/// Source of random numbers.
pub trait Rng: Send + Sync {
    fn next_u64(&self) -> u64;
}

/// [`Rng`] backed by the thread-local generator.
#[derive(Debug, Default)]
pub struct ThreadRng;

impl Rng for ThreadRng {
    fn next_u64(&self) -> u64 {
        rand::random()
    }
}

/// How a group orders its members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Rotate the starting member on every query.
    RoundRobin,
    /// Random first choice proportional to member weight.
    Weighted,
    /// Lowest EWMA latency first; unmeasured members are tried first.
    LowestLatency,
    /// Configured order; later members only when earlier ones are down or fail.
    Failover,
}

impl Strategy {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::Weighted => "weighted",
            Self::LowestLatency => "lowest_latency",
            Self::Failover => "failover",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "round_robin" => Self::RoundRobin,
            "weighted" => Self::Weighted,
            "lowest_latency" => Self::LowestLatency,
            "failover" => Self::Failover,
            _ => return None,
        })
    }
}

/// An upstream and its weight (used by [`Strategy::Weighted`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub upstream: Upstream,
    /// At least 1.
    pub weight: u32,
}

/// Definition of one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSpec {
    pub name: String,
    pub strategy: Strategy,
    /// Receives queries no domain pattern matches. Exactly one group is the default.
    pub default: bool,
    /// Patterns such as `corp.example` or `*.corp.example`; both match the name itself and
    /// everything below it.
    pub domains: Vec<String>,
    pub members: Vec<GroupMember>,
}

/// Why a group set could not be built or a query could not be answered.
#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("invalid group configuration: {0}")]
    Invalid(String),
    #[error("query has no question")]
    NoQuestion,
    #[error("no available upstream in group {0:?}")]
    NoAvailableUpstream(String),
    #[error("all upstreams failed: {0}")]
    AllFailed(UpstreamError),
}

/// Sends a query to one upstream. Implemented by [`UpstreamClient`]; tests substitute fakes.
pub trait Exchange: Send + Sync {
    fn exchange(
        &self,
        upstream: &Upstream,
        query: &Message,
    ) -> impl Future<Output = Result<Message, UpstreamError>> + Send;
}

impl Exchange for UpstreamClient {
    fn exchange(
        &self,
        upstream: &Upstream,
        query: &Message,
    ) -> impl Future<Output = Result<Message, UpstreamError>> + Send {
        self.query(upstream, query)
    }
}

/// Health snapshot of one upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamHealth {
    pub upstream: Upstream,
    pub available: bool,
    pub consecutive_failures: u32,
    pub latency_ewma: Option<Duration>,
}

struct Group {
    spec: GroupSpec,
    next: AtomicUsize,
    health: Mutex<Vec<Health>>,
}

impl Group {
    fn health(&self) -> MutexGuard<'_, Vec<Health>> {
        self.health.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// All groups plus the routing table.
pub struct GroupSet {
    groups: Vec<Group>,
    /// Domain patterns with their group index, longest first.
    routes: Vec<(Name, usize)>,
    default: usize,
    clock: Arc<dyn Clock>,
    /// The clock's instant at construction; health times are measured from it.
    origin: Instant,
    rng: Arc<dyn Rng>,
}

fn parse_pattern(p: &str) -> Result<Name, GroupError> {
    let bare = p.strip_prefix("*.").unwrap_or(p);
    Name::from_ascii(bare)
        .map(|n| n.to_lowercase())
        .map_err(|_| GroupError::Invalid(format!("bad domain pattern {p:?}")))
}

impl GroupSet {
    /// Build a set from group definitions.
    ///
    /// # Errors
    /// Duplicate group names or patterns, a group without members or with a zero weight, a bad
    /// pattern, or not exactly one default group.
    pub fn new(
        specs: Vec<GroupSpec>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
    ) -> Result<Self, GroupError> {
        let invalid = |m: String| Err(GroupError::Invalid(m));
        let mut names = HashSet::new();
        let mut routes: Vec<(Name, usize)> = Vec::new();
        let mut default = None;
        for (i, spec) in specs.iter().enumerate() {
            if !names.insert(spec.name.as_str()) {
                return invalid(format!("duplicate group {:?}", spec.name));
            }
            if spec.members.is_empty() || spec.members.iter().any(|m| m.weight == 0) {
                return invalid(format!(
                    "group {:?} needs members with weight >= 1",
                    spec.name
                ));
            }
            if spec.default && default.replace(i).is_some() {
                return invalid("more than one default group".to_owned());
            }
            for d in &spec.domains {
                let name = parse_pattern(d)?;
                if routes.iter().any(|(n, _)| *n == name) {
                    return invalid(format!("domain {d:?} routed twice"));
                }
                routes.push((name, i));
            }
        }
        let Some(default) = default else {
            return invalid("no default group".to_owned());
        };
        routes.sort_by_key(|(n, _)| std::cmp::Reverse(n.label_count()));
        let groups = specs
            .into_iter()
            .map(|spec| Group {
                health: Mutex::new(vec![Health::default(); spec.members.len()]),
                next: AtomicUsize::new(0),
                spec,
            })
            .collect();
        Ok(Self {
            groups,
            routes,
            default,
            origin: clock.instant(),
            clock,
            rng,
        })
    }

    /// [`GroupSet::new`] with the system clock and the thread RNG.
    ///
    /// # Errors
    /// As [`GroupSet::new`].
    pub fn from_specs(specs: Vec<GroupSpec>) -> Result<Self, GroupError> {
        Self::new(specs, Arc::new(SystemClock), Arc::new(ThreadRng))
    }

    /// Time elapsed on the clock since this set was built.
    fn elapsed(&self) -> Duration {
        self.clock.instant().saturating_duration_since(self.origin)
    }

    /// Name of the group that serves `qname`.
    #[must_use]
    pub fn group_for(&self, qname: &Name) -> &str {
        &self.groups[self.route(qname)].spec.name
    }

    fn route(&self, qname: &Name) -> usize {
        self.routes
            .iter()
            .find(|(pattern, _)| qname.is_subdomain_of(pattern))
            .map_or(self.default, |(_, i)| *i)
    }

    /// Health of every member of `group`, in configured order.
    #[must_use]
    pub fn health(&self, group: &str) -> Option<Vec<UpstreamHealth>> {
        let g = self.groups.iter().find(|g| g.spec.name == group)?;
        let h = g.health();
        Some(
            g.spec
                .members
                .iter()
                .zip(h.iter())
                .map(|(m, h)| UpstreamHealth {
                    upstream: m.upstream.clone(),
                    available: h.is_available(),
                    consecutive_failures: h.failures(),
                    latency_ewma: h.ewma(),
                })
                .collect(),
        )
    }

    /// Indices of the available members of a group, in the order the strategy wants them tried.
    fn candidates(&self, g: &Group) -> Vec<usize> {
        let (mut avail, ewma): (Vec<usize>, Vec<Option<Duration>>) = {
            let h = g.health();
            (
                (0..h.len()).filter(|&i| h[i].is_available()).collect(),
                h.iter().map(Health::ewma).collect(),
            )
        };
        if avail.is_empty() {
            return avail;
        }
        match g.spec.strategy {
            Strategy::Failover => {}
            Strategy::RoundRobin => {
                let n = g.next.fetch_add(1, Ordering::Relaxed);
                let len = avail.len();
                avail.rotate_left(n % len);
            }
            Strategy::LowestLatency => {
                avail.sort_by_key(|&i| ewma[i].unwrap_or(Duration::ZERO));
            }
            Strategy::Weighted => {
                let mut ordered = Vec::with_capacity(avail.len());
                while !avail.is_empty() {
                    let total: u64 = avail
                        .iter()
                        .map(|&i| u64::from(g.spec.members[i].weight))
                        .sum();
                    let mut roll = self.rng.next_u64() % total;
                    let pos = avail
                        .iter()
                        .position(|&i| {
                            let w = u64::from(g.spec.members[i].weight);
                            if roll < w {
                                true
                            } else {
                                roll -= w;
                                false
                            }
                        })
                        .unwrap_or(0);
                    ordered.push(avail.remove(pos));
                }
                avail = ordered;
            }
        }
        avail
    }

    /// Route `query` to its group and try the group's members in strategy order until one
    /// answers. Transport errors count against the member's health; any DNS response (whatever
    /// its RCODE) counts as success.
    ///
    /// # Errors
    /// [`GroupError::NoAvailableUpstream`] when every member is ejected, otherwise
    /// [`GroupError::AllFailed`] with the last error.
    pub async fn resolve<E: Exchange>(
        &self,
        exchange: &E,
        query: &Message,
    ) -> Result<Message, GroupError> {
        let qname = &query.questions.first().ok_or(GroupError::NoQuestion)?.name;
        let g = &self.groups[self.route(qname)];
        let order = self.candidates(g);
        if order.is_empty() {
            return Err(GroupError::NoAvailableUpstream(g.spec.name.clone()));
        }
        let mut last = None;
        for i in order {
            let started = self.elapsed();
            match exchange.exchange(&g.spec.members[i].upstream, query).await {
                Ok(resp) => {
                    let latency = self.elapsed().saturating_sub(started);
                    g.health()[i].record_success(latency);
                    return Ok(resp);
                }
                Err(e) => {
                    g.health()[i].record_failure(self.elapsed());
                    last = Some(e);
                }
            }
        }
        Err(last.map_or(GroupError::NoQuestion, GroupError::AllFailed))
    }

    /// One round of active probing: every ejected upstream whose backoff has elapsed gets a
    /// root NS query. Success re-admits it; failure restarts the (longer) backoff. Meant to be
    /// called periodically by a background task.
    pub async fn run_probes<E: Exchange>(&self, exchange: &E) {
        let probe = probe_query();
        for g in &self.groups {
            let due: Vec<usize> = {
                let now = self.elapsed();
                let mut h = g.health();
                (0..h.len()).filter(|&i| h[i].begin_probe(now)).collect()
            };
            for i in due {
                let started = self.elapsed();
                let res = exchange.exchange(&g.spec.members[i].upstream, &probe).await;
                let now = self.elapsed();
                let mut h = g.health();
                match res {
                    Ok(_) => h[i].record_success(now.saturating_sub(started)),
                    Err(_) => h[i].record_failure(now),
                }
            }
        }
    }
}

fn probe_query() -> Message {
    Message {
        header: Header {
            id: 0,
            qr: false,
            opcode: Opcode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NoError,
        },
        questions: vec![Question {
            name: Name::root(),
            qtype: RecordType::Ns,
            qclass: Class::In,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
        edns: None,
    }
}
