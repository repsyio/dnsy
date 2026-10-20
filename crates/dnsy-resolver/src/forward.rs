//! The DNSSEC side of the validating forwarder (spec 5.2).
//!
//! [`DnssecPolicy`] holds the validation mode, the [`Validator`] (trust anchors, negative trust
//! anchors, work limits) and the clock-sanity floor. [`UpstreamFetcher`] implements the
//! validator's [`DnssecFetcher`] over the upstream groups: DS and DNSKEY queries go out with DO=1
//! and CD=1, through the main cache, where their answers are memoised as `Unchecked` under the
//! DO=1/CD=1 key (so they are never mistaken for validated data).
//!
//! Amplification is bounded twice: the validator's [`dnsy_dnssec::ValidationLimits`] cap the
//! fetches and signature checks of one validation, and a shared semaphore caps the validation
//! fetches in flight across all clients.

use std::future::Future;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dnsy_config::{TrustAnchor, Validation};
use dnsy_core::DnssecStatus;
use dnsy_dnssec::{
    DnssecFetcher, FetchError, TrustAnchors, ValidationLimits, ValidationOutcome, Validator,
};
use dnsy_proto::{Ds, Edns, Header, Message, Name, Opcode, Question, Rcode, ede};
use tokio::sync::Semaphore;

use crate::cache::{Cache, CacheKey, CacheLookup};
use crate::groups::{Exchange, GroupSet};

/// Validation fetches (DS/DNSKEY queries) in flight at once, across all client queries.
pub const MAX_CONCURRENT_FETCHES: usize = 64;

/// The default clock-sanity floor: 2026-10-01T00:00:00Z. A system clock earlier than this cannot
/// be right (this code did not exist yet), so signature times cannot be checked. The binary
/// replaces it with its build timestamp.
pub const RELEASE_FLOOR_UNIX: u64 = 1_790_812_800;

/// Why the `[dnssec]` section could not be turned into a [`DnssecPolicy`].
#[derive(Debug, thiserror::Error)]
pub enum DnssecConfigError {
    #[error("{0}")]
    Anchor(#[from] dnsy_config::ConfigError),
    #[error("trust anchor file {path}: {source}")]
    AnchorFile {
        path: String,
        source: std::io::Error,
    },
    #[error("negative trust anchor {0:?} is not a domain name")]
    NegativeAnchor(String),
}

/// How forwarded answers are validated.
#[derive(Debug, Clone)]
pub struct DnssecPolicy {
    /// `off`, `permissive` or `strict`.
    pub mode: Validation,
    /// Trust anchors, negative trust anchors and work limits.
    pub validator: Validator,
    /// Clock-sanity floor (seconds since the epoch): while the system clock is earlier,
    /// validation is skipped and answers are `Indeterminate`.
    pub not_before_unix: u64,
}

impl DnssecPolicy {
    /// Validation off.
    #[must_use]
    pub fn off() -> Self {
        Self {
            mode: Validation::Off,
            validator: Validator::new(TrustAnchors::new()),
            not_before_unix: RELEASE_FLOOR_UNIX,
        }
    }

    /// The policy described by `[dnssec]`: root DS anchors from `trust_anchors` and
    /// `trust_anchor_file` (one DS per line; blank lines and lines starting with `;` or `#` are
    /// skipped), negative trust anchors and the clock skew.
    ///
    /// # Errors
    /// A malformed anchor, an unreadable anchor file or a bad negative trust anchor name.
    pub fn from_config(cfg: &dnsy_config::Dnssec) -> Result<Self, DnssecConfigError> {
        let mut anchors = TrustAnchors::new();
        let mut add = |text: &str| -> Result<(), DnssecConfigError> {
            let ta = TrustAnchor::parse(text)?;
            anchors.add_ds(
                Name::root(),
                Ds {
                    key_tag: ta.key_tag,
                    algorithm: ta.algorithm,
                    digest_type: ta.digest_type,
                    digest: ta.digest,
                },
            );
            Ok(())
        };
        for text in &cfg.trust_anchors {
            add(text)?;
        }
        if let Some(path) = &cfg.trust_anchor_file {
            for line in read_anchor_file(path)?.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with(';') && !line.starts_with('#') {
                    add(line)?;
                }
            }
        }
        anchors.set_negative(parse_negative(&cfg.negative_trust_anchors)?);
        let limits = ValidationLimits {
            clock_skew: cfg.clock_skew_s,
            ..ValidationLimits::default()
        };
        Ok(Self {
            mode: cfg.validation,
            validator: Validator::with_limits(anchors, limits),
            not_before_unix: RELEASE_FLOOR_UNIX,
        })
    }

    /// The same policy with its negative trust anchors replaced by `names`.
    #[must_use]
    pub fn with_negative_trust_anchors(&self, names: Vec<Name>) -> Self {
        let mut anchors = self.validator.anchors().clone();
        anchors.set_negative(names);
        Self {
            validator: Validator::with_limits(anchors, *self.validator.limits()),
            ..self.clone()
        }
    }

    /// Whether `now_unix` is a plausible wall-clock time (not before the floor).
    #[must_use]
    pub fn clock_trusted(&self, now_unix: u64) -> bool {
        now_unix >= self.not_before_unix
    }

    /// Validates `resp`, the DO=1/CD=1 upstream answer to `q`, at `now_unix`. With an untrusted
    /// clock nothing is checked and the outcome is `Indeterminate` (EDE 5): signature times are
    /// meaningless, and turning every answer Bogus would also break the NTP lookup that would fix
    /// the clock.
    pub async fn validate<F: DnssecFetcher>(
        &self,
        fetcher: &F,
        q: &Question,
        resp: &Message,
        now_unix: u64,
    ) -> ValidationOutcome {
        if !self.clock_trusted(now_unix) {
            return ValidationOutcome {
                status: DnssecStatus::Indeterminate,
                ede: Some((
                    ede::DNSSEC_INDETERMINATE,
                    "system clock is untrusted; DNSSEC not validated".to_owned(),
                )),
                min_ttl: None,
            };
        }
        // RFC 1982 serial arithmetic: the validator compares times modulo 2^32.
        let now = u32::try_from(now_unix & u64::from(u32::MAX)).unwrap_or(0);
        self.validator.validate(fetcher, q, resp, now).await
    }
}

fn read_anchor_file(path: &Path) -> Result<String, DnssecConfigError> {
    std::fs::read_to_string(path).map_err(|source| DnssecConfigError::AnchorFile {
        path: path.display().to_string(),
        source,
    })
}

/// Parses negative trust anchor names (lowercased).
///
/// # Errors
/// [`DnssecConfigError::NegativeAnchor`] for a name that does not parse.
pub fn parse_negative(names: &[String]) -> Result<Vec<Name>, DnssecConfigError> {
    names
        .iter()
        .map(|s| {
            let fq = if s.ends_with('.') {
                s.clone()
            } else {
                format!("{s}.")
            };
            Name::from_ascii(&fq)
                .map(|n| n.to_lowercase())
                .map_err(|_| DnssecConfigError::NegativeAnchor(s.clone()))
        })
        .collect()
}

/// Seconds since the epoch, 0 for a clock before 1970.
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Caps every record TTL (except OPT) of `msg` at `cap`: validated data must not outlive its
/// signatures, and the cache derives an entry's lifetime from the record TTLs.
pub fn cap_ttls(msg: &mut Message, cap: u32) {
    for r in msg
        .answers
        .iter_mut()
        .chain(msg.authority.iter_mut())
        .chain(msg.additional.iter_mut())
    {
        r.ttl = r.ttl.min(cap);
    }
}

/// A recursive query for `q` with DO=1 and CD=1.
#[must_use]
pub fn dnssec_query(q: &Question) -> Message {
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
            cd: true,
            rcode: Rcode::NoError,
        },
        questions: vec![q.clone()],
        answers: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
        edns: Some(Edns {
            dnssec_ok: true,
            ..Edns::default()
        }),
    }
}

/// The validator's [`DnssecFetcher`] over the upstream groups, memoising through `cache`.
pub struct UpstreamFetcher<'a, E> {
    pub groups: &'a GroupSet,
    pub exchange: &'a E,
    pub cache: &'a Cache,
    /// Shared by every validation (see [`MAX_CONCURRENT_FETCHES`]).
    pub permits: &'a Semaphore,
    /// No fetch outlives it; a late fetch fails (and the validation turns Bogus).
    pub deadline: tokio::time::Instant,
}

impl<E: Exchange> UpstreamFetcher<'_, E> {
    async fn fetch_inner(&self, q: Question) -> Result<Message, FetchError> {
        let key = CacheKey {
            name: q.name.to_lowercase(),
            qtype: q.qtype,
            qclass: q.qclass,
            do_bit: true,
            cd_bit: true,
        };
        if let CacheLookup::Fresh { msg, .. } = self.cache.get(&key, Instant::now()) {
            return Ok(msg);
        }
        let late = || FetchError(format!("{} {:?}: deadline exceeded", q.name, q.qtype));
        let _permit = tokio::time::timeout_at(self.deadline, self.permits.acquire())
            .await
            .map_err(|_| late())?
            .map_err(|_| FetchError("fetch limiter closed".to_owned()))?;
        let mut resp = tokio::time::timeout_at(
            self.deadline,
            self.groups.resolve(self.exchange, &dnssec_query(&q)),
        )
        .await
        .map_err(|_| late())?
        .map_err(|e| FetchError(e.to_string()))?;
        if resp.questions.len() != 1 || resp.questions[0] != q {
            return Err(FetchError(format!(
                "{} {:?}: response does not match the question",
                q.name, q.qtype
            )));
        }
        resp.header.aa = false;
        resp.header.ad = false;
        resp.additional.clear();
        resp.edns = None;
        self.cache
            .insert(key, &resp, DnssecStatus::Unchecked, Instant::now());
        Ok(resp)
    }
}

impl<E: Exchange> DnssecFetcher for UpstreamFetcher<'_, E> {
    fn fetch(&self, q: Question) -> impl Future<Output = Result<Message, FetchError>> + Send {
        self.fetch_inner(q)
    }
}

#[cfg(test)]
mod tests;
