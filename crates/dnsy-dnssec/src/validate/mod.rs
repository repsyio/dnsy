//! Chain-of-trust validation (RFC 4033, 4034, 4035, 5155, 6840, 9276).
//!
//! [`Validator::validate`] checks one upstream response (fetched with DO=1, CD=1) and returns
//! its RFC 4035 4.3 security status. Missing DS and DNSKEY `RRsets` are fetched through a
//! [`DnssecFetcher`]; every validation runs under a [`ValidationLimits`] work budget.

mod anchors;
mod chain;
mod denial;
mod response;
mod rrset;

use std::fmt;
use std::future::Future;

use dnsy_core::DnssecStatus;
use dnsy_proto::{Message, Question, ede};

pub use anchors::TrustAnchors;

/// Why a [`DnssecFetcher`] could not produce a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchError(pub String);

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fetch failed: {}", self.0)
    }
}

impl std::error::Error for FetchError {}

/// Fetches the DS and DNSKEY `RRsets` the chain of trust needs. Queries are sent with DO=1 and
/// CD=1 so that RRSIGs and denial records come back unvalidated.
pub trait DnssecFetcher: Send + Sync {
    /// Resolves `q` and returns the full response message.
    fn fetch(&self, q: Question) -> impl Future<Output = Result<Message, FetchError>> + Send;
}

/// Work limits for one validation. They bound the CPU an adversarial zone can make the
/// validator spend: colliding key tags and RRSIG floods (`KeyTrap`, CVE-2023-50387) and NSEC3
/// hash floods (CVE-2023-50868).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Names walked between the trust anchor and a signer (zone cuts and the labels between).
    pub max_zone_cuts: usize,
    /// Signature verifications attempted for one `RRset`.
    pub max_rrsig_verifications: usize,
    /// Signature verifications attempted over the whole validation.
    pub max_verifications: usize,
    /// DS/DNSKEY fetches per validation.
    pub max_fetches: usize,
    /// NSEC3 iterations above this make the proof `Insecure` (RFC 9276 3.2).
    pub max_nsec3_iterations: u16,
    /// Distinct NSEC3 hash computations per validation.
    pub max_nsec3_hashes: usize,
    /// Seconds the RRSIG validity window is widened by on each side (capped at one day).
    pub clock_skew: u32,
    /// Seconds an answer stays cached when validation failed to fetch DS or DNSKEY data
    /// (`Indeterminate`); match the cache's `servfail_ttl`.
    pub indeterminate_ttl: u32,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_zone_cuts: 16,
            max_rrsig_verifications: 8,
            max_verifications: 64,
            max_fetches: 32,
            max_nsec3_iterations: crate::MAX_NSEC3_ITERATIONS,
            max_nsec3_hashes: 64,
            clock_skew: 300,
            indeterminate_ttl: 5,
        }
    }
}

/// The result of a validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationOutcome {
    /// RFC 4035 4.3 status (never `Unchecked`).
    pub status: DnssecStatus,
    /// Extended DNS error (RFC 8914) explaining a non-secure status.
    pub ede: Option<(u16, String)>,
    /// For `Secure` answers: the lowest of the validated records' TTLs, their RRSIG original
    /// TTLs and the seconds left until their RRSIGs expire. Caches cap their TTL with it.
    pub min_ttl: Option<u32>,
    /// The chain of trust could not be built because a DS or DNSKEY fetch failed (status
    /// `Indeterminate`, EDE 5). A strict resolver must not hand the unvalidated data on.
    pub fetch_failed: bool,
}

/// A DNSSEC validator holding trust anchors and work limits; cheap to share.
#[derive(Debug, Clone)]
pub struct Validator {
    anchors: TrustAnchors,
    limits: ValidationLimits,
}

impl Validator {
    /// A validator with the default [`ValidationLimits`].
    pub fn new(anchors: TrustAnchors) -> Self {
        Self::with_limits(anchors, ValidationLimits::default())
    }

    /// A validator with explicit limits.
    pub fn with_limits(anchors: TrustAnchors, limits: ValidationLimits) -> Self {
        Self { anchors, limits }
    }

    /// The configured trust anchors.
    pub fn anchors(&self) -> &TrustAnchors {
        &self.anchors
    }

    /// The configured work limits.
    pub fn limits(&self) -> &ValidationLimits {
        &self.limits
    }

    /// Validates `resp`, the upstream answer to `q`, at time `now_unix` (seconds since the
    /// epoch; injected so callers control the clock).
    pub async fn validate<F: DnssecFetcher>(
        &self,
        f: &F,
        q: &Question,
        resp: &Message,
        now_unix: u32,
    ) -> ValidationOutcome {
        let mut ctx = chain::Ctx::new(self, f, now_unix);
        match ctx.response(q, resp).await {
            Ok(Verdict::Secure) => ValidationOutcome {
                status: DnssecStatus::Secure,
                ede: None,
                min_ttl: ctx.min_ttl(),
                fetch_failed: false,
            },
            Ok(Verdict::Insecure(ede)) => ValidationOutcome {
                status: DnssecStatus::Insecure,
                ede,
                // An answer accepted under an expiring negative trust anchor carries a cap.
                min_ttl: ctx.min_ttl(),
                fetch_failed: false,
            },
            Err(f) => ValidationOutcome {
                status: f.status,
                ede: Some((f.ede, f.text)),
                min_ttl: f.transient.then_some(self.limits.indeterminate_ttl),
                fetch_failed: f.transient,
            },
        }
    }
}

/// A non-failing result: `Secure`, or `Insecure` with an optional explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Secure,
    Insecure(Option<(u16, String)>),
}

impl Verdict {
    /// `Insecure` wins over `Secure`; the first explanation is kept.
    fn and(self, other: Verdict) -> Verdict {
        match (&self, &other) {
            (Verdict::Insecure(Some(_)), _) | (_, Verdict::Secure) => self,
            _ => other,
        }
    }
}

/// A `Bogus` or `Indeterminate` result with its EDE.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Failure {
    status: DnssecStatus,
    ede: u16,
    text: String,
    /// A fetch failure: retry soon instead of caching the outcome for long.
    transient: bool,
}

impl Failure {
    fn bogus(ede: u16, text: impl Into<String>) -> Self {
        Self {
            status: DnssecStatus::Bogus,
            ede,
            text: text.into(),
            transient: false,
        }
    }

    fn indeterminate(text: impl Into<String>) -> Self {
        Self {
            status: DnssecStatus::Indeterminate,
            ede: ede::DNSSEC_INDETERMINATE,
            text: text.into(),
            transient: false,
        }
    }

    fn fetch(text: impl Into<String>) -> Self {
        Self {
            transient: true,
            ..Self::indeterminate(text)
        }
    }

    fn limit(what: &str) -> Self {
        Self::bogus(
            ede::DNSSEC_BOGUS,
            format!("validation work limit exceeded: {what}"),
        )
    }
}

type Res<T> = Result<T, Failure>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_and_keeps_insecure_and_first_reason() {
        let reason = || Some((1, "alg".to_owned()));
        assert_eq!(Verdict::Secure.and(Verdict::Secure), Verdict::Secure);
        assert_eq!(
            Verdict::Secure.and(Verdict::Insecure(None)),
            Verdict::Insecure(None)
        );
        assert_eq!(
            Verdict::Insecure(None).and(Verdict::Insecure(reason())),
            Verdict::Insecure(reason())
        );
        assert_eq!(
            Verdict::Insecure(reason()).and(Verdict::Insecure(None)),
            Verdict::Insecure(reason())
        );
        assert_eq!(
            Verdict::Insecure(reason()).and(Verdict::Secure),
            Verdict::Insecure(reason())
        );
    }

    #[test]
    fn fetch_error_displays_reason() {
        assert_eq!(
            FetchError("timeout".into()).to_string(),
            "fetch failed: timeout"
        );
    }

    #[test]
    fn limits_default_to_the_documented_values() {
        let l = ValidationLimits::default();
        assert_eq!(
            (l.max_zone_cuts, l.max_rrsig_verifications, l.max_fetches),
            (16, 8, 32)
        );
        assert_eq!(l.max_nsec3_iterations, 100);
        let v = Validator::new(TrustAnchors::new());
        assert_eq!(v.limits(), &l);
        assert!(v.anchors().is_empty());
    }
}
