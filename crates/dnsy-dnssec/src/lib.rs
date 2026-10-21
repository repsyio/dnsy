//! dnsy-dnssec: in-house DNSSEC cryptography over `ring` primitives.
//!
//! The DNSSEC logic (RRSIG signed-data construction, key conversion, DS digests, NSEC3
//! hashing, limits) and the chain-of-trust validator are written here; `ring` supplies only
//! signatures and digests.

#![expect(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "fallible functions return documented error enums; accessors are self-describing"
)]

mod algorithm;
pub mod anchors;
mod ds;
mod error;
mod keys;
mod nsec3;
mod pubkey;
mod sign;
mod signing;
mod validate;
mod verify;

pub use algorithm::{Algorithm, DigestType};
pub use anchors::{TrustAnchor, TrustAnchorError};
pub use ds::ds_for;
pub use error::{DnssecError, VerifyError};
pub use keys::{
    Clock, KeyRecord, KeyRole, KeyState, ManualClock, RolloverTimings, SystemClock, Transition,
    plan,
};
pub use nsec3::{MAX_NSEC3_ITERATIONS, checked_nsec3_hash, nsec3_hash};
pub use sign::{
    ActiveKeys, Denial, SignedRrset, SignedZone, SigningPolicy, ZoneData, ZoneKey, ZoneSigner,
};
pub use signing::SigningKey;
pub use validate::{
    DnssecFetcher, FetchError, TrustAnchors, ValidationLimits, ValidationOutcome, Validator,
};
pub use verify::{MAX_CLOCK_SKEW, verify_rrsig, verify_rrsig_with_skew};
