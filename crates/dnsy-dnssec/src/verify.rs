//! RRSIG verification (RFC 4034 3.1.8, RFC 6840 5).

use crate::pubkey::PublicKey;
use crate::{Algorithm, VerifyError};
use dnsy_proto::{Dnskey, Record, RecordType, Rrsig, canonical, serial_lt};

/// Largest clock skew [`verify_rrsig_with_skew`] honours, in seconds (one day).
pub const MAX_CLOCK_SKEW: u32 = 86_400;

/// The DNSKEY REVOKE flag (RFC 5011 2.1): a revoked key is never trusted.
pub(crate) const DNSKEY_REVOKE: u16 = 0x0080;

/// Verifies `rrsig` over `rrset` with `key` at `now_unix`, with no clock tolerance.
pub fn verify_rrsig(
    rrset: &[Record],
    rrsig: &Rrsig,
    key: &Dnskey,
    now_unix: u32,
) -> Result<(), VerifyError> {
    verify_rrsig_with_skew(rrset, rrsig, key, now_unix, 0)
}

/// [`verify_rrsig`] accepting a validity window widened by `skew` seconds on both ends
/// (capped at [`MAX_CLOCK_SKEW`]). Times use RFC 1982 serial arithmetic.
///
/// Checks, in order: the `RRset` matches the RRSIG (owner, class, type, labels, signer),
/// the DNSKEY is a zone key with protocol 3, not revoked, and has a matching algorithm and key tag, the
/// validity window, then the signature over `canonical::rrset_signing_input`.
pub fn verify_rrsig_with_skew(
    rrset: &[Record],
    rrsig: &Rrsig,
    key: &Dnskey,
    now_unix: u32,
    skew: u32,
) -> Result<(), VerifyError> {
    check_rrset(rrset, rrsig)?;
    if !key.is_zone_key() || key.protocol != 3 {
        return Err(VerifyError::NotZoneKey);
    }
    if key.flags & DNSKEY_REVOKE != 0 {
        return Err(VerifyError::Revoked);
    }
    if key.algorithm != rrsig.algorithm {
        return Err(VerifyError::AlgorithmMismatch);
    }
    if key.key_tag() != rrsig.key_tag {
        return Err(VerifyError::KeyTagMismatch);
    }
    let skew = skew.min(MAX_CLOCK_SKEW);
    if serial_lt(now_unix.wrapping_add(skew), rrsig.inception) {
        return Err(VerifyError::NotYetValid);
    }
    if serial_lt(rrsig.expiration, now_unix.wrapping_sub(skew)) {
        return Err(VerifyError::Expired);
    }
    let public = PublicKey::parse(Algorithm::from(rrsig.algorithm), &key.public_key)?;
    let input = canonical::rrset_signing_input(rrsig, rrset);
    public.verify(&input, &rrsig.signature)
}

fn check_rrset(rrset: &[Record], rrsig: &Rrsig) -> Result<(), VerifyError> {
    let first = rrset.first().ok_or(VerifyError::EmptyRrset)?;
    if rrsig.type_covered == RecordType::Rrsig {
        return Err(VerifyError::RrsetMismatch);
    }
    let owner = first.name.to_lowercase();
    for r in rrset {
        if r.rtype != rrsig.type_covered
            || r.rtype != r.data.rtype()
            || r.class != first.class
            || r.name.to_lowercase() != owner
        {
            return Err(VerifyError::RrsetMismatch);
        }
    }
    if rrsig.labels > owner.label_count() {
        return Err(VerifyError::InvalidLabels);
    }
    if !owner.is_subdomain_of(&rrsig.signer) {
        return Err(VerifyError::SignerNotAncestor);
    }
    Ok(())
}
