//! NSEC3 owner-name hashing (RFC 5155 5) with the iteration cap of RFC 9276.

use crate::DnssecError;
use dnsy_proto::Name;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

/// The one NSEC3 iteration cap: the validator's default limit (RFC 9276 3.2 lets a resolver
/// treat a higher count as insecure) and the most a signed zone may use (it should publish 0,
/// and a zone above the cap would be insecure to validators like this one). Every extra
/// iteration costs the resolver one SHA-1 per name, so the cap bounds attacker-chosen work.
pub const MAX_NSEC3_ITERATIONS: u16 = 100;

/// `IH(salt, name, iterations)` for hash algorithm 1 (SHA-1): the hash of the lowercased
/// owner name wire form, then `iterations` further rounds, each salted.
///
/// This does not cap `iterations`; hash records from the network with
/// [`checked_nsec3_hash`].
pub fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> [u8; 20] {
    let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(name.to_lowercase().as_wire());
    ctx.update(salt);
    let mut digest = ctx.finish();
    for _ in 0..iterations {
        let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(digest.as_ref());
        ctx.update(salt);
        digest = ctx.finish();
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(digest.as_ref());
    out
}

/// [`nsec3_hash`] after checking the parameters from an NSEC3 or NSEC3PARAM record:
/// `iterations` must not exceed `max_iterations` and the salt must fit its one-octet length.
pub fn checked_nsec3_hash(
    name: &Name,
    salt: &[u8],
    iterations: u16,
    max_iterations: u16,
) -> Result<[u8; 20], DnssecError> {
    if iterations > max_iterations {
        return Err(DnssecError::Nsec3IterationsTooHigh {
            iterations,
            max: max_iterations,
        });
    }
    if salt.len() > usize::from(u8::MAX) {
        return Err(DnssecError::Nsec3SaltTooLong);
    }
    Ok(nsec3_hash(name, salt, iterations))
}
