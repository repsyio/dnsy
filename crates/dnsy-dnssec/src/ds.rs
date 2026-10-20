//! DS record creation (RFC 4034 5.1.4, RFC 4509, RFC 6605).

use crate::{DigestType, DnssecError};
use dnsy_proto::{Dnskey, Ds, Name, RData, canonical};
use ring::digest::{Algorithm, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384, digest};

/// The DS for `key` at `owner`: the digest of the canonical owner name followed by the
/// DNSKEY RDATA. SHA-1 exists to check old DS records; do not publish new ones with it.
pub fn ds_for(owner: &Name, key: &Dnskey, dt: DigestType) -> Result<Ds, DnssecError> {
    let algorithm: &'static Algorithm = match dt {
        DigestType::Sha1 => &SHA1_FOR_LEGACY_USE_ONLY,
        DigestType::Sha256 => &SHA256,
        DigestType::Sha384 => &SHA384,
        DigestType::Unsupported(n) => return Err(DnssecError::UnsupportedDigest(n)),
    };
    let mut input = owner.to_lowercase().as_wire().to_vec();
    input.extend_from_slice(&canonical::rdata_wire(&RData::Dnskey(key.clone())));
    Ok(Ds {
        key_tag: key.key_tag(),
        algorithm: key.algorithm,
        digest_type: dt.number(),
        digest: digest(algorithm, &input).as_ref().to_vec(),
    })
}
