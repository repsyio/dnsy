//! Error types.

use std::fmt;

/// Why an RRSIG did not validate against a DNSKEY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The `RRset` is empty.
    EmptyRrset,
    /// A record's owner, class or type differs from the RRSIG's `RRset`.
    RrsetMismatch,
    /// The RRSIG labels field exceeds the owner's label count.
    InvalidLabels,
    /// The owner is not at or below the signer name.
    SignerNotAncestor,
    /// The DNSKEY lacks the zone-key flag or has a protocol other than 3.
    NotZoneKey,
    /// The DNSKEY has the REVOKE bit set (RFC 5011 2.1) and signs nothing.
    Revoked,
    /// The RRSIG and DNSKEY algorithms differ.
    AlgorithmMismatch,
    /// The RRSIG key tag does not match the DNSKEY.
    KeyTagMismatch,
    /// The signature inception lies in the future.
    NotYetValid,
    /// The signature has expired.
    Expired,
    /// The algorithm is not supported (the zone is insecure for this algorithm).
    UnsupportedAlgorithm(u8),
    /// The DNSKEY public key is malformed for its algorithm.
    MalformedKey,
    /// The RSA key is shorter than 1024 bits or longer than 8192 bits.
    UnsupportedKeySize,
    /// The signature does not match.
    BadSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::EmptyRrset => f.write_str("empty RRset"),
            VerifyError::RrsetMismatch => f.write_str("RRset does not match the RRSIG"),
            VerifyError::InvalidLabels => f.write_str("RRSIG labels exceed the owner's labels"),
            VerifyError::SignerNotAncestor => f.write_str("owner is not within the signer zone"),
            VerifyError::NotZoneKey => f.write_str("DNSKEY is not a zone key"),
            VerifyError::Revoked => f.write_str("DNSKEY is revoked"),
            VerifyError::AlgorithmMismatch => f.write_str("RRSIG and DNSKEY algorithms differ"),
            VerifyError::KeyTagMismatch => f.write_str("RRSIG key tag does not match the DNSKEY"),
            VerifyError::NotYetValid => f.write_str("signature is not yet valid"),
            VerifyError::Expired => f.write_str("signature has expired"),
            VerifyError::UnsupportedAlgorithm(n) => write!(f, "unsupported algorithm {n}"),
            VerifyError::MalformedKey => f.write_str("malformed DNSKEY public key"),
            VerifyError::UnsupportedKeySize => f.write_str("RSA key size outside 1024-8192 bits"),
            VerifyError::BadSignature => f.write_str("signature verification failed"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Failures of key handling, signing, DS creation and NSEC3 hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecError {
    /// The algorithm is not supported for this operation (RSA signing is unsupported).
    UnsupportedAlgorithm(u8),
    /// The DS digest type is not supported.
    UnsupportedDigest(u8),
    /// The key material is malformed or does not match the algorithm.
    InvalidKey,
    /// The system random generator failed.
    KeyGeneration,
    /// The `RRset` cannot be signed as given.
    InvalidRrset(&'static str),
    /// The signature validity window is empty or reversed.
    InvalidValidity,
    /// The signing operation failed.
    SigningFailed,
    /// NSEC3 iterations exceed the permitted maximum (RFC 9276).
    Nsec3IterationsTooHigh {
        /// Iterations in the record.
        iterations: u16,
        /// Maximum the caller allows.
        max: u16,
    },
    /// The NSEC3 salt is longer than 255 octets.
    Nsec3SaltTooLong,
    /// The zone cannot be signed as given.
    InvalidZone(&'static str),
    /// No key is available for a signing duty (zone data or the DNSKEY `RRset`).
    NoSigningKey(&'static str),
}

impl fmt::Display for DnssecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnssecError::UnsupportedAlgorithm(n) => write!(f, "unsupported algorithm {n}"),
            DnssecError::UnsupportedDigest(n) => write!(f, "unsupported digest type {n}"),
            DnssecError::InvalidKey => f.write_str("invalid key material"),
            DnssecError::KeyGeneration => f.write_str("key generation failed"),
            DnssecError::InvalidRrset(why) => write!(f, "invalid RRset: {why}"),
            DnssecError::InvalidValidity => f.write_str("invalid signature validity window"),
            DnssecError::SigningFailed => f.write_str("signing failed"),
            DnssecError::Nsec3IterationsTooHigh { iterations, max } => {
                write!(f, "NSEC3 iterations {iterations} exceed the limit {max}")
            }
            DnssecError::Nsec3SaltTooLong => f.write_str("NSEC3 salt longer than 255 octets"),
            DnssecError::InvalidZone(why) => write!(f, "invalid zone: {why}"),
            DnssecError::NoSigningKey(duty) => write!(f, "no key signs {duty}"),
        }
    }
}

impl std::error::Error for DnssecError {}
