//! DNSKEY public-key conversion to the forms `ring` verifies against.

use crate::{Algorithm, VerifyError};
use ring::signature::{
    self, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519, RsaParameters,
    RsaPublicKeyComponents, UnparsedPublicKey,
};

const MIN_RSA_BITS: usize = 1024;
const MODERN_RSA_BITS: usize = 2048;
const MAX_RSA_BITS: usize = 8192;

/// A DNSKEY public key parsed for one algorithm.
pub(crate) enum PublicKey<'a> {
    Rsa {
        n: &'a [u8],
        e: &'a [u8],
        params: &'static RsaParameters,
    },
    Ecdsa {
        alg: &'static signature::EcdsaVerificationAlgorithm,
        /// SEC1 uncompressed point (`0x04 || x || y`).
        point: Vec<u8>,
    },
    Ed25519(&'a [u8]),
}

impl<'a> PublicKey<'a> {
    /// Parses the DNSKEY public key field for `alg`, rejecting any malformed encoding.
    pub(crate) fn parse(alg: Algorithm, key: &'a [u8]) -> Result<Self, VerifyError> {
        match alg {
            Algorithm::RsaSha256 | Algorithm::RsaSha512 => parse_rsa(alg, key),
            Algorithm::EcdsaP256Sha256 => parse_ec(&ECDSA_P256_SHA256_FIXED, 64, key),
            Algorithm::EcdsaP384Sha384 => parse_ec(&ECDSA_P384_SHA384_FIXED, 96, key),
            Algorithm::Ed25519 => {
                if key.len() == 32 {
                    Ok(PublicKey::Ed25519(key))
                } else {
                    Err(VerifyError::MalformedKey)
                }
            }
            Algorithm::Unsupported(n) => Err(VerifyError::UnsupportedAlgorithm(n)),
        }
    }

    pub(crate) fn verify(&self, message: &[u8], sig: &[u8]) -> Result<(), VerifyError> {
        let result = match self {
            PublicKey::Rsa { n, e, params } => {
                RsaPublicKeyComponents { n, e }.verify(params, message, sig)
            }
            PublicKey::Ecdsa { alg, point } => {
                UnparsedPublicKey::new(*alg, point).verify(message, sig)
            }
            PublicKey::Ed25519(key) => UnparsedPublicKey::new(&ED25519, key).verify(message, sig),
        };
        result.map_err(|_| VerifyError::BadSignature)
    }
}

/// RFC 6605 4 and RFC 8080: the raw point (`x || y`) is `2 * coordinate` octets.
fn parse_ec<'a>(
    alg: &'static signature::EcdsaVerificationAlgorithm,
    len: usize,
    key: &[u8],
) -> Result<PublicKey<'a>, VerifyError> {
    if key.len() != len {
        return Err(VerifyError::MalformedKey);
    }
    let mut point = Vec::with_capacity(len + 1);
    point.push(0x04);
    point.extend_from_slice(key);
    Ok(PublicKey::Ecdsa { alg, point })
}

/// RFC 3110 2: a one-octet exponent length (or zero and a two-octet length), the exponent,
/// then the modulus. Neither number may have leading zero octets.
fn parse_rsa(alg: Algorithm, key: &[u8]) -> Result<PublicKey<'_>, VerifyError> {
    let (&first, rest) = key.split_first().ok_or(VerifyError::MalformedKey)?;
    let (exp_len, rest) = if first == 0 {
        let (len, rest) = rest
            .split_first_chunk::<2>()
            .ok_or(VerifyError::MalformedKey)?;
        (usize::from(u16::from_be_bytes(*len)), rest)
    } else {
        (usize::from(first), rest)
    };
    if exp_len == 0 || exp_len >= rest.len() {
        return Err(VerifyError::MalformedKey);
    }
    let (e, n) = rest.split_at(exp_len);
    if e[0] == 0 || n[0] == 0 {
        return Err(VerifyError::MalformedKey);
    }
    let bits = n.len() * 8 - n[0].leading_zeros() as usize;
    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
        return Err(VerifyError::UnsupportedKeySize);
    }
    let modern = bits >= MODERN_RSA_BITS;
    let params = match (alg, modern) {
        (Algorithm::RsaSha256, true) => &signature::RSA_PKCS1_2048_8192_SHA256,
        (Algorithm::RsaSha256, false) => &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        (_, true) => &signature::RSA_PKCS1_2048_8192_SHA512,
        (_, false) => &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
    };
    Ok(PublicKey::Rsa { n, e, params })
}
