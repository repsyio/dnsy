//! Signing keys and `RRset` signing (RFC 4034 3, RFC 6605, RFC 8080).

use crate::{Algorithm, DnssecError};
use dnsy_proto::{Dnskey, RData, Record, RecordType, Rrsig, canonical, serial_lt};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
use std::fmt;
use zeroize::Zeroizing;

const FLAG_ZONE: u16 = 0x0100;
const FLAG_SEP: u16 = 0x0001;
const DNSKEY_PROTOCOL: u8 = 3;

enum Pair {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

/// A DNSSEC signing key for algorithm 13 or 15. `Debug` never prints key material.
pub struct SigningKey {
    algorithm: Algorithm,
    ksk: bool,
    pair: Pair,
    pkcs8: Zeroizing<Vec<u8>>,
    rng: SystemRandom,
}

impl SigningKey {
    /// Generates a new key. Only ECDSAP256SHA256 (13) and Ed25519 (15) are supported:
    /// `ring` cannot generate RSA keys, and RSA signing is out of scope.
    pub fn generate(alg: Algorithm, ksk: bool) -> Result<SigningKey, DnssecError> {
        let rng = SystemRandom::new();
        let pkcs8 = match alg {
            Algorithm::EcdsaP256Sha256 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            }
            Algorithm::Ed25519 => Ed25519KeyPair::generate_pkcs8(&rng),
            other => return Err(DnssecError::UnsupportedAlgorithm(other.number())),
        }
        .map_err(|_| DnssecError::KeyGeneration)?;
        Self::from_pkcs8(alg, ksk, pkcs8.as_ref())
    }

    /// Loads a PKCS#8 private key. Malformed or mismatching keys (including an Ed25519 key
    /// whose embedded public key disagrees with its seed) are rejected.
    pub fn from_pkcs8(alg: Algorithm, ksk: bool, der: &[u8]) -> Result<SigningKey, DnssecError> {
        let rng = SystemRandom::new();
        let pair = match alg {
            Algorithm::EcdsaP256Sha256 => Pair::Ecdsa(
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
                    .map_err(|_| DnssecError::InvalidKey)?,
            ),
            Algorithm::Ed25519 => {
                Pair::Ed25519(Ed25519KeyPair::from_pkcs8(der).map_err(|_| DnssecError::InvalidKey)?)
            }
            other => return Err(DnssecError::UnsupportedAlgorithm(other.number())),
        };
        Ok(SigningKey {
            algorithm: alg,
            ksk,
            pair,
            pkcs8: Zeroizing::new(der.to_vec()),
            rng,
        })
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The PKCS#8 private key; callers must keep it out of logs and API bodies.
    pub fn to_pkcs8(&self) -> Zeroizing<Vec<u8>> {
        self.pkcs8.clone()
    }

    /// The matching DNSKEY: zone key flag, plus SEP for a KSK, protocol 3.
    pub fn dnskey(&self) -> Dnskey {
        let public_key = match &self.pair {
            // ring yields the SEC1 uncompressed point; DNSKEY stores `x || y` (RFC 6605 4).
            Pair::Ecdsa(p) => p.public_key().as_ref()[1..].to_vec(),
            Pair::Ed25519(p) => p.public_key().as_ref().to_vec(),
        };
        Dnskey {
            flags: FLAG_ZONE | if self.ksk { FLAG_SEP } else { 0 },
            protocol: DNSKEY_PROTOCOL,
            algorithm: self.algorithm.number(),
            public_key,
        }
    }

    /// Signs an `RRset` (one owner, type and class; no RRSIG type) and returns the RRSIG
    /// record, with the original TTL taken from the first record. `signer` must be the
    /// owner or one of its ancestors.
    pub fn sign_rrset(
        &self,
        rrset: &[Record],
        signer: &dnsy_proto::Name,
        inception: u32,
        expiration: u32,
    ) -> Result<Record, DnssecError> {
        let first = rrset
            .first()
            .ok_or(DnssecError::InvalidRrset("empty RRset"))?;
        let owner = first.name.to_lowercase();
        if first.rtype == RecordType::Rrsig {
            return Err(DnssecError::InvalidRrset("RRSIG records are not signed"));
        }
        if rrset.iter().any(|r| {
            r.rtype != first.rtype
                || r.rtype != r.data.rtype()
                || r.class != first.class
                || r.name.to_lowercase() != owner
        }) {
            return Err(DnssecError::InvalidRrset("mixed owner, type or class"));
        }
        if !owner.is_subdomain_of(signer) {
            return Err(DnssecError::InvalidRrset(
                "owner is outside the signer zone",
            ));
        }
        if !serial_lt(inception, expiration) {
            return Err(DnssecError::InvalidValidity);
        }
        let wildcard = owner.labels().next() == Some(b"*");
        let mut rrsig = Rrsig {
            type_covered: first.rtype,
            algorithm: self.algorithm.number(),
            labels: owner.label_count() - u8::from(wildcard),
            original_ttl: first.ttl,
            expiration,
            inception,
            key_tag: self.dnskey().key_tag(),
            signer: signer.clone(),
            signature: Vec::new(),
        };
        let input = canonical::rrset_signing_input(&rrsig, rrset);
        rrsig.signature = self.sign(&input)?;
        Ok(Record {
            name: first.name.clone(),
            rtype: RecordType::Rrsig,
            class: first.class,
            ttl: first.ttl,
            data: RData::Rrsig(rrsig),
        })
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DnssecError> {
        match &self.pair {
            Pair::Ecdsa(p) => p
                .sign(&self.rng, message)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| DnssecError::SigningFailed),
            Pair::Ed25519(p) => Ok(p.sign(message).as_ref().to_vec()),
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .field("ksk", &self.ksk)
            .finish_non_exhaustive()
    }
}
