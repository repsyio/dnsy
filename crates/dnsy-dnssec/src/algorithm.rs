//! DNSSEC algorithm and DS digest type numbers.

/// A DNSSEC signing algorithm (IANA "DNS Security Algorithm Numbers").
///
/// Everything outside the five supported algorithms, including RSAMD5 (1), DSA (3), the
/// RSASHA1 family (5, 7), GOST (12) and Ed448 (16), is `Unsupported`; a validator treats
/// such a zone as insecure (RFC 6840 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// 8, RSA/SHA-256 (RFC 5702); verify only.
    RsaSha256,
    /// 10, RSA/SHA-512 (RFC 5702); verify only.
    RsaSha512,
    /// 13, ECDSA P-256 with SHA-256 (RFC 6605).
    EcdsaP256Sha256,
    /// 14, ECDSA P-384 with SHA-384 (RFC 6605).
    EcdsaP384Sha384,
    /// 15, Ed25519 (RFC 8080).
    Ed25519,
    /// Any other algorithm number.
    Unsupported(u8),
}

impl Algorithm {
    pub fn number(self) -> u8 {
        match self {
            Algorithm::RsaSha256 => 8,
            Algorithm::RsaSha512 => 10,
            Algorithm::EcdsaP256Sha256 => 13,
            Algorithm::EcdsaP384Sha384 => 14,
            Algorithm::Ed25519 => 15,
            Algorithm::Unsupported(n) => n,
        }
    }

    /// True when signatures of this algorithm can be verified.
    pub fn is_supported(self) -> bool {
        !matches!(self, Algorithm::Unsupported(_))
    }

    /// True when keys of this algorithm can be generated and used to sign (13 and 15;
    /// `ring` cannot generate RSA keys).
    pub fn can_sign(self) -> bool {
        matches!(self, Algorithm::EcdsaP256Sha256 | Algorithm::Ed25519)
    }
}

impl From<u8> for Algorithm {
    fn from(n: u8) -> Self {
        match n {
            8 => Algorithm::RsaSha256,
            10 => Algorithm::RsaSha512,
            13 => Algorithm::EcdsaP256Sha256,
            14 => Algorithm::EcdsaP384Sha384,
            15 => Algorithm::Ed25519,
            other => Algorithm::Unsupported(other),
        }
    }
}

impl From<Algorithm> for u8 {
    fn from(a: Algorithm) -> u8 {
        a.number()
    }
}

/// A DS digest type (IANA "Delegation Signer Digest Algorithm Numbers").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestType {
    /// 1, SHA-1. Accepted for checking existing DS records; do not publish new ones.
    Sha1,
    /// 2, SHA-256.
    Sha256,
    /// 4, SHA-384.
    Sha384,
    /// Any other digest type (3 is GOST R 34.11-94).
    Unsupported(u8),
}

impl DigestType {
    pub fn number(self) -> u8 {
        match self {
            DigestType::Sha1 => 1,
            DigestType::Sha256 => 2,
            DigestType::Sha384 => 4,
            DigestType::Unsupported(n) => n,
        }
    }
}

impl From<u8> for DigestType {
    fn from(n: u8) -> Self {
        match n {
            1 => DigestType::Sha1,
            2 => DigestType::Sha256,
            4 => DigestType::Sha384,
            other => DigestType::Unsupported(other),
        }
    }
}

impl From<DigestType> for u8 {
    fn from(d: DigestType) -> u8 {
        d.number()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_round_trip() {
        for n in 0..=u8::MAX {
            assert_eq!(Algorithm::from(n).number(), n);
            assert_eq!(u8::from(DigestType::from(n)), n);
        }
        assert_eq!(Algorithm::from(13), Algorithm::EcdsaP256Sha256);
        assert_eq!(DigestType::from(4), DigestType::Sha384);
    }

    #[test]
    fn legacy_algorithms_unsupported() {
        for n in [0, 1, 3, 5, 6, 7, 12, 16, 200] {
            assert!(!Algorithm::from(n).is_supported(), "{n}");
        }
        for n in [8, 10, 13, 14, 15] {
            assert!(Algorithm::from(n).is_supported(), "{n}");
        }
    }

    #[test]
    fn only_13_and_15_sign() {
        let signing: Vec<u8> = (0..=u8::MAX)
            .filter(|n| Algorithm::from(*n).can_sign())
            .collect();
        assert_eq!(signing, [13, 15]);
    }
}
