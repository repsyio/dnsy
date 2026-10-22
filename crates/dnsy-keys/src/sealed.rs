//! Sealing of private keys and bundles: argon2id derives the key-encryption key from the
//! passphrase, AES-256-GCM seals the plaintext. Blob layout (unchanged since the first
//! release): `version || memory KiB (u32 BE) || iterations (u32 BE) || salt || nonce ||
//! ciphertext+tag`, with the header authenticated as associated data.

use argon2::{Algorithm as Argon2Algorithm, Argon2, Params, Version};
use dnsy_dnssec::DnssecError;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::{KeyStoreError, Passphrase};

const BLOB_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
/// version, memory KiB (u32), iterations (u32), salt
const HEADER_LEN: usize = 1 + 4 + 4 + SALT_LEN;
/// Largest KDF cost accepted from a stored blob or bundle, so hostile input cannot exhaust memory.
const MAX_KDF_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_KDF_ITERATIONS: u32 = 16;

/// Argon2id cost for deriving the key-encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    pub memory_kib: u32,
    pub iterations: u32,
}

impl KdfCost {
    /// Cost of backup bundles: 64 MiB, 3 iterations, 1 lane.
    pub const BUNDLE: KdfCost = KdfCost {
        memory_kib: 64 * 1024,
        iterations: 3,
    };
}

impl Default for KdfCost {
    /// OWASP minimum for argon2id: 19 MiB, 2 iterations, 1 lane.
    fn default() -> Self {
        KdfCost {
            memory_kib: 19 * 1024,
            iterations: 2,
        }
    }
}

fn derive(
    pass: &Passphrase,
    cost: KdfCost,
    salt: &[u8],
) -> Result<Zeroizing<[u8; 32]>, KeyStoreError> {
    let params = Params::new(cost.memory_kib, cost.iterations, 1, Some(32))
        .map_err(|_| KeyStoreError::Decrypt)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Argon2Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), salt, key.as_mut())
        .map_err(|_| KeyStoreError::Decrypt)?;
    Ok(key)
}

fn fill(buf: &mut [u8]) -> Result<(), KeyStoreError> {
    SystemRandom::new()
        .fill(buf)
        .map_err(|_| KeyStoreError::Key(DnssecError::KeyGeneration))
}

fn aead(key: &[u8; 32]) -> Result<LessSafeKey, KeyStoreError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| KeyStoreError::Decrypt)
}

/// Seals `plain` as `header || nonce || ciphertext+tag`; the header (version, KDF cost, salt)
/// is authenticated.
pub(crate) fn encrypt(
    pass: &Passphrase,
    cost: KdfCost,
    plain: &[u8],
) -> Result<Vec<u8>, KeyStoreError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    fill(&mut salt)?;
    fill(&mut nonce)?;
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + plain.len() + 16);
    out.push(BLOB_VERSION);
    out.extend_from_slice(&cost.memory_kib.to_be_bytes());
    out.extend_from_slice(&cost.iterations.to_be_bytes());
    out.extend_from_slice(&salt);
    let key = derive(pass, cost, &salt)?;
    let header = out.clone();
    let mut body = Zeroizing::new(plain.to_vec());
    aead(&key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header),
            &mut *body,
        )
        .map_err(|_| KeyStoreError::Decrypt)?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

pub(crate) fn decrypt(pass: &Passphrase, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyStoreError> {
    if blob.len() < HEADER_LEN + NONCE_LEN + AES_256_GCM.tag_len() || blob[0] != BLOB_VERSION {
        return Err(KeyStoreError::Decrypt);
    }
    let (header, rest) = blob.split_at(HEADER_LEN);
    let (nonce, sealed) = rest.split_at(NONCE_LEN);
    let memory_kib = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let iterations = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
    if memory_kib > MAX_KDF_MEMORY_KIB || iterations > MAX_KDF_ITERATIONS {
        return Err(KeyStoreError::Decrypt);
    }
    let key = derive(
        pass,
        KdfCost {
            memory_kib,
            iterations,
        },
        &header[9..],
    )?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| KeyStoreError::Decrypt)?;
    let mut buf = Zeroizing::new(sealed.to_vec());
    let plain_len = aead(&key)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(header),
            &mut buf,
        )
        .map_err(|_| KeyStoreError::Decrypt)?
        .len();
    buf.truncate(plain_len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::CHEAP;
    use dnsy_dnssec::{Algorithm, SigningKey};

    #[test]
    fn pkcs8_encrypt_roundtrip() {
        let key = SigningKey::generate(Algorithm::Ed25519, false).unwrap();
        let der = key.to_pkcs8();
        let pass = Passphrase::new("correct horse");
        let blob = encrypt(&pass, CHEAP, &der).unwrap();
        assert!(!blob.windows(der.len()).any(|w| w == der.as_slice()));
        assert_eq!(decrypt(&pass, &blob).unwrap().as_slice(), der.as_slice());
        // Fresh salt and nonce per seal.
        assert_ne!(blob, encrypt(&pass, CHEAP, &der).unwrap());
    }

    #[test]
    fn wrong_passphrase_fails_cleanly() {
        let blob = encrypt(&Passphrase::new("right"), CHEAP, b"secret").unwrap();
        assert!(matches!(
            decrypt(&Passphrase::new("wrong"), &blob),
            Err(KeyStoreError::Decrypt)
        ));
        let pass = Passphrase::new("right");
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(matches!(
            decrypt(&pass, &tampered),
            Err(KeyStoreError::Decrypt)
        ));
        let mut header = blob.clone();
        header[8] ^= 1;
        assert!(matches!(
            decrypt(&pass, &header),
            Err(KeyStoreError::Decrypt)
        ));
        assert!(matches!(
            decrypt(&pass, &blob[..10]),
            Err(KeyStoreError::Decrypt)
        ));
        let mut greedy = blob;
        greedy[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decrypt(&pass, &greedy),
            Err(KeyStoreError::Decrypt)
        ));
        let msg = KeyStoreError::Decrypt.to_string();
        assert!(!msg.contains("right") && !msg.contains("secret"));
    }
}
