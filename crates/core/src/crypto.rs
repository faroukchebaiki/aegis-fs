use std::fmt;

use aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

pub const MASTER_KEY_LEN: usize = 32;
pub const FILE_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("encryption failure")]
    Encrypt,
    #[error("decryption failure")]
    Decrypt,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

#[must_use]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0_u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[must_use]
pub fn random_key() -> [u8; MASTER_KEY_LEN] {
    let mut key = [0_u8; MASTER_KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

#[must_use]
pub fn random_nonce() -> [u8; AEAD_NONCE_LEN] {
    let mut nonce = [0_u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[must_use]
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0_u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives a master key from the provided password and salt using Argon2id.
///
/// # Errors
/// Returns an error if key derivation fails.
pub fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<[u8; MASTER_KEY_LEN]> {
    let mut master_key = [0_u8; MASTER_KEY_LEN];
    let argon = Argon2::default();
    argon
        .hash_password_into(password, salt, &mut master_key)
        .map_err(|err| CryptoError::KeyDerivation(err.to_string()))?;
    Ok(master_key)
}

/// Derives a per-file wrapping key from the master key and context string.
///
/// # Panics
/// Panics if HKDF expansion fails, which should not occur with the configured parameters.
#[must_use]
pub fn derive_wrapping_key(
    master_key: &[u8; MASTER_KEY_LEN],
    context: &[u8],
) -> [u8; FILE_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(master_key), context);
    let mut derived = [0_u8; FILE_KEY_LEN];
    hk.expand(b"aegis-fs:file-key", &mut derived)
        .expect("hkdf expand");
    derived
}

/// Encrypts the plaintext using AES-256-GCM.
///
/// # Errors
/// Returns an error if encryption fails.
pub fn encrypt(
    key: &[u8; MASTER_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encrypt)
}

/// Decrypts the ciphertext using AES-256-GCM.
///
/// # Errors
/// Returns an error if authentication fails.
pub fn decrypt(
    key: &[u8; MASTER_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let nonce = Nonce::from_slice(nonce);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Decrypt)
}

/// Wraps a file key using a derived wrapping key and AES-256-GCM.
///
/// # Errors
/// Returns an error if encryption fails.
pub fn wrap_file_key(
    master_key: &[u8; MASTER_KEY_LEN],
    file_id: &str,
    plain_key: &[u8; FILE_KEY_LEN],
) -> Result<WrappedKey> {
    let nonce = random_nonce();
    let mut wrapping_key = derive_wrapping_key(master_key, file_id.as_bytes());
    let ciphertext = encrypt(&wrapping_key, &nonce, plain_key)?;
    wrapping_key.zeroize();
    Ok(WrappedKey { nonce, ciphertext })
}

/// Unwraps a stored file key back into its plaintext bytes.
///
/// # Errors
/// Returns an error if decryption fails or the stored key length is invalid.
pub fn unwrap_file_key(
    master_key: &[u8; MASTER_KEY_LEN],
    file_id: &str,
    wrapped: &WrappedKey,
) -> Result<[u8; FILE_KEY_LEN]> {
    let mut wrapping_key = derive_wrapping_key(master_key, file_id.as_bytes());
    let plaintext = decrypt(&wrapping_key, &wrapped.nonce, &wrapped.ciphertext)?;
    wrapping_key.zeroize();
    if plaintext.len() != FILE_KEY_LEN {
        return Err(CryptoError::Decrypt);
    }
    let mut key = [0_u8; FILE_KEY_LEN];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

#[derive(Clone)]
pub struct WrappedKey {
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedKey")
            .field("nonce", &BASE64.encode(self.nonce))
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl WrappedKey {
    #[must_use]
    pub fn to_base64(&self) -> (String, String) {
        (BASE64.encode(self.nonce), BASE64.encode(&self.ciphertext))
    }

    /// Reconstructs a wrapped key from base64-encoded components.
    ///
    /// # Errors
    /// Returns an error if decoding fails or if the nonce length is invalid.
    pub fn from_base64(nonce_b64: &str, cipher_b64: &str) -> Result<Self> {
        let nonce_vec = BASE64.decode(nonce_b64).map_err(|_| CryptoError::Decrypt)?;
        if nonce_vec.len() != AEAD_NONCE_LEN {
            return Err(CryptoError::Decrypt);
        }
        let mut nonce = [0_u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&nonce_vec);
        let ciphertext = BASE64
            .decode(cipher_b64)
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(Self { nonce, ciphertext })
    }
}

#[must_use]
/// Calculates the BLAKE3 digest of the supplied data.
pub fn blake3_checksum(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

#[must_use]
/// Calculates the BLAKE3 digest and renders it as a lowercase hexadecimal string.
pub fn blake3_checksum_hex(data: &[u8]) -> String {
    let hash = blake3_checksum(data);
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = random_key();
        let nonce = random_nonce();
        let message = b"hello world";

        let ciphertext = encrypt(&key, &nonce, message).expect("encrypt");
        assert_ne!(ciphertext, message);

        let decrypted = decrypt(&key, &nonce, &ciphertext).expect("decrypt");
        assert_eq!(decrypted, message);
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let key = random_key();
        let nonce = random_nonce();
        let plaintext = b"secure payload";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).expect("encrypt");
        ciphertext[0] ^= 0xFF;

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn wrapped_key_round_trip() {
        let master_key = random_key();
        let file_key = random_key();
        let wrapped = wrap_file_key(&master_key, "file-id", &file_key).expect("wrap");
        let restored = unwrap_file_key(&master_key, "file-id", &wrapped).expect("unwrap");
        assert_eq!(restored, file_key);
    }
}
