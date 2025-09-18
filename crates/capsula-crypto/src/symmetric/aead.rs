//! Authenticated Encryption with Associated Data (AEAD)
//!
//! This module provides AEAD operations with separate nonce handling,
//! specifically designed for the Capsula project's encryption needs.

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

use crate::error::{Error, Result};
use crate::hash::base64;

/// AEAD cipher for Capsula protocol
pub struct AeadCipher {
    cipher: Aes256Gcm,
}

impl AeadCipher {
    /// Create new AEAD cipher from 32-byte key
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::Other("Key must be 32 bytes for AES-256".to_string()));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::Other("Invalid key for AES-256-GCM".to_string()))?;

        Ok(Self { cipher })
    }

    /// Encrypt data with associated data and return separate nonce and ciphertext
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `nonce` - 12-byte nonce for encryption
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    /// Base64-encoded ciphertext with authentication tag appended
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<String> {
        let nonce = Nonce::from_slice(nonce);
        let mut ciphertext = plaintext.to_vec();

        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, aad, &mut ciphertext)
            .map_err(|_| Error::Other("Encryption failed".to_string()))?;

        // Append authentication tag to ciphertext
        ciphertext.extend_from_slice(&tag);

        Ok(base64::encode(ciphertext))
    }

    /// Decrypt data with associated data using separate nonce
    ///
    /// # Arguments
    /// * `ciphertext_b64` - Base64-encoded ciphertext with auth tag
    /// * `nonce` - 12-byte nonce used for encryption
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt_with_nonce(
        &self,
        ciphertext_b64: &str,
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let encrypted_data = base64::decode(ciphertext_b64)?;

        if encrypted_data.len() < 16 {
            return Err(Error::Other("Ciphertext too short".to_string()));
        }

        // Separate ciphertext and authentication tag
        let tag_start = encrypted_data.len() - 16;
        let mut ciphertext = encrypted_data[.. tag_start].to_vec();
        let tag = &encrypted_data[tag_start ..];

        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt_in_place_detached(nonce, aad, &mut ciphertext, tag.into())
            .map_err(|_| Error::Other("Decryption failed".to_string()))?;

        Ok(ciphertext)
    }
}

/// Generate a random 32-byte key for AES-256
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Generate a random 12-byte nonce for AES-256-GCM
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate a random identifier with a given prefix
pub fn generate_id(prefix: &str) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 16] = rng.gen();
    format!("{}_{}", prefix, hex::encode(random_bytes))
}

/// Convenience function to encrypt with a new key and nonce
pub fn encrypt_aead(plaintext: &[u8], key: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Result<String> {
    let cipher = AeadCipher::new(key)?;
    cipher.encrypt_with_nonce(plaintext, nonce, aad)
}

/// Convenience function to decrypt with key and nonce
pub fn decrypt_aead(
    ciphertext_b64: &str,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = AeadCipher::new(key)?;
    cipher.decrypt_with_nonce(ciphertext_b64, nonce, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_round_trip() -> Result<()> {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, AEAD world!";
        let aad = b"additional_data";

        let cipher = AeadCipher::new(&key)?;

        // Encrypt
        let ciphertext = cipher.encrypt_with_nonce(plaintext, &nonce, aad)?;

        // Decrypt
        let decrypted = cipher.decrypt_with_nonce(&ciphertext, &nonce, aad)?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_aad_integrity() -> Result<()> {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, AEAD world!";
        let aad = b"additional_data";
        let wrong_aad = b"wrong_additional_data";

        let cipher = AeadCipher::new(&key)?;

        // Encrypt with correct AAD
        let ciphertext = cipher.encrypt_with_nonce(plaintext, &nonce, aad)?;

        // Try to decrypt with wrong AAD - should fail
        let result = cipher.decrypt_with_nonce(&ciphertext, &nonce, wrong_aad);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_convenience_functions() -> Result<()> {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, convenience!";
        let aad = b"additional_data";

        // Test convenience functions
        let ciphertext = encrypt_aead(plaintext, &key, &nonce, aad)?;
        let decrypted = decrypt_aead(&ciphertext, &key, &nonce, aad)?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }
}
