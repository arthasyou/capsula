//! ChaCha20-Poly1305 authenticated encryption
//!
//! Provides AEAD encryption using ChaCha20-Poly1305 algorithm.

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::error::{Error, Result};

/// ChaCha20-Poly1305 cipher wrapper
pub struct ChaCha {
    cipher: ChaCha20Poly1305,
}

impl ChaCha {
    /// Create a new ChaCha20-Poly1305 cipher from a 32-byte key
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Ok(Self { cipher })
    }

    /// Encrypt data with ChaCha20-Poly1305 (auto-generated nonce)
    ///
    /// Returns encrypted data with 12-byte nonce prepended
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate random nonce (12 bytes for ChaCha20-Poly1305)
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Encrypt the plaintext
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| Error::Other(format!("ChaCha20-Poly1305 encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Encrypt data with ChaCha20-Poly1305 using external nonce and AAD
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `nonce` - 12-byte nonce for encryption
    /// * `aad` - Additional authenticated data (can be empty)
    ///
    /// # Returns
    /// Encrypted data with authentication tag, nonce NOT prepended
    pub fn encrypt_with_nonce_and_aad(
        &self,
        plaintext: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::AeadInPlace;

        let nonce = Nonce::from_slice(nonce);
        let mut buffer = plaintext.to_vec();

        // Encrypt in-place with AAD
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, aad, &mut buffer)
            .map_err(|e| {
                Error::Other(format!(
                    "ChaCha20-Poly1305 encryption with AAD failed: {}",
                    e
                ))
            })?;

        // Append authentication tag
        buffer.extend_from_slice(&tag);

        Ok(buffer)
    }

    /// Decrypt data with ChaCha20-Poly1305
    ///
    /// Expects encrypted data with 12-byte nonce prepended
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        // Check minimum length (12 bytes nonce + at least 16 bytes auth tag)
        if encrypted_data.len() < 28 {
            return Err(Error::Other(
                "Encrypted data too short for ChaCha20-Poly1305".to_string(),
            ));
        }

        // Extract nonce from the first 12 bytes
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the ciphertext
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::Other(format!("ChaCha20-Poly1305 decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    /// Decrypt data with ChaCha20-Poly1305 using external nonce and AAD
    ///
    /// # Arguments
    /// * `encrypted_data` - Encrypted data with authentication tag (no nonce prepended)
    /// * `nonce` - 12-byte nonce used for encryption
    /// * `aad` - Additional authenticated data used during encryption
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt_with_nonce_and_aad(
        &self,
        encrypted_data: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::AeadInPlace;

        if encrypted_data.len() < 16 {
            return Err(Error::Other(
                "Encrypted data too short for ChaCha20-Poly1305 tag".to_string(),
            ));
        }

        let nonce = Nonce::from_slice(nonce);

        // Separate ciphertext and authentication tag
        let tag_start = encrypted_data.len() - 16;
        let mut buffer = encrypted_data[.. tag_start].to_vec();
        let tag = &encrypted_data[tag_start ..];

        // Decrypt in-place with AAD
        self.cipher
            .decrypt_in_place_detached(&nonce, aad, &mut buffer, tag.into())
            .map_err(|e| {
                Error::Other(format!(
                    "ChaCha20-Poly1305 decryption with AAD failed: {}",
                    e
                ))
            })?;

        Ok(buffer)
    }
}

/// Encrypt data using ChaCha20-Poly1305 with a one-time key
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Encrypted data with 12-byte nonce prepended
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let chacha = ChaCha::new(key)?;
    chacha.encrypt(plaintext)
}

/// Decrypt data using ChaCha20-Poly1305 with a one-time key
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `encrypted_data` - Encrypted data with 12-byte nonce prepended
///
/// # Returns
/// Decrypted plaintext
pub fn decrypt(key: &[u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    let chacha = ChaCha::new(key)?;
    chacha.decrypt(encrypted_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let plaintext = b"Hello, ChaCha20-Poly1305!";

        // Test standalone functions
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // Test struct methods
        let chacha = ChaCha::new(&key).unwrap();
        let encrypted = chacha.encrypt(plaintext).unwrap();
        let decrypted = chacha.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
