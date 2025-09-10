//! AES-GCM authenticated encryption
//!
//! Provides AEAD encryption using AES-GCM algorithm with 256-bit keys.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

use crate::error::{Error, Result};

/// AES-256-GCM cipher wrapper
pub struct Aes {
    cipher: Aes256Gcm,
}

impl Aes {
    /// Create a new AES-256-GCM cipher from a 32-byte key
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        Ok(Self { cipher })
    }

    /// Encrypt data with AES-256-GCM
    ///
    /// Returns encrypted data with 12-byte nonce prepended
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate random nonce (12 bytes for AES-GCM)
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Encrypt the plaintext
        let ciphertext = self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| Error::Other(format!("AES-GCM encryption failed: {}", e)))?;
        
        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    /// Decrypt data with AES-256-GCM
    ///
    /// Expects encrypted data with 12-byte nonce prepended
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        // Check minimum length (12 bytes nonce + at least 16 bytes auth tag)
        if encrypted_data.len() < 28 {
            return Err(Error::Other("Encrypted data too short for AES-GCM".to_string()));
        }
        
        // Extract nonce from the first 12 bytes
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt the ciphertext
        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| Error::Other(format!("AES-GCM decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }
}

/// Encrypt data using AES-256-GCM with a one-time key
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Encrypted data with 12-byte nonce prepended
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let aes = Aes::new(key)?;
    aes.encrypt(plaintext)
}

/// Decrypt data using AES-256-GCM with a one-time key
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `encrypted_data` - Encrypted data with 12-byte nonce prepended
///
/// # Returns
/// Decrypted plaintext
pub fn decrypt(key: &[u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    let aes = Aes::new(key)?;
    aes.decrypt(encrypted_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let plaintext = b"Hello, AES-256-GCM!";
        
        // Test standalone functions
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
        
        // Test struct methods
        let aes = Aes::new(&key).unwrap();
        let encrypted = aes.encrypt(plaintext).unwrap();
        let decrypted = aes.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}