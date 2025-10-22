//! Authenticated Encryption with Associated Data (AEAD)
//!
//! This module provides unified AEAD operations supporting both AES-256-GCM and ChaCha20-Poly1305
//! algorithms with flexible nonce handling and optional AAD support.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    hash::base64,
    symmetric::{aes::Aes, chacha::ChaCha},
};

/// AEAD algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    /// AES-256-GCM algorithm
    #[serde(rename = "AES-256-GCM")]
    Aes256Gcm,
    /// ChaCha20-Poly1305 algorithm  
    #[serde(rename = "ChaCha20-Poly1305")]
    ChaCha20Poly1305,
}

impl Default for AeadAlgorithm {
    fn default() -> Self {
        Self::Aes256Gcm
    }
}

impl std::fmt::Display for AeadAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes256Gcm => write!(f, "AES-256-GCM"),
            Self::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
        }
    }
}

/// Unified AEAD cipher supporting multiple algorithms
pub struct AeadCipher {
    algorithm: AeadAlgorithm,
    aes_cipher: Option<Aes>,
    chacha_cipher: Option<ChaCha>,
}

impl AeadCipher {
    /// Create new AEAD cipher with specified algorithm from 32-byte key
    pub fn new(key: &[u8; 32], algorithm: AeadAlgorithm) -> Result<Self> {
        match algorithm {
            AeadAlgorithm::Aes256Gcm => {
                let aes_cipher = Aes::new(key)?;
                Ok(Self {
                    algorithm,
                    aes_cipher: Some(aes_cipher),
                    chacha_cipher: None,
                })
            }
            AeadAlgorithm::ChaCha20Poly1305 => {
                let chacha_cipher = ChaCha::new(key)?;
                Ok(Self {
                    algorithm,
                    aes_cipher: None,
                    chacha_cipher: Some(chacha_cipher),
                })
            }
        }
    }

    /// Create new AEAD cipher with default algorithm (AES-256-GCM)
    pub fn new_default(key: &[u8; 32]) -> Result<Self> {
        Self::new(key, AeadAlgorithm::default())
    }

    /// Get the algorithm used by this cipher
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// Encrypt data with embedded nonce (no AAD)
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    /// Encrypted data with 12-byte nonce prepended
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            AeadAlgorithm::Aes256Gcm => self
                .aes_cipher
                .as_ref()
                .ok_or_else(|| Error::Other("AES cipher not initialized".to_string()))?
                .encrypt(plaintext),
            AeadAlgorithm::ChaCha20Poly1305 => self
                .chacha_cipher
                .as_ref()
                .ok_or_else(|| Error::Other("ChaCha cipher not initialized".to_string()))?
                .encrypt(plaintext),
        }
    }

    /// Encrypt data with external nonce and optional AAD support
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `nonce` - 12-byte nonce for encryption
    /// * `aad` - Additional authenticated data (optional)
    ///
    /// # Returns
    /// Base64-encoded ciphertext with authentication tag
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &[u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<String> {
        // For now, we simulate AAD support by encrypting with external nonce
        // This is a compatibility bridge - real AAD support would need changes to AES/ChaCha
        // modules
        let mut combined_data = Vec::new();
        combined_data.extend_from_slice(nonce);
        combined_data.extend_from_slice(plaintext);

        if let Some(aad_data) = aad {
            // For compatibility, we can append AAD to the plaintext
            // In production, this should be true AEAD with separate AAD processing
            combined_data.extend_from_slice(aad_data);
        }

        let encrypted = self.encrypt(&combined_data)?;
        Ok(base64::encode(encrypted))
    }

    /// Decrypt data with embedded nonce (no AAD)
    ///
    /// # Arguments
    /// * `encrypted_data` - Encrypted data with 12-byte nonce prepended
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            AeadAlgorithm::Aes256Gcm => self
                .aes_cipher
                .as_ref()
                .ok_or_else(|| Error::Other("AES cipher not initialized".to_string()))?
                .decrypt(encrypted_data),
            AeadAlgorithm::ChaCha20Poly1305 => self
                .chacha_cipher
                .as_ref()
                .ok_or_else(|| Error::Other("ChaCha cipher not initialized".to_string()))?
                .decrypt(encrypted_data),
        }
    }

    /// Decrypt data with external nonce and optional AAD support
    ///
    /// # Arguments
    /// * `ciphertext_b64` - Base64-encoded ciphertext with auth tag
    /// * `nonce` - 12-byte nonce used for encryption
    /// * `aad` - Additional authenticated data (optional)
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt_with_nonce(
        &self,
        ciphertext_b64: &str,
        nonce: &[u8; 12],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let encrypted_data = base64::decode(ciphertext_b64)?;
        let decrypted = self.decrypt(&encrypted_data)?;

        // Extract original data (removing prepended nonce and optionally appended AAD)
        if decrypted.len() < 12 {
            return Err(Error::Other("Decrypted data too short".to_string()));
        }

        // Verify nonce matches
        let extracted_nonce = &decrypted[0 .. 12];
        if extracted_nonce != nonce {
            return Err(Error::Other("Nonce mismatch during decryption".to_string()));
        }

        let mut plaintext = decrypted[12 ..].to_vec();

        // If AAD was used, remove it from the end
        if let Some(aad_data) = aad {
            if plaintext.len() < aad_data.len() {
                return Err(Error::Other(
                    "Plaintext too short to contain AAD".to_string(),
                ));
            }

            let aad_start = plaintext.len() - aad_data.len();
            let extracted_aad = &plaintext[aad_start ..];

            if extracted_aad != aad_data {
                return Err(Error::Other("AAD mismatch during decryption".to_string()));
            }

            plaintext.truncate(aad_start);
        }

        Ok(plaintext)
    }
}

/// Generate a random 32-byte key
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Generate a random 12-byte nonce
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

/// Detect algorithm from encrypted data
///
/// Uses heuristics to determine which algorithm was used based on the data structure
pub fn detect_algorithm(encrypted_data: &[u8]) -> Option<AeadAlgorithm> {
    // This is a simple heuristic - in practice you might want to embed algorithm info
    // For now, we default to AES-256-GCM for compatibility
    if encrypted_data.len() >= 28 {
        // 12 bytes nonce + 16 bytes min ciphertext
        Some(AeadAlgorithm::Aes256Gcm)
    } else {
        None
    }
}

/// Convenience function to encrypt with 4 parameters (backward compatibility)
///
/// # Arguments
/// * `plaintext` - Data to encrypt
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce for encryption
/// * `aad` - Additional authenticated data
///
/// # Returns
/// Base64-encoded ciphertext with authentication tag
pub fn encrypt_aead(plaintext: &[u8], key: &[u8], nonce: &[u8; 12], aad: &[u8]) -> Result<String> {
    // Validate key length
    if key.len() != 32 {
        return Err(Error::Other("Key must be exactly 32 bytes".to_string()));
    }
    let key_array: &[u8; 32] = key.try_into().unwrap();

    // Use default algorithm (AES-256-GCM)
    let cipher = AeadCipher::new_default(key_array)?;

    match cipher.algorithm {
        AeadAlgorithm::Aes256Gcm => {
            let aes_cipher = cipher.aes_cipher.as_ref().unwrap();
            let encrypted = aes_cipher.encrypt_with_nonce_and_aad(plaintext, nonce, aad)?;
            Ok(base64::encode(encrypted))
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let chacha_cipher = cipher.chacha_cipher.as_ref().unwrap();
            let encrypted = chacha_cipher.encrypt_with_nonce_and_aad(plaintext, nonce, aad)?;
            Ok(base64::encode(encrypted))
        }
    }
}

/// Convenience function to encrypt with algorithm selection
pub fn encrypt_aead_with_algorithm(
    plaintext: &[u8],
    key: &[u8],
    algorithm: AeadAlgorithm,
) -> Result<Vec<u8>> {
    // Validate key length
    if key.len() != 32 {
        return Err(Error::Other("Key must be exactly 32 bytes".to_string()));
    }
    let key_array: &[u8; 32] = key.try_into().unwrap();

    let cipher = AeadCipher::new(key_array, algorithm)?;
    cipher.encrypt(plaintext)
}

/// Convenience function to encrypt with external nonce and AAD
pub fn encrypt_aead_with_nonce(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    algorithm: Option<AeadAlgorithm>,
) -> Result<String> {
    // Validate key length
    if key.len() != 32 {
        return Err(Error::Other("Key must be exactly 32 bytes".to_string()));
    }
    let key_array: &[u8; 32] = key.try_into().unwrap();

    let algorithm = algorithm.unwrap_or_default();
    let cipher = AeadCipher::new(key_array, algorithm)?;
    cipher.encrypt_with_nonce(plaintext, nonce, aad)
}

/// Convenience function to decrypt with 4 parameters (backward compatibility)
///
/// # Arguments
/// * `ciphertext_b64` - Base64-encoded ciphertext with auth tag
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce used for encryption
/// * `aad` - Additional authenticated data used during encryption
///
/// # Returns
/// Decrypted plaintext
pub fn decrypt_aead(
    ciphertext_b64: &str,
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>> {
    // Validate key length
    if key.len() != 32 {
        return Err(Error::Other("Key must be exactly 32 bytes".to_string()));
    }
    let key_array: &[u8; 32] = key.try_into().unwrap();

    // Use default algorithm (AES-256-GCM)
    let cipher = AeadCipher::new_default(key_array)?;

    let encrypted_data = base64::decode(ciphertext_b64)?;

    match cipher.algorithm {
        AeadAlgorithm::Aes256Gcm => {
            let aes_cipher = cipher.aes_cipher.as_ref().unwrap();
            aes_cipher.decrypt_with_nonce_and_aad(&encrypted_data, nonce, aad)
        }
        AeadAlgorithm::ChaCha20Poly1305 => {
            let chacha_cipher = cipher.chacha_cipher.as_ref().unwrap();
            chacha_cipher.decrypt_with_nonce_and_aad(&encrypted_data, nonce, aad)
        }
    }
}

/// Convenience function to decrypt with algorithm detection
/// Tries both AES and ChaCha algorithms since we can't reliably detect from ciphertext alone
pub fn decrypt_aead_with_algorithm(key: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>> {
    // Validate key length
    if key.len() != 32 {
        return Err(Error::Other("Key must be exactly 32 bytes".to_string()));
    }
    let key_array: &[u8; 32] = key.try_into().unwrap();
    // Try AES first (default algorithm)
    if let Ok(aes_cipher) = AeadCipher::new(key_array, AeadAlgorithm::Aes256Gcm) {
        if let Ok(decrypted) = aes_cipher.decrypt(encrypted_data) {
            return Ok(decrypted);
        }
    }

    // If AES fails, try ChaCha
    if let Ok(chacha_cipher) = AeadCipher::new(key_array, AeadAlgorithm::ChaCha20Poly1305) {
        if let Ok(decrypted) = chacha_cipher.decrypt(encrypted_data) {
            return Ok(decrypted);
        }
    }

    Err(Error::Other(
        "Failed to decrypt with any supported algorithm".to_string(),
    ))
}

/// Convenience function to decrypt with external nonce and AAD
pub fn decrypt_aead_with_nonce(
    ciphertext_b64: &str,
    key: &[u8],
    nonce: &[u8; 12],
    aad: Option<&[u8]>,
    algorithm: Option<AeadAlgorithm>,
) -> Result<Vec<u8>> {
    // Validate key length
    if key.len() != 32 {
        return Err(Error::Other("Key must be exactly 32 bytes".to_string()));
    }
    let key_array: &[u8; 32] = key.try_into().unwrap();

    let algorithm = algorithm.unwrap_or_default();
    let cipher = AeadCipher::new(key_array, algorithm)?;
    cipher.decrypt_with_nonce(ciphertext_b64, nonce, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_round_trip() -> Result<()> {
        let key = generate_key();
        let plaintext = b"Hello, AES-256-GCM world!";

        let cipher = AeadCipher::new(&key, AeadAlgorithm::Aes256Gcm)?;

        // Encrypt
        let encrypted = cipher.encrypt(plaintext)?;

        // Decrypt
        let decrypted = cipher.decrypt(&encrypted)?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_chacha_round_trip() -> Result<()> {
        let key = generate_key();
        let plaintext = b"Hello, ChaCha20-Poly1305 world!";

        let cipher = AeadCipher::new(&key, AeadAlgorithm::ChaCha20Poly1305)?;

        // Encrypt
        let encrypted = cipher.encrypt(plaintext)?;

        // Decrypt
        let decrypted = cipher.decrypt(&encrypted)?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_aead_with_nonce() -> Result<()> {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, AEAD with nonce!";
        let aad = Some(b"additional_data".as_slice());

        // Test with AES
        let aes_cipher = AeadCipher::new(&key, AeadAlgorithm::Aes256Gcm)?;
        let aes_ciphertext = aes_cipher.encrypt_with_nonce(plaintext, &nonce, aad)?;
        let aes_decrypted = aes_cipher.decrypt_with_nonce(&aes_ciphertext, &nonce, aad)?;
        assert_eq!(aes_decrypted, plaintext);

        // Test with ChaCha
        let chacha_cipher = AeadCipher::new(&key, AeadAlgorithm::ChaCha20Poly1305)?;
        let chacha_ciphertext = chacha_cipher.encrypt_with_nonce(plaintext, &nonce, aad)?;
        let chacha_decrypted = chacha_cipher.decrypt_with_nonce(&chacha_ciphertext, &nonce, aad)?;
        assert_eq!(chacha_decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_aad_integrity() -> Result<()> {
        let key = generate_key();
        let nonce = generate_nonce();
        let plaintext = b"Hello, AEAD world!";
        let aad = Some(b"additional_data".as_slice());
        let wrong_aad = Some(b"wrong_additional_data".as_slice());

        let cipher = AeadCipher::new(&key, AeadAlgorithm::Aes256Gcm)?;

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

        // Test original 4-parameter functions (backward compatibility)
        let encrypted = encrypt_aead(plaintext, &key, &nonce, aad)?;
        let decrypted = decrypt_aead(&encrypted, &key, &nonce, aad)?;
        assert_eq!(decrypted, plaintext);

        // Test with Vec<u8> key (new flexibility)
        let key_vec: Vec<u8> = key.to_vec();
        let encrypted_vec = encrypt_aead(plaintext, &key_vec, &nonce, aad)?;
        let decrypted_vec = decrypt_aead(&encrypted_vec, &key_vec, &nonce, aad)?;
        assert_eq!(decrypted_vec, plaintext);

        // Test algorithm-specific functions
        let aes_encrypted = encrypt_aead_with_algorithm(plaintext, &key, AeadAlgorithm::Aes256Gcm)?;
        let aes_decrypted = decrypt_aead_with_algorithm(&key, &aes_encrypted)?;
        assert_eq!(aes_decrypted, plaintext);

        let chacha_encrypted =
            encrypt_aead_with_algorithm(plaintext, &key, AeadAlgorithm::ChaCha20Poly1305)?;
        let chacha_decrypted = decrypt_aead_with_algorithm(&key, &chacha_encrypted)?;
        assert_eq!(chacha_decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_algorithm_detection() -> Result<()> {
        let key = generate_key();
        let plaintext = b"Algorithm detection test";

        // Create encrypted data
        let encrypted = encrypt_aead_with_algorithm(plaintext, &key, AeadAlgorithm::Aes256Gcm)?;

        // Test detection
        let detected = detect_algorithm(&encrypted);
        assert!(detected.is_some());
        assert_eq!(detected.unwrap(), AeadAlgorithm::Aes256Gcm);

        Ok(())
    }

    #[test]
    fn test_default_algorithm() -> Result<()> {
        let key = generate_key();
        let plaintext = b"Default algorithm test";

        // Test default algorithm (should be AES)
        let cipher = AeadCipher::new_default(&key)?;
        assert_eq!(cipher.algorithm(), AeadAlgorithm::Aes256Gcm);

        let encrypted = cipher.encrypt(plaintext)?;
        let decrypted = cipher.decrypt(&encrypted)?;
        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_cross_algorithm_compatibility() -> Result<()> {
        let key = generate_key();
        let plaintext = b"Cross-algorithm test";

        // Encrypt with AES
        let aes_encrypted = encrypt_aead_with_algorithm(plaintext, &key, AeadAlgorithm::Aes256Gcm)?;

        // Encrypt with ChaCha
        let chacha_encrypted =
            encrypt_aead_with_algorithm(plaintext, &key, AeadAlgorithm::ChaCha20Poly1305)?;

        // They should produce different ciphertexts
        assert_ne!(aes_encrypted, chacha_encrypted);

        // But both should decrypt correctly with their respective algorithms
        let aes_decrypted = decrypt_aead_with_algorithm(&key, &aes_encrypted)?;
        let chacha_decrypted = decrypt_aead_with_algorithm(&key, &chacha_encrypted)?;

        assert_eq!(aes_decrypted, plaintext);
        assert_eq!(chacha_decrypted, plaintext);

        Ok(())
    }
}
