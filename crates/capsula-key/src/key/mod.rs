use std::{fs, path::Path};

use capsula_crypto::{ed25519::Ed25519, x25519::X25519};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// A unified key structure that combines Ed25519 and X25519 keys
/// derived from the same seed for both signing and key exchange
pub struct Key {
    pub ed25519: Ed25519,
    pub x25519: X25519,
}

impl Key {
    /// Generate a new key pair from a random seed
    pub fn generate() -> Self {
        // Generate a 32-byte seed
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("failed to generate random bytes");

        Self::from_seed(&seed)
    }

    /// Create a key pair from a 32-byte seed
    ///
    /// Both Ed25519 and X25519 keys are derived from the same seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // Create Ed25519 key from seed
        let ed25519 = Ed25519::from_raw_seed(seed);

        // Derive X25519 seed from Ed25519 seed using SHA256
        // This ensures both keys are related but cryptographically independent
        let mut hasher = Sha256::new();
        hasher.update(b"capsula-x25519-derivation");
        hasher.update(seed);
        let x25519_seed: [u8; 32] = hasher.finalize().into();

        let x25519 = X25519::from_raw_seed(&x25519_seed);

        Self { ed25519, x25519 }
    }

    /// Import key from PEM-encoded Ed25519 private key
    ///
    /// X25519 key will be derived from the Ed25519 key
    pub fn from_pem(pem: &str) -> Result<Self> {
        let ed25519 = Ed25519::from_pem(pem)
            .map_err(|e| Error::ImportError(format!("Failed to import Ed25519 key: {}", e)))?;

        // Derive X25519 from Ed25519 private key bytes
        let ed25519_bytes = ed25519.to_seed_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"capsula-x25519-derivation");
        hasher.update(ed25519_bytes);
        let x25519_seed: [u8; 32] = hasher.finalize().into();

        let x25519 = X25519::from_raw_seed(&x25519_seed);

        Ok(Self { ed25519, x25519 })
    }

    /// Export the Ed25519 private key to PEM format
    pub fn to_pem(&self) -> Result<String> {
        self.ed25519
            .to_pkcs8_pem()
            .map_err(|e| Error::ExportError(format!("Failed to export Ed25519 key: {}", e)))
    }

    /// Get the Ed25519 public key
    pub fn ed25519_public_key(&self) -> VerifyingKey {
        self.ed25519.public_key()
    }

    /// Get the X25519 public key bytes
    pub fn x25519_public_key(&self) -> [u8; 32] {
        self.x25519.public_key().to_bytes()
    }

    /// Sign a message using Ed25519
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.ed25519.sign(message)
    }

    /// Verify an Ed25519 signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let public_key = self.ed25519_public_key();
        capsula_crypto::ed25519::verify(&public_key.to_bytes(), message, signature)
    }

    /// Compute X25519 shared secret with another party's public key
    pub fn compute_shared_secret(&self, their_public_key: &[u8; 32]) -> [u8; 32] {
        self.x25519.compute_shared_secret(their_public_key)
    }

    /// Get a unique identifier for this key (first 8 bytes of SHA256 of public keys)
    pub fn key_id(&self) -> [u8; 8] {
        let mut hasher = Sha256::new();
        hasher.update(self.ed25519_public_key().to_bytes());
        hasher.update(self.x25519_public_key());
        let hash = hasher.finalize();
        let mut id = [0u8; 8];
        id.copy_from_slice(&hash[.. 8]);
        id
    }

    /// Get a hex-encoded key ID
    pub fn key_id_hex(&self) -> String {
        hex::encode(self.key_id())
    }

    /// Save the private key to a PEM file
    ///
    /// # Arguments
    /// * `path` - Path to the file where the key will be saved
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let pem = self.to_pem()?;
        fs::write(path, pem).map_err(Error::IoError)
    }

    /// Load a private key from a PEM file
    ///
    /// # Arguments
    /// * `path` - Path to the PEM file
    ///
    /// # Returns
    /// Key instance loaded from the file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let pem = fs::read_to_string(path).map_err(Error::IoError)?;
        Self::from_pem(&pem)
    }

    /// Export the Ed25519 public key to PEM format
    pub fn export_ed25519_public_key_to_pem(&self) -> Result<String> {
        self.ed25519
            .to_spki_pem()
            .map_err(|e| Error::ExportError(format!("Failed to export Ed25519 public key: {}", e)))
    }

    /// Export the X25519 public key to PEM format
    pub fn export_x25519_public_key_to_pem(&self) -> Result<String> {
        self.x25519
            .to_spki_pem()
            .map_err(|e| Error::ExportError(format!("Failed to export X25519 public key: {}", e)))
    }

    /// Save the Ed25519 public key to a PEM file
    ///
    /// # Arguments
    /// * `path` - Path to the file where the public key will be saved
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn save_ed25519_public_key_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let pem = self.export_ed25519_public_key_to_pem()?;
        fs::write(path, pem).map_err(Error::IoError)
    }

    /// Save the X25519 public key to a PEM file
    ///
    /// # Arguments
    /// * `path` - Path to the file where the public key will be saved
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn save_x25519_public_key_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let pem = self.export_x25519_public_key_to_pem()?;
        fs::write(path, pem).map_err(Error::IoError)
    }

    /// Save the public key information to a JSON file (for backward compatibility)
    ///
    /// # Arguments
    /// * `path` - Path to the file where the public key info will be saved
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn save_public_key_info_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let public_info = PublicKeyInfo::from(self);
        let json = serde_json::to_string_pretty(&public_info)
            .map_err(|e| Error::EncodingError(format!("Failed to serialize public key: {}", e)))?;
        fs::write(path, json).map_err(Error::IoError)
    }

    /// Load public key information from a JSON file
    ///
    /// # Arguments
    /// * `path` - Path to the JSON file
    ///
    /// # Returns
    /// PublicKeyInfo loaded from the file
    pub fn load_public_key_info_from_file<P: AsRef<Path>>(path: P) -> Result<PublicKeyInfo> {
        let json = fs::read_to_string(path).map_err(Error::IoError)?;
        serde_json::from_str(&json)
            .map_err(|e| Error::EncodingError(format!("Failed to deserialize public key: {}", e)))
    }
}

/// Public key information that can be shared
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub ed25519: [u8; 32],
    pub x25519: [u8; 32],
    pub key_id: String,
}

impl From<&Key> for PublicKeyInfo {
    fn from(key: &Key) -> Self {
        Self {
            ed25519: key.ed25519_public_key().to_bytes(),
            x25519: key.x25519_public_key(),
            key_id: key.key_id_hex(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = Key::generate();

        // Test signing
        let message = b"test message";
        let signature = key.sign(message);
        assert!(key.verify(message, &signature));

        // Test key exchange
        let key2 = Key::generate();
        let shared1 = key.compute_shared_secret(&key2.x25519_public_key());
        let shared2 = key2.compute_shared_secret(&key.x25519_public_key());
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_key_from_seed() {
        let seed = [42u8; 32];
        let key1 = Key::from_seed(&seed);
        let key2 = Key::from_seed(&seed);

        // Same seed should produce same keys
        assert_eq!(key1.ed25519.to_seed_bytes(), key2.ed25519.to_seed_bytes());
        assert_eq!(key1.x25519.to_bytes(), key2.x25519.to_bytes());
    }

    #[test]
    fn test_pem_export_import() {
        let key = Key::generate();
        let pem = key.to_pem().unwrap();
        let imported_key = Key::from_pem(&pem).unwrap();

        // Ed25519 keys should match
        assert_eq!(
            key.ed25519.to_seed_bytes(),
            imported_key.ed25519.to_seed_bytes()
        );

        // X25519 keys should also match (derived deterministically)
        assert_eq!(key.x25519.to_bytes(), imported_key.x25519.to_bytes());
    }

    #[test]
    fn test_file_operations() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.pem");
        let ed25519_pub_path = dir.path().join("test_ed25519.pub.pem");
        let x25519_pub_path = dir.path().join("test_x25519.pub.pem");
        let info_path = dir.path().join("test.pub.json");

        // Generate and save key
        let key = Key::generate();
        key.save_to_file(&key_path).unwrap();
        key.save_ed25519_public_key_to_file(&ed25519_pub_path)
            .unwrap();
        key.save_x25519_public_key_to_file(&x25519_pub_path)
            .unwrap();
        key.save_public_key_info_to_file(&info_path).unwrap();

        // Load key back
        let loaded_key = Key::load_from_file(&key_path).unwrap();
        let loaded_info = Key::load_public_key_info_from_file(&info_path).unwrap();

        // Verify keys match
        assert_eq!(
            key.ed25519.to_seed_bytes(),
            loaded_key.ed25519.to_seed_bytes()
        );
        assert_eq!(key.x25519.to_bytes(), loaded_key.x25519.to_bytes());
        assert_eq!(key.key_id_hex(), loaded_info.key_id);

        // Verify PEM files were created
        assert!(ed25519_pub_path.exists());
        assert!(x25519_pub_path.exists());
    }
}
