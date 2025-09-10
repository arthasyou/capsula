// Domain separation label for deriving the X25519 seed from the master seed
const X25519_DERIVE_LABEL: &[u8] = b"capsula-x25519-derivation-v1\0\0\0";

use std::{fs, path::Path};

pub use capsula_crypto::asymmetric::ed25519::verify;
use capsula_crypto::{derive_key32, sha256, Ed25519, X25519};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// ============================================================================
// Core Key Structure
// ============================================================================

/// A unified cryptographic key that combines Ed25519 and X25519 keys
///
/// This structure provides both signing (Ed25519) and key exchange (X25519)
/// capabilities derived from a common seed, ensuring cryptographic separation
/// while maintaining a single key identity.
///
/// # Examples
///
/// ```no_run
/// use capsula_key::key::{verify, Key};
///
/// // Generate a new random key
/// let key = Key::generate().unwrap();
///
/// // Sign a message
/// let message = b"Hello, World!";
/// let signature = key.sign(message);
/// assert!(verify(&key.ed25519_public_key_bytes(), message, &signature));
///
/// // Perform key exchange
/// let other_key = Key::generate().unwrap();
/// let shared_secret = key.compute_shared_secret(&other_key.x25519_public_key());
/// ```
pub struct Key {
    /// Ed25519 signing key
    ed25519: Ed25519,
    /// X25519 key exchange key
    x25519: X25519,
}

impl Key {
    // ========================================================================
    // Key Generation and Creation
    // ========================================================================

    /// Generate a new key pair with cryptographically secure randomness
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Other(e.to_string()))?;
        Ok(Self::from_seed(&seed))
    }

    /// Create a key pair from a 32-byte seed
    ///
    /// Both Ed25519 and X25519 keys are deterministically derived from the seed
    /// using domain separation to ensure cryptographic independence.
    ///
    /// # Arguments
    /// * `seed` - 32-byte seed material
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // Create Ed25519 key directly from seed
        let ed25519 = Ed25519::from_raw_seed(seed);

        // Derive X25519 seed using domain-separated hash
        let x25519_seed = Self::derive_x25519_seed(seed);
        let x25519 = X25519::from_raw_seed(&x25519_seed);

        Self { ed25519, x25519 }
    }

    /// Derive X25519 seed from master seed using domain separation
    fn derive_x25519_seed(seed: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(seed.len() + X25519_DERIVE_LABEL.len());
        data.extend_from_slice(X25519_DERIVE_LABEL);
        data.extend_from_slice(seed);
        sha256(&data)
    }

    // ========================================================================
    // Key Import/Export - PEM Format
    // ========================================================================

    /// Import key from PKCS#8 (PEM) encoded Ed25519 private key
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let ed25519 = Ed25519::from_pem(pem)
            .map_err(|e| Error::ImportError(format!("Failed to import Ed25519 key: {}", e)))?;

        // Derive X25519 from Ed25519 seed
        let ed25519_seed = ed25519.to_seed_bytes();
        let x25519_seed = Self::derive_x25519_seed(&ed25519_seed);
        let x25519 = X25519::from_raw_seed(&x25519_seed);

        Ok(Self { ed25519, x25519 })
    }

    /// Export the Ed25519 private key to PKCS#8 (PEM) format
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        self.ed25519
            .to_pkcs8_pem()
            .map_err(|e| Error::ExportError(format!("Failed to export Ed25519 key: {}", e)))
    }

    /// Export Ed25519 public key to SPKI (PEM) format
    pub fn ed25519_spki_pem(&self) -> Result<String> {
        self.ed25519
            .to_spki_pem()
            .map_err(|e| Error::ExportError(format!("Failed to export Ed25519 public key: {}", e)))
    }

    /// Export X25519 public key to SPKI (PEM) format
    pub fn x25519_spki_pem(&self) -> Result<String> {
        self.x25519
            .to_spki_pem()
            .map_err(|e| Error::ExportError(format!("Failed to export X25519 public key: {}", e)))
    }

    // ========================================================================
    // Key Import/Export - DER Format
    // ========================================================================

    /// Import key from PKCS#8 (DER) encoded Ed25519 private key
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let ed25519 = Ed25519::from_pkcs8_der(der).map_err(|e| {
            Error::ImportError(format!("Failed to import Ed25519 key from DER: {}", e))
        })?;

        let ed25519_seed = ed25519.to_seed_bytes();
        let x25519_seed = Self::derive_x25519_seed(&ed25519_seed);
        let x25519 = X25519::from_raw_seed(&x25519_seed);

        Ok(Self { ed25519, x25519 })
    }

    /// Export the Ed25519 private key to PKCS#8 (DER) format
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        self.ed25519
            .to_pkcs8_der()
            .map_err(|e| Error::ExportError(format!("Failed to export Ed25519 key to DER: {}", e)))
    }

    /// Export Ed25519 public key to SPKI (DER)
    pub fn ed25519_spki_der(&self) -> Result<Vec<u8>> {
        self.ed25519.to_spki_der().map_err(|e| {
            Error::ExportError(format!("Failed to export Ed25519 public key (DER): {}", e))
        })
    }

    /// Export X25519 public key to SPKI (DER)
    pub fn x25519_spki_der(&self) -> Result<Vec<u8>> {
        self.x25519.to_spki_der().map_err(|e| {
            Error::ExportError(format!("Failed to export X25519 public key (DER): {}", e))
        })
    }

    /// SHA-256 fingerprint of the Ed25519 SPKI (DER)
    pub fn ed25519_spki_fingerprint_sha256(&self) -> Result<[u8; 32]> {
        let spki = self.ed25519_spki_der()?;
        Ok(sha256(&spki))
    }

    /// SHA-256 fingerprint of the X25519 SPKI (DER)
    pub fn x25519_spki_fingerprint_sha256(&self) -> Result<[u8; 32]> {
        let spki = self.x25519_spki_der()?;
        Ok(sha256(&spki))
    }

    // ========================================================================
    // Public Key Access
    // ========================================================================

    /// Get the Ed25519 public key
    pub fn ed25519_public_key(&self) -> VerifyingKey {
        self.ed25519.public_key()
    }

    /// Get the Ed25519 public key as bytes
    pub fn ed25519_public_key_bytes(&self) -> [u8; 32] {
        self.ed25519_public_key().to_bytes()
    }

    /// Get the X25519 public key as bytes
    pub fn x25519_public_key(&self) -> [u8; 32] {
        self.x25519.public_key().to_bytes()
    }

    // ========================================================================
    // Cryptographic Operations
    // ========================================================================

    /// Sign a message using Ed25519
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.ed25519.sign(message)
    }

    /// Compute X25519 shared secret with another party's public key
    pub fn compute_shared_secret(&self, their_public_key: &[u8; 32]) -> [u8; 32] {
        self.x25519.compute_shared_secret(their_public_key)
    }

    /// Derive a 32-byte session key from the X25519 shared secret using HKDF-SHA256
    pub fn derive_session_key_hkdf(
        &self,
        their_public_key: &[u8; 32],
        salt: &[u8],
        info: &[u8],
    ) -> [u8; 32] {
        let shared_secret = self.compute_shared_secret(their_public_key);
        derive_key32(&shared_secret, salt, info)
    }

    // ========================================================================
    // Key Identification
    // ========================================================================

    /// Concatenate Ed25519 and X25519 public keys (64 bytes total)
    fn concat_public_keys(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[.. 32].copy_from_slice(&self.ed25519_public_key_bytes());
        buf[32 ..].copy_from_slice(&self.x25519_public_key());
        buf
    }

    /// Get a unique identifier for this key
    ///
    /// The key ID is the first 8 bytes of the fingerprint (SHA-256 of public keys)
    pub fn key_id(&self) -> [u8; 8] {
        let fp = self.fingerprint();
        let mut id = [0u8; 8];
        id.copy_from_slice(&fp[.. 8]);
        id
    }

    /// Get a hex-encoded key ID
    pub fn key_id_hex(&self) -> String {
        hex::encode(self.key_id())
    }

    /// SHA-256 fingerprint of the concatenated public keys (Ed25519 || X25519)
    pub fn fingerprint(&self) -> [u8; 32] {
        sha256(&self.concat_public_keys())
    }

    /// Hex-encoded SHA-256 fingerprint
    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint())
    }

    // ========================================================================
    // File I/O Operations
    // ========================================================================

    /// Save the private key (PKCS#8 PEM) to a file
    pub fn save_pkcs8_pem_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let pem = self.to_pkcs8_pem()?;
        fs::write(path, pem).map_err(Error::IoError)
    }

    /// Load the private key (PKCS#8 PEM) from a file
    pub fn load_pkcs8_pem_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let pem = fs::read_to_string(path).map_err(Error::IoError)?;
        Self::from_pkcs8_pem(&pem)
    }

    /// Save the private key (PKCS#8 DER) to a file
    pub fn save_pkcs8_der_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let der = self.to_pkcs8_der()?;
        fs::write(path, der).map_err(Error::IoError)
    }

    /// Load the private key (PKCS#8 DER) from a file
    pub fn load_pkcs8_der_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let der = fs::read(path).map_err(Error::IoError)?;
        Self::from_pkcs8_der(&der)
    }

    /// Save SPKI (PEM) public keys to files
    pub fn save_spki_public_keys<P: AsRef<Path>>(
        &self,
        ed25519_path: P,
        x25519_path: P,
    ) -> Result<()> {
        let ed25519_pem = self.ed25519_spki_pem()?;
        let x25519_pem = self.x25519_spki_pem()?;

        fs::write(ed25519_path, ed25519_pem).map_err(Error::IoError)?;
        fs::write(x25519_path, x25519_pem).map_err(Error::IoError)?;

        Ok(())
    }

    /// Save public key info as JSON (for compatibility)
    pub fn save_public_key_info<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let info = PublicKeyInfo::from(self);
        let json = serde_json::to_string_pretty(&info).map_err(|e| {
            Error::EncodingError(format!("Failed to serialize public key info: {}", e))
        })?;
        fs::write(path, json).map_err(Error::IoError)
    }

    /// Load public key info from JSON file
    pub fn load_public_key_info<P: AsRef<Path>>(path: P) -> Result<PublicKeyInfo> {
        let json = fs::read_to_string(path).map_err(Error::IoError)?;
        serde_json::from_str(&json).map_err(|e| {
            Error::EncodingError(format!("Failed to deserialize public key info: {}", e))
        })
    }
}

// ============================================================================
// Public Key Information
// ============================================================================

/// Public key information that can be shared
///
/// This structure contains both public keys and the key ID,
/// suitable for distribution and key exchange protocols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// Ed25519 public key (32 bytes)
    pub ed25519: [u8; 32],
    /// X25519 public key (32 bytes)  
    pub x25519: [u8; 32],
    /// Hex-encoded key ID
    pub key_id: String,
    /// Optional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<KeyMetadata>,
}

/// Optional metadata for key identification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyMetadata {
    /// Human-readable name for the key
    pub name: Option<String>,
    /// Email associated with the key
    pub email: Option<String>,
    /// Key creation timestamp (Unix timestamp)
    pub created_at: Option<u64>,
    /// Key expiration timestamp (Unix timestamp)
    pub expires_at: Option<u64>,
}

impl From<&Key> for PublicKeyInfo {
    fn from(key: &Key) -> Self {
        Self {
            ed25519: key.ed25519_public_key_bytes(),
            x25519: key.x25519_public_key(),
            key_id: key.key_id_hex(),
            metadata: None,
        }
    }
}

impl PublicKeyInfo {
    /// Create with metadata
    pub fn with_metadata(key: &Key, metadata: KeyMetadata) -> Self {
        let mut info = Self::from(key);
        info.metadata = Some(metadata);
        info
    }

    /// Verify a signature using the Ed25519 public key
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        verify(&self.ed25519, message, signature)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_key_generation() {
        let key = Key::generate().unwrap();
        let pub_key = key.ed25519_public_key_bytes();

        // Test signing
        let message = b"test message";
        let signature = key.sign(message);
        assert!(verify(&pub_key, message, &signature));

        // Test key exchange
        let key2 = Key::generate().unwrap();
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
        assert_eq!(key1.key_id(), key2.key_id());
    }

    #[test]
    fn test_pem_export_import() {
        let key = Key::generate().unwrap();
        let pem = key.to_pkcs8_pem().unwrap();
        let imported = Key::from_pkcs8_pem(&pem).unwrap();

        // Keys should match
        assert_eq!(
            key.ed25519.to_seed_bytes(),
            imported.ed25519.to_seed_bytes()
        );
        assert_eq!(key.x25519.to_bytes(), imported.x25519.to_bytes());
        assert_eq!(key.key_id(), imported.key_id());
    }

    #[test]
    fn test_der_export_import() {
        let key = Key::generate().unwrap();
        let der = key.to_pkcs8_der().unwrap();
        let imported = Key::from_pkcs8_der(&der).unwrap();

        // Keys should match
        assert_eq!(
            key.ed25519.to_seed_bytes(),
            imported.ed25519.to_seed_bytes()
        );
        assert_eq!(key.x25519.to_bytes(), imported.x25519.to_bytes());
    }

    #[test]
    fn test_key_derivation() {
        let alice = Key::generate().unwrap();
        let bob = Key::generate().unwrap();

        let salt = b"test-salt";
        let info = b"test-encryption-v1";

        let alice_key = alice.derive_session_key_hkdf(&bob.x25519_public_key(), salt, info);
        let bob_key = bob.derive_session_key_hkdf(&alice.x25519_public_key(), salt, info);

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_fingerprint() {
        let key = Key::generate().unwrap();

        let fp = key.fingerprint();
        assert_eq!(fp.len(), 32);

        // Deterministic for the same key
        assert_eq!(fp, key.fingerprint());

        // Hex helper works and length is 64 hex chars
        let hex_fp = key.fingerprint_hex();
        assert_eq!(hex_fp.len(), 64);
    }

    #[test]
    fn test_file_operations() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.pem");
        let der_path = dir.path().join("test.der");
        let ed25519_pub = dir.path().join("ed25519.pub.pem");
        let x25519_pub = dir.path().join("x25519.pub.pem");
        let info_path = dir.path().join("public.json");

        let key = Key::generate().unwrap();

        // Test PEM file operations
        key.save_pkcs8_pem_file(&key_path).unwrap();
        let loaded = Key::load_pkcs8_pem_file(&key_path).unwrap();
        assert_eq!(key.key_id(), loaded.key_id());

        // Test DER file operations
        key.save_pkcs8_der_file(&der_path).unwrap();
        let loaded = Key::load_pkcs8_der_file(&der_path).unwrap();
        assert_eq!(key.key_id(), loaded.key_id());

        // Test public key export
        key.save_spki_public_keys(&ed25519_pub, &x25519_pub)
            .unwrap();
        assert!(ed25519_pub.exists());
        assert!(x25519_pub.exists());

        // Test JSON export
        key.save_public_key_info(&info_path).unwrap();
        let info = Key::load_public_key_info(&info_path).unwrap();
        assert_eq!(info.key_id, key.key_id_hex());
    }

    #[test]
    fn test_public_key_info_with_metadata() {
        let key = Key::generate().unwrap();

        let metadata = KeyMetadata {
            name: Some("Test Key".to_string()),
            email: Some("test@example.com".to_string()),
            created_at: Some(1234567890),
            expires_at: None,
        };

        let info = PublicKeyInfo::with_metadata(&key, metadata.clone());
        assert_eq!(info.metadata.as_ref().unwrap().name, metadata.name);

        // Test signature verification through PublicKeyInfo
        let message = b"test message";
        let signature = key.sign(message);
        assert!(info.verify(message, &signature));
    }
}
