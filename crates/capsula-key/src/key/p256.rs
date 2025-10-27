// All imports
use capsula_crypto::P256;
use pkcs8::spki::AlgorithmIdentifierOwned;

use super::{
    Algorithm, Key, KeyAgree, KeyCapabilities, KeyExport, KeyExportInfo, KeyFileIO, KeySign,
    KeyUsage, PublicKeyExportInfo, PublicKeySet,
};
use crate::error::{Error, Result};

// ============================================================================
// Core Key Structure
// ============================================================================

/// NIST P-256 elliptic curve cryptographic key implementation
///
/// This structure provides both ECDSA signing and ECDH key agreement
/// capabilities using the NIST P-256 (secp256r1) elliptic curve.
///
/// # Examples
///
/// ```no_run
/// use capsula_key::{Key, KeyAgree, KeySign, P256Key};
///
/// // Generate a new P-256 key
/// let key = P256Key::generate().unwrap();
///
/// // Sign a message using trait
/// let message = b"Hello, World!";
/// let signature = <P256Key as KeySign>::sign(&key, message).unwrap();
///
/// // Perform key agreement using trait
/// let other_key = P256Key::generate().unwrap();
/// let other_public_keys = other_key.public_keys();
/// if let Some(kex_key) = other_public_keys.key_agreement_key() {
///     let shared_secret =
///         <P256Key as KeyAgree>::compute_shared_secret(&key, &kex_key.spki_der).unwrap();
/// }
/// ```
pub struct P256Key {
    /// P-256 key implementation from capsula-crypto
    inner: P256,
}

// ============================================================================
// Constructors (public interface)
// ============================================================================

impl P256Key {
    /// Generate a new P-256 key pair
    pub fn generate() -> Result<Self> {
        let inner = P256::generate()
            .map_err(|e| Error::KeyError(format!("P-256 generation failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Create from raw scalar bytes (32 bytes)
    pub fn from_raw_scalar(bytes: &[u8; 32]) -> Result<Self> {
        let inner = P256::from_raw_scalar(bytes)
            .map_err(|e| Error::KeyError(format!("P-256 from scalar failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Import from PKCS8 PEM format
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let inner = P256::from_pkcs8_pem(pem)
            .map_err(|e| Error::KeyError(format!("P-256 PKCS8 PEM import failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Import from PKCS8 DER format
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let inner = P256::from_pkcs8_der(der)
            .map_err(|e| Error::KeyError(format!("P-256 PKCS8 DER import failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get raw scalar bytes (32 bytes)
    pub fn to_scalar_bytes(&self) -> [u8; 32] {
        self.inner.to_scalar_bytes()
    }
}

// ============================================================================
// Key Trait Implementation
// ============================================================================

impl Key for P256Key {
    fn algorithm(&self) -> Algorithm {
        Algorithm::P256
    }

    fn public_keys(&self) -> PublicKeySet {
        let spki_der = self
            .inner
            .to_spki_der()
            .expect("P-256 SPKI DER encoding failed");

        // P-256 supports both signing and key agreement with the same key
        let mut public_keys = PublicKeySet::new();
        public_keys.add_key(KeyUsage::Signing, spki_der.clone());
        public_keys.add_key(KeyUsage::KeyAgreement, spki_der);
        public_keys
    }

    fn fingerprint_sha256_spki(&self) -> Vec<u8> {
        self.inner
            .spki_sha256_fingerprint()
            .expect("P-256 SPKI fingerprint failed")
            .to_vec()
    }

    fn key_id(&self) -> Vec<u8> {
        // Use SPKI SHA-256 fingerprint as key ID (first 16 bytes)
        let fingerprint = self.fingerprint_sha256_spki();
        fingerprint[.. 16].to_vec()
    }

    fn capabilities(&self) -> KeyCapabilities {
        KeyCapabilities::SIGNING.union(KeyCapabilities::KEY_AGREEMENT)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ============================================================================
// KeySign Trait Implementation
// ============================================================================

impl KeySign for P256Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .sign(message)
            .map_err(|e| Error::SignatureError(format!("P-256 signing failed: {}", e)))
    }

    fn signature_algorithm_id(&self) -> AlgorithmIdentifierOwned {
        // ECDSA with SHA-256 signature algorithm OID
        AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        }
    }
}

// ============================================================================
// KeyAgree Trait Implementation
// ============================================================================

impl KeyAgree for P256Key {
    fn compute_shared_secret(&self, peer_spki_der: &[u8]) -> Result<Vec<u8>> {
        // Import the other party's public key from DER format
        let their_public_key = capsula_crypto::asymmetric::p256::public_key_from_spki_der(
            peer_spki_der,
        )
        .map_err(|e| Error::KeyError(format!("Failed to import P-256 public key: {}", e)))?;

        // Perform ECDH
        let shared_secret = self
            .inner
            .compute_shared_secret(&their_public_key)
            .map_err(|e| Error::KeyError(format!("P-256 ECDH failed: {}", e)))?;

        Ok(shared_secret.to_vec())
    }

    fn kex_algorithm_id(&self) -> AlgorithmIdentifierOwned {
        // ECDH algorithm identifier
        AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
            parameters: None,
        }
    }
}

// ============================================================================
// KeyExport Trait Implementation
// ============================================================================

impl KeyExport for P256Key {
    fn to_pkcs8_pem(&self) -> Result<String> {
        self.inner
            .to_pkcs8_pem()
            .map_err(|e| Error::ExportError(format!("P-256 PKCS8 PEM export failed: {}", e)))
    }

    fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        self.inner
            .to_pkcs8_der()
            .map_err(|e| Error::ExportError(format!("P-256 PKCS8 DER export failed: {}", e)))
    }

    fn to_spki_der(&self) -> Result<Vec<u8>> {
        let der = self.inner.to_spki_der()?;
        Ok(der)
    }

    fn to_spki_pem(&self) -> Result<String> {
        let pem = self.inner.to_spki_pem()?;
        Ok(pem)
    }
}

// ============================================================================
// KeyFileIO Trait Implementation
// ============================================================================

impl KeyFileIO for P256Key {
    fn export_all_keys<P: AsRef<std::path::Path>>(
        &self,
        base_dir: P,
        name_prefix: &str,
    ) -> Result<KeyExportInfo> {
        let base_path = base_dir.as_ref();
        std::fs::create_dir_all(base_path).map_err(Error::IoError)?;

        // Export private key
        let private_pem = self.to_pkcs8_pem()?;
        let private_path = base_path.join(format!("{}.key", name_prefix));
        std::fs::write(&private_path, private_pem).map_err(Error::IoError)?;

        // Export public key (same key used for both signing and key agreement)
        let public_pem = self
            .inner
            .to_spki_pem()
            .map_err(|e| Error::ExportError(format!("P-256 public PEM export failed: {}", e)))?;
        let public_path = base_path.join(format!("{}.pub", name_prefix));
        std::fs::write(&public_path, &public_pem).map_err(Error::IoError)?;

        Ok(KeyExportInfo {
            algorithm: "P-256".to_string(),
            key_id: hex::encode(self.key_id()),
            private_key_path: private_path.to_string_lossy().to_string(),
            public_key_paths: vec![PublicKeyExportInfo {
                key_type: KeyUsage::Signing, // Primary usage, but also supports key agreement
                file_path: public_path.to_string_lossy().to_string(),
            }],
        })
    }

    fn export_public_keys_pem<P: AsRef<std::path::Path>>(
        &self,
        base_dir: P,
        name_prefix: &str,
    ) -> Result<Vec<PublicKeyExportInfo>> {
        let base_path = base_dir.as_ref();
        std::fs::create_dir_all(base_path).map_err(Error::IoError)?;

        let public_pem = self
            .inner
            .to_spki_pem()
            .map_err(|e| Error::ExportError(format!("P-256 public PEM export failed: {}", e)))?;
        let public_path = base_path.join(format!("{}.pub", name_prefix));
        std::fs::write(&public_path, &public_pem).map_err(Error::IoError)?;

        Ok(vec![PublicKeyExportInfo {
            key_type: KeyUsage::Signing,
            file_path: public_path.to_string_lossy().to_string(),
        }])
    }

    fn export_public_keys_der<P: AsRef<std::path::Path>>(
        &self,
        base_dir: P,
        name_prefix: &str,
    ) -> Result<Vec<PublicKeyExportInfo>> {
        let base_path = base_dir.as_ref();
        std::fs::create_dir_all(base_path).map_err(Error::IoError)?;

        let public_der = self
            .inner
            .to_spki_der()
            .map_err(|e| Error::ExportError(format!("P-256 public DER export failed: {}", e)))?;
        let public_path = base_path.join(format!("{}.der", name_prefix));
        std::fs::write(&public_path, &public_der).map_err(Error::IoError)?;

        Ok(vec![PublicKeyExportInfo {
            key_type: KeyUsage::Signing,
            file_path: public_path.to_string_lossy().to_string(),
        }])
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_key_generation() {
        let key = P256Key::generate().unwrap();
        assert_eq!(key.algorithm(), Algorithm::P256);
    }

    #[test]
    fn test_p256_key_capabilities() {
        let key = P256Key::generate().unwrap();
        let caps = key.capabilities();
        assert!(caps.supports_signing());
        assert!(caps.supports_key_agreement());
        assert!(!caps.supports_encryption()); // P-256 doesn't support direct encryption
    }

    #[test]
    fn test_p256_signing() {
        let key = P256Key::generate().unwrap();
        let message = b"Hello, P-256 World!";

        let signature = key.sign(message).unwrap();
        assert!(signature.len() > 0);

        let spki_der = key.inner.to_spki_der().unwrap();
        let is_valid = capsula_crypto::verify_signature(&spki_der, message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_p256_key_agreement() {
        let alice = P256Key::generate().unwrap();
        let bob = P256Key::generate().unwrap();

        let alice_public_keys = alice.public_keys();
        let bob_public_keys = bob.public_keys();

        let alice_kex_key = alice_public_keys.key_agreement_key().unwrap();
        let bob_kex_key = bob_public_keys.key_agreement_key().unwrap();

        let alice_shared = alice.compute_shared_secret(&bob_kex_key.spki_der).unwrap();
        let bob_shared = bob.compute_shared_secret(&alice_kex_key.spki_der).unwrap();

        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 32); // P-256 shared secret is 32 bytes
    }

    #[test]
    fn test_p256_public_keys() {
        let key = P256Key::generate().unwrap();
        let public_keys = key.public_keys();

        let signing_key = public_keys.signing_key();
        assert!(signing_key.is_some());
        assert_eq!(signing_key.unwrap().usage, KeyUsage::Signing);

        let kex_key = public_keys.key_agreement_key();
        assert!(kex_key.is_some());
        assert_eq!(kex_key.unwrap().usage, KeyUsage::KeyAgreement);

        // For P-256, the same key is used for both operations
        assert_eq!(signing_key.unwrap().spki_der, kex_key.unwrap().spki_der);
    }

    #[test]
    fn test_p256_fingerprint_and_key_id() {
        let key = P256Key::generate().unwrap();

        let fingerprint = key.fingerprint_sha256_spki();
        assert_eq!(fingerprint.len(), 32);

        let key_id = key.key_id();
        assert_eq!(key_id.len(), 16);
        assert_eq!(key_id, &fingerprint[.. 16]);
    }

    #[test]
    fn test_p256_key_export_import() {
        let original_key = P256Key::generate().unwrap();

        // Test PEM round-trip
        let pem = original_key.to_pkcs8_pem().unwrap();
        let imported_key = P256Key::from_pkcs8_pem(&pem).unwrap();

        assert_eq!(
            original_key.to_scalar_bytes(),
            imported_key.to_scalar_bytes()
        );
        assert_eq!(original_key.key_id(), imported_key.key_id());

        // Test DER round-trip
        let der = original_key.to_pkcs8_der().unwrap();
        let imported_key_der = P256Key::from_pkcs8_der(&der).unwrap();

        assert_eq!(original_key.key_id(), imported_key_der.key_id());
    }

    #[test]
    fn test_p256_from_raw_scalar() {
        let scalar_bytes = [42u8; 32];
        let key1 = P256Key::from_raw_scalar(&scalar_bytes).unwrap();
        let key2 = P256Key::from_raw_scalar(&scalar_bytes).unwrap();

        // Same scalar should produce same keys
        assert_eq!(key1.to_scalar_bytes(), key2.to_scalar_bytes());
        assert_eq!(key1.key_id(), key2.key_id());
    }

    #[test]
    fn test_p256_file_export() {
        use tempfile::TempDir;

        let key = P256Key::generate().unwrap();
        let temp_dir = TempDir::new().unwrap();

        let export_info = key.export_all_keys(temp_dir.path(), "test_p256").unwrap();

        // Check files exist
        assert!(std::path::Path::new(&export_info.private_key_path).exists());
        assert_eq!(export_info.public_key_paths.len(), 1);
        assert!(std::path::Path::new(&export_info.public_key_paths[0].file_path).exists());

        // Check key can be imported back
        let private_pem = std::fs::read_to_string(&export_info.private_key_path).unwrap();
        let imported_key = P256Key::from_pkcs8_pem(&private_pem).unwrap();
        assert_eq!(key.key_id(), imported_key.key_id());
    }
}
