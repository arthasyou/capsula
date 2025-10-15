// All imports
use capsula_crypto::Rsa;
use pkcs8::spki::AlgorithmIdentifierOwned;

use super::{
    Algorithm, ExportablePrivateKey, Key, KeyCapabilities, KeyEncDec, KeyExportInfo, KeyFileIO,
    KeySign, KeyUsage, PublicKeyExportInfo, PublicKeySet,
};
use crate::error::{Error, Result};

// ============================================================================
// Core Key Structure
// ============================================================================

/// RSA cryptographic key implementation
///
/// This structure provides RSA signing and encryption capabilities.
/// RSA keys support both digital signatures and asymmetric encryption.
///
/// # Examples
///
/// ```no_run
/// use capsula_key::{Key, KeySign, RsaKey};
///
/// // Generate a new 2048-bit RSA key
/// let key = RsaKey::generate_2048().unwrap();
///
/// // Sign a message using trait
/// let message = b"Hello, World!";
/// let signature = <RsaKey as KeySign>::sign(&key, message).unwrap();
/// ```
pub struct RsaKey {
    /// RSA key implementation from capsula-crypto
    inner: Rsa,
}

// ============================================================================
// Constructors (public interface)
// ============================================================================

impl RsaKey {
    /// Generate a new 2048-bit RSA key pair
    pub fn generate_2048() -> Result<Self> {
        let inner = Rsa::generate_2048()
            .map_err(|e| Error::KeyError(format!("RSA-2048 generation failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Generate a new 3072-bit RSA key pair
    pub fn generate_3072() -> Result<Self> {
        let inner = Rsa::generate_3072()
            .map_err(|e| Error::KeyError(format!("RSA-3072 generation failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Generate a new 4096-bit RSA key pair
    pub fn generate_4096() -> Result<Self> {
        let inner = Rsa::generate_4096()
            .map_err(|e| Error::KeyError(format!("RSA-4096 generation failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Import from PKCS8 PEM format
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let inner = Rsa::from_pkcs8_pem(pem)
            .map_err(|e| Error::KeyError(format!("RSA PKCS8 PEM import failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Import from PKCS8 DER format
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let inner = Rsa::from_pkcs8_der(der)
            .map_err(|e| Error::KeyError(format!("RSA PKCS8 DER import failed: {}", e)))?;
        Ok(Self { inner })
    }

    /// Get RSA key size in bits
    pub fn size_bits(&self) -> usize {
        self.inner.size()
    }
}

// ============================================================================
// Key Trait Implementation
// ============================================================================

impl Key for RsaKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Rsa
    }

    fn public_keys(&self) -> PublicKeySet {
        let spki_der = self
            .inner
            .to_spki_der()
            .expect("RSA SPKI DER encoding failed");

        let mut public_keys = PublicKeySet::new();
        public_keys.add_key(KeyUsage::Signing, spki_der);
        public_keys
    }

    fn fingerprint_sha256_spki(&self) -> Vec<u8> {
        self.inner
            .spki_sha256_fingerprint()
            .expect("RSA SPKI fingerprint failed")
            .to_vec()
    }

    fn key_id(&self) -> Vec<u8> {
        // Use SPKI SHA-256 fingerprint as key ID (first 16 bytes)
        let fingerprint = self.fingerprint_sha256_spki();
        fingerprint[.. 16].to_vec()
    }

    fn capabilities(&self) -> KeyCapabilities {
        KeyCapabilities::SIGNING.union(KeyCapabilities::ENCRYPTION)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ============================================================================
// KeySign Trait Implementation
// ============================================================================

impl KeySign for RsaKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .sign(message)
            .map_err(|e| Error::SignatureError(format!("RSA signing failed: {}", e)))
    }

    fn signature_algorithm_id(&self) -> AlgorithmIdentifierOwned {
        // RSA with SHA-256 signature algorithm OID
        AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
            parameters: None,
        }
    }
}

// ============================================================================
// KeyEncDec Trait Implementation
// ============================================================================

impl KeyEncDec for RsaKey {
    /// Encrypt data using RSA public key with PKCS1v15 padding
    ///
    /// Note: This encrypts using the key's own public key.
    /// Use this when you want data that only this key can decrypt.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .encrypt_with_own_key(plaintext)
            .map_err(|e| Error::CryptoError(e))
    }

    /// Decrypt data using RSA private key with PKCS1v15 padding
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.inner
            .decrypt(ciphertext)
            .map_err(|e| Error::CryptoError(e))
    }

    /// Get encryption algorithm identifier for RSA-PKCS1v15
    fn encryption_algorithm_id(&self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
            parameters: None,
        }
    }
}

// ============================================================================
// ExportablePrivateKey Trait Implementation
// ============================================================================

impl ExportablePrivateKey for RsaKey {
    fn to_pkcs8_pem(&self) -> Result<String> {
        self.inner
            .to_pkcs8_pem()
            .map_err(|e| Error::ExportError(format!("RSA PKCS8 PEM export failed: {}", e)))
    }

    fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        self.inner
            .to_pkcs8_der()
            .map_err(|e| Error::ExportError(format!("RSA PKCS8 DER export failed: {}", e)))
    }
}

// ============================================================================
// KeyFileIO Trait Implementation
// ============================================================================

impl KeyFileIO for RsaKey {
    fn export_all_keys<P: AsRef<std::path::Path>>(
        &self,
        base_dir: P,
        name_prefix: &str,
    ) -> Result<KeyExportInfo> {
        let base_path = base_dir.as_ref();
        std::fs::create_dir_all(base_path).map_err(Error::IoError)?;

        // Export private key
        let private_pem = self.to_pkcs8_pem()?;
        let private_path = base_path.join(format!("{}_private.pem", name_prefix));
        std::fs::write(&private_path, private_pem).map_err(Error::IoError)?;

        // Export public key
        let public_pem = self
            .inner
            .to_spki_pem()
            .map_err(|e| Error::ExportError(format!("RSA public PEM export failed: {}", e)))?;
        let public_path = base_path.join(format!("{}_public.pem", name_prefix));
        std::fs::write(&public_path, &public_pem).map_err(Error::IoError)?;

        Ok(KeyExportInfo {
            algorithm: "RSA".to_string(),
            key_id: hex::encode(self.key_id()),
            private_key_path: private_path.to_string_lossy().to_string(),
            public_key_paths: vec![PublicKeyExportInfo {
                key_type: KeyUsage::Signing,
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
            .map_err(|e| Error::ExportError(format!("RSA public PEM export failed: {}", e)))?;
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
            .map_err(|e| Error::ExportError(format!("RSA public DER export failed: {}", e)))?;
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
    fn test_rsa_key_generation() {
        let key = RsaKey::generate_2048().unwrap();
        assert_eq!(key.size_bits(), 2048);
        assert_eq!(key.algorithm(), Algorithm::Rsa);
    }

    #[test]
    fn test_rsa_different_sizes() {
        let key_2048 = RsaKey::generate_2048().unwrap();
        assert_eq!(key_2048.size_bits(), 2048);

        let key_3072 = RsaKey::generate_3072().unwrap();
        assert_eq!(key_3072.size_bits(), 3072);

        let key_4096 = RsaKey::generate_4096().unwrap();
        assert_eq!(key_4096.size_bits(), 4096);
    }

    #[test]
    fn test_rsa_key_capabilities() {
        let key = RsaKey::generate_2048().unwrap();
        let caps = key.capabilities();
        assert!(caps.supports_signing());
        assert!(caps.supports_encryption());
        assert!(!caps.supports_key_agreement()); // RSA doesn't support ECDH
    }

    #[test]
    fn test_rsa_signing() {
        let key = RsaKey::generate_2048().unwrap();
        let message = b"Hello, RSA World!";

        let signature = key.sign(message).unwrap();
        assert!(signature.len() > 0);

        let spki_der = key.inner.to_spki_der().unwrap();
        let is_valid = capsula_crypto::verify_signature(&spki_der, message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_rsa_public_keys() {
        let key = RsaKey::generate_2048().unwrap();
        let public_keys = key.public_keys();

        let signing_key = public_keys.signing_key();
        assert!(signing_key.is_some());
        assert_eq!(signing_key.unwrap().usage, KeyUsage::Signing);

        // RSA doesn't support key agreement
        let kex_key = public_keys.key_agreement_key();
        assert!(kex_key.is_none());
    }

    #[test]
    fn test_rsa_fingerprint_and_key_id() {
        let key = RsaKey::generate_2048().unwrap();

        let fingerprint = key.fingerprint_sha256_spki();
        assert_eq!(fingerprint.len(), 32);

        let key_id = key.key_id();
        assert_eq!(key_id.len(), 16);
        assert_eq!(key_id, &fingerprint[.. 16]);
    }

    #[test]
    fn test_rsa_key_export_import() {
        let original_key = RsaKey::generate_2048().unwrap();

        // Test PEM round-trip
        let pem = original_key.to_pkcs8_pem().unwrap();
        let imported_key = RsaKey::from_pkcs8_pem(&pem).unwrap();

        assert_eq!(original_key.size_bits(), imported_key.size_bits());
        assert_eq!(original_key.key_id(), imported_key.key_id());

        // Test DER round-trip
        let der = original_key.to_pkcs8_der().unwrap();
        let imported_key_der = RsaKey::from_pkcs8_der(&der).unwrap();

        assert_eq!(original_key.key_id(), imported_key_der.key_id());
    }

    #[test]
    fn test_rsa_file_export() {
        use tempfile::TempDir;

        let key = RsaKey::generate_2048().unwrap();
        let temp_dir = TempDir::new().unwrap();

        let export_info = key.export_all_keys(temp_dir.path(), "test_rsa").unwrap();

        // Check files exist
        assert!(std::path::Path::new(&export_info.private_key_path).exists());
        assert_eq!(export_info.public_key_paths.len(), 1);
        assert!(std::path::Path::new(&export_info.public_key_paths[0].file_path).exists());

        // Check key can be imported back
        let private_pem = std::fs::read_to_string(&export_info.private_key_path).unwrap();
        let imported_key = RsaKey::from_pkcs8_pem(&private_pem).unwrap();
        assert_eq!(key.key_id(), imported_key.key_id());
    }

    #[test]
    fn test_rsa_encrypt_decrypt_with_own_key() {
        let key = RsaKey::generate_2048().unwrap();
        let message = b"Secret message encrypted with own key";

        // Encrypt using the KeyEncDec trait (uses own public key)
        let ciphertext = key.encrypt(message).unwrap();

        // Decrypt using the same key's private key
        let plaintext = key.decrypt(&ciphertext).unwrap();

        assert_eq!(message.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_rsa_encrypt_decrypt_round_trip() {
        let key = RsaKey::generate_2048().unwrap();
        let original_data = b"Round trip encryption test with own public key";

        // Test encryption with own key
        let encrypted = key.encrypt(original_data).unwrap();
        assert_ne!(encrypted, original_data);

        // Test decryption
        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(original_data.as_slice(), decrypted.as_slice());
    }
}
