// All imports
pub use capsula_crypto::asymmetric::ed25519::verify;
use capsula_crypto::{sha256, Ed25519, X25519};
use pkcs8::spki::AlgorithmIdentifierOwned;
use sha2::{Digest, Sha256};

use super::{
    Algorithm, ExportablePrivateKey, Key, KeyAgree, KeyCapabilities, KeyExportInfo, KeyFileIO,
    KeySign, KeyUsage, PublicKeyExportInfo, PublicKeySet,
};
use crate::error::{Error, Result};

// Domain separation label for deriving the X25519 seed from the master seed
const X25519_DERIVE_LABEL: &[u8] = b"capsula-x25519-derivation-v1\0\0\0";

// ============================================================================
// Core Key Structure
// ============================================================================

/// Curve25519-based cryptographic key implementation
///
/// This structure provides both signing (Ed25519) and key exchange (X25519)
/// capabilities derived from a common seed, ensuring cryptographic separation
/// while maintaining a single key identity.
///
/// # Examples
///
/// ```no_run
/// use capsula_key::{Curve25519, Key, KeyAgree, KeySign};
///
/// // Generate a new random key
/// let key = Curve25519::generate().unwrap();
///
/// // Sign a message using trait
/// let message = b"Hello, World!";
/// let signature = <Curve25519 as KeySign>::sign(&key, message).unwrap();
///
/// // Perform key exchange using trait
/// let other_key = Curve25519::generate().unwrap();
/// // Get X25519 public key from the other key's public key set
/// let other_public_keys = other_key.public_keys();
/// if let Some(kex_key) = other_public_keys.key_agreement_key() {
///     let shared_secret =
///         <Curve25519 as KeyAgree>::compute_shared_secret(&key, &kex_key.spki_der).unwrap();
/// }
/// ```
pub struct Curve25519 {
    /// Ed25519 signing key
    ed25519: Ed25519,
    /// X25519 key exchange key
    x25519: X25519,
}

impl Curve25519 {
    /// Generate a new key pair with cryptographically secure randomness
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::Other(e.to_string()))?;
        Ok(Self::from_seed(&seed))
    }

    /// Create a key pair from a 32-byte seed
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // Create Ed25519 key directly from seed
        let ed25519 = Ed25519::from_raw_seed(seed);

        // Derive X25519 seed using domain-separated hash
        let x25519_seed = Self::derive_x25519_seed(seed);
        let x25519 = X25519::from_raw_seed(&x25519_seed);

        Self { ed25519, x25519 }
    }

    /// Import key from PKCS#8 (PEM) encoded Ed25519 private key
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let ed25519 = Ed25519::from_pem(pem)
            .map_err(|e| Error::ImportError(format!("Failed to import Ed25519 key: {}", e)))?;

        let ed25519_seed = ed25519.to_seed_bytes();
        let x25519_seed = Self::derive_x25519_seed(&ed25519_seed);
        let x25519 = X25519::from_raw_seed(&x25519_seed);

        Ok(Self { ed25519, x25519 })
    }

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

    /// Derive X25519 seed from master seed using domain separation
    fn derive_x25519_seed(seed: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::with_capacity(seed.len() + X25519_DERIVE_LABEL.len());
        data.extend_from_slice(X25519_DERIVE_LABEL);
        data.extend_from_slice(seed);
        sha256(&data)
    }

    // Helper methods for trait implementations
    fn ed25519_spki_der(&self) -> Result<Vec<u8>> {
        self.ed25519
            .to_spki_der()
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    fn x25519_spki_der(&self) -> Result<Vec<u8>> {
        self.x25519
            .to_spki_der()
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    fn ed25519_public_key_bytes(&self) -> [u8; 32] {
        self.ed25519.public_key().to_bytes()
    }

    fn x25519_public_key(&self) -> [u8; 32] {
        self.x25519.to_bytes()
    }

    // Convert SPKI DER to PEM format
    fn spki_der_to_pem(&self, der_bytes: &[u8], label: &str) -> Result<String> {
        use base64::Engine;
        let base64_engine = base64::engine::general_purpose::STANDARD;
        let encoded = base64_engine.encode(der_bytes);

        let mut pem = String::new();
        pem.push_str(&format!("-----BEGIN {}-----\n", label));

        // Split base64 into 64-character lines
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }

        pem.push_str(&format!("-----END {}-----\n", label));
        Ok(pem)
    }
}

// ============================================================================
// Key Trait Implementation
// ============================================================================

impl Key for Curve25519 {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn public_keys(&self) -> PublicKeySet {
        let mut keys = PublicKeySet::new();

        // Add Ed25519 signing key
        if let Ok(signing_spki) = self.ed25519_spki_der() {
            keys.add_key_with_raw(
                KeyUsage::Signing,
                signing_spki,
                self.ed25519_public_key_bytes().to_vec(),
            );
        }

        // Add X25519 key agreement key
        if let Ok(kex_spki) = self.x25519_spki_der() {
            keys.add_key_with_raw(
                KeyUsage::KeyAgreement,
                kex_spki,
                self.x25519_public_key().to_vec(),
            );
        }

        keys
    }

    fn fingerprint_sha256_spki(&self) -> Vec<u8> {
        if let Ok(spki) = self.ed25519_spki_der() {
            let mut hasher = Sha256::new();
            hasher.update(&spki);
            hasher.finalize().to_vec()
        } else {
            vec![]
        }
    }

    fn key_id(&self) -> Vec<u8> {
        // Use first 8 bytes of fingerprint as key ID
        let fingerprint = self.fingerprint_sha256_spki();
        if fingerprint.len() >= 8 {
            fingerprint[.. 8].to_vec()
        } else {
            vec![]
        }
    }

    fn capabilities(&self) -> KeyCapabilities {
        KeyCapabilities::SIGNING.union(KeyCapabilities::KEY_AGREEMENT)
    }
}

impl KeySign for Curve25519 {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.ed25519.sign(message).to_vec())
    }

    fn signature_algorithm_id(&self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc8410::ID_ED_25519,
            parameters: None,
        }
    }
}

impl KeyAgree for Curve25519 {
    fn compute_shared_secret(&self, peer_spki_der: &[u8]) -> Result<Vec<u8>> {
        // Extract X25519 public key from SPKI DER and compute shared secret
        // For now, assume the peer_spki_der contains raw X25519 key (32 bytes)
        if peer_spki_der.len() >= 32 {
            let mut peer_key = [0u8; 32];
            // Extract last 32 bytes as the raw key (simplified)
            peer_key.copy_from_slice(&peer_spki_der[peer_spki_der.len() - 32 ..]);
            // Directly call x25519 compute_shared_secret
            Ok(self.x25519.compute_shared_secret(&peer_key).to_vec())
        } else {
            Err(crate::error::Error::KeyError(
                "Invalid SPKI DER format".to_string(),
            ))
        }
    }

    fn kex_algorithm_id(&self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc8410::ID_X_25519,
            parameters: None,
        }
    }
}

impl ExportablePrivateKey for Curve25519 {
    fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        self.ed25519
            .to_pkcs8_der()
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    fn to_pkcs8_pem(&self) -> Result<String> {
        self.ed25519
            .to_pkcs8_pem()
            .map_err(|e| Error::EncodingError(e.to_string()))
    }
}

impl KeyFileIO for Curve25519 {
    fn export_all_keys<P: AsRef<std::path::Path>>(
        &self,
        base_dir: P,
        name_prefix: &str,
    ) -> Result<KeyExportInfo> {
        use std::fs;

        let base_dir = base_dir.as_ref();

        // Create base directory if it doesn't exist
        fs::create_dir_all(base_dir).map_err(Error::from)?;

        // Export private key
        let private_key_path = base_dir.join(format!("{}_private.pem", name_prefix));
        self.save_pkcs8_pem_file(&private_key_path)?;

        // Export public keys
        let public_key_exports = self.export_public_keys_pem(base_dir, name_prefix)?;

        // Create export info
        let export_info = KeyExportInfo {
            algorithm: self.algorithm().name().to_string(),
            key_id: self.key_id_hex(),
            private_key_path: private_key_path.to_string_lossy().to_string(),
            public_key_paths: public_key_exports,
        };

        // Save export info as JSON
        let info_path = base_dir.join(format!("{}_export_info.json", name_prefix));
        export_info.save_to_file(&info_path)?;

        Ok(export_info)
    }

    fn export_public_keys_pem<P: AsRef<std::path::Path>>(
        &self,
        base_dir: P,
        name_prefix: &str,
    ) -> Result<Vec<PublicKeyExportInfo>> {
        use std::fs;

        let base_dir = base_dir.as_ref();
        let mut export_info = Vec::new();
        let public_keys = self.public_keys();

        // Export signing public key
        if let Some(signing_key) = public_keys.signing_key() {
            let signing_pem = self.spki_der_to_pem(&signing_key.spki_der, "PUBLIC KEY")?;
            let signing_path = base_dir.join(format!("{}_signing_pub.pem", name_prefix));
            fs::write(&signing_path, signing_pem).map_err(Error::from)?;

            export_info.push(PublicKeyExportInfo {
                key_type: KeyUsage::Signing,
                file_path: signing_path.to_string_lossy().to_string(),
            });
        }

        // Export key agreement public key
        if let Some(kex_key) = public_keys.key_agreement_key() {
            let kex_pem = self.spki_der_to_pem(&kex_key.spki_der, "PUBLIC KEY")?;
            let kex_path = base_dir.join(format!("{}_kex_pub.pem", name_prefix));
            fs::write(&kex_path, kex_pem).map_err(Error::from)?;

            export_info.push(PublicKeyExportInfo {
                key_type: KeyUsage::KeyAgreement,
                file_path: kex_path.to_string_lossy().to_string(),
            });
        }

        Ok(export_info)
    }

    fn export_public_keys_der<P: AsRef<std::path::Path>>(
        &self,
        base_dir: P,
        name_prefix: &str,
    ) -> Result<Vec<PublicKeyExportInfo>> {
        use std::fs;

        let base_dir = base_dir.as_ref();
        let mut export_info = Vec::new();
        let public_keys = self.public_keys();

        // Export signing public key
        if let Some(signing_key) = public_keys.signing_key() {
            let signing_path = base_dir.join(format!("{}_signing_pub.der", name_prefix));
            fs::write(&signing_path, &signing_key.spki_der).map_err(Error::from)?;

            export_info.push(PublicKeyExportInfo {
                key_type: KeyUsage::Signing,
                file_path: signing_path.to_string_lossy().to_string(),
            });
        }

        // Export key agreement public key
        if let Some(kex_key) = public_keys.key_agreement_key() {
            let kex_path = base_dir.join(format!("{}_kex_pub.der", name_prefix));
            fs::write(&kex_path, &kex_key.spki_der).map_err(Error::from)?;

            export_info.push(PublicKeyExportInfo {
                key_type: KeyUsage::KeyAgreement,
                file_path: kex_path.to_string_lossy().to_string(),
            });
        }

        Ok(export_info)
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
        let key = Curve25519::generate().unwrap();
        let pub_key = key.ed25519_public_key_bytes();

        // Test signing using trait
        let message = b"test message";
        let signature = <Curve25519 as KeySign>::sign(&key, message).unwrap();
        assert!(verify(&pub_key, message, &signature.try_into().unwrap()));

        // Test key exchange using trait
        let key2 = Curve25519::generate().unwrap();
        let key2_spki = key2.x25519_spki_der().unwrap();
        let shared1 = <Curve25519 as KeyAgree>::compute_shared_secret(&key, &key2_spki).unwrap();
        let key_spki = key.x25519_spki_der().unwrap();
        let shared2 = <Curve25519 as KeyAgree>::compute_shared_secret(&key2, &key_spki).unwrap();
        assert_eq!(shared1, shared2);
    }

    #[test]
    fn test_key_from_seed() {
        let seed = [42u8; 32];
        let key1 = Curve25519::from_seed(&seed);
        let key2 = Curve25519::from_seed(&seed);

        // Same seed should produce same keys
        assert_eq!(key1.ed25519.to_seed_bytes(), key2.ed25519.to_seed_bytes());
        assert_eq!(key1.x25519.to_bytes(), key2.x25519.to_bytes());
        assert_eq!(key1.key_id(), key2.key_id());
    }

    #[test]
    fn test_pem_export_import() {
        let key = Curve25519::generate().unwrap();
        let pem = <Curve25519 as ExportablePrivateKey>::to_pkcs8_pem(&key).unwrap();
        let imported = Curve25519::from_pkcs8_pem(&pem).unwrap();

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
        let key = Curve25519::generate().unwrap();
        let der = <Curve25519 as ExportablePrivateKey>::to_pkcs8_der(&key).unwrap();
        let imported = Curve25519::from_pkcs8_der(&der).unwrap();

        // Keys should match
        assert_eq!(
            key.ed25519.to_seed_bytes(),
            imported.ed25519.to_seed_bytes()
        );
        assert_eq!(key.x25519.to_bytes(), imported.x25519.to_bytes());
    }

    #[test]
    fn test_key_derivation() {
        let alice = Curve25519::generate().unwrap();
        let bob = Curve25519::generate().unwrap();

        // Test basic key agreement using traits
        let alice_spki = alice.x25519_spki_der().unwrap();
        let bob_spki = bob.x25519_spki_der().unwrap();

        let alice_shared =
            <Curve25519 as KeyAgree>::compute_shared_secret(&bob, &alice_spki).unwrap();
        let bob_shared =
            <Curve25519 as KeyAgree>::compute_shared_secret(&alice, &bob_spki).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_fingerprint() {
        let key = Curve25519::generate().unwrap();

        let fp = key.fingerprint_sha256_spki();
        assert_eq!(fp.len(), 32);

        // Deterministic for the same key
        assert_eq!(fp, key.fingerprint_sha256_spki());

        // Hex helper works and length is 64 hex chars
        let hex_fp = key.fingerprint_hex();
        assert_eq!(hex_fp.len(), 64);
    }

    #[test]
    fn test_file_operations() {
        use std::fs;

        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.pem");
        let der_path = dir.path().join("test.der");

        let key = Curve25519::generate().unwrap();

        // Test PEM file operations using trait methods
        let pem_data = <Curve25519 as ExportablePrivateKey>::to_pkcs8_pem(&key).unwrap();
        fs::write(&key_path, &pem_data).unwrap();
        let loaded = Curve25519::from_pkcs8_pem(&pem_data).unwrap();
        assert_eq!(key.key_id(), loaded.key_id());

        // Test DER file operations using trait methods
        let der_data = <Curve25519 as ExportablePrivateKey>::to_pkcs8_der(&key).unwrap();
        fs::write(&der_path, &der_data).unwrap();
        let loaded = Curve25519::from_pkcs8_der(&der_data).unwrap();
        assert_eq!(key.key_id(), loaded.key_id());
    }

    #[test]
    fn test_public_key_info_with_metadata() {
        let key = Curve25519::generate().unwrap();

        // Test trait-based key information
        let public_keys = key.public_keys();
        assert!(public_keys.signing_key().is_some());
        assert!(public_keys.key_agreement_key().is_some());

        // Test signature verification using trait
        let message = b"test message";
        let signature = <Curve25519 as KeySign>::sign(&key, message).unwrap();
        assert!(verify(
            &key.ed25519_public_key_bytes(),
            message,
            &signature.try_into().unwrap()
        ));
    }

    #[test]
    fn test_key_file_io() {
        use std::fs;

        let dir = tempdir().unwrap();
        let key = Curve25519::generate().unwrap();

        // Test export_all_keys
        let export_info =
            <Curve25519 as KeyFileIO>::export_all_keys(&key, dir.path(), "test_key").unwrap();

        // Verify private key was exported
        assert!(fs::exists(&export_info.private_key_path).unwrap());

        // Verify public keys were exported
        assert_eq!(export_info.public_key_paths.len(), 2); // signing + key agreement
        for pub_key_info in &export_info.public_key_paths {
            assert!(fs::exists(&pub_key_info.file_path).unwrap());
        }

        // Verify export info JSON was created
        let info_path = dir.path().join("test_key_export_info.json");
        assert!(fs::exists(&info_path).unwrap());

        // Test loading the export info
        let loaded_info = KeyExportInfo::load_from_file(&info_path).unwrap();
        assert_eq!(loaded_info.algorithm, export_info.algorithm);
        assert_eq!(loaded_info.key_id, export_info.key_id);

        // Test export_public_keys_der
        let der_exports =
            <Curve25519 as KeyFileIO>::export_public_keys_der(&key, dir.path(), "test_der")
                .unwrap();
        assert_eq!(der_exports.len(), 2);
        for der_info in &der_exports {
            assert!(fs::exists(&der_info.file_path).unwrap());
            assert!(der_info.file_path.ends_with(".der"));
        }
    }
}
