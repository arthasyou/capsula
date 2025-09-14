//! PKI KeyStore Adapter
//!
//! This module provides a PKI-specific adapter layer over capsula-key's EnhancedKeyStore,
//! adding certificate-key associations, PKI-specific policies, and enterprise features.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use capsula_key::{
    Key, Algorithm as KeyAlgorithm,
    store::{EnhancedKeyStore, EnhancedKeyMetadata, KeyUsage as StoreKeyUsage, KeyValidity}
};
use crate::ra::cert::X509Certificate;
use crate::error::{Result, PkiError};

/// PKI-specific key metadata extensions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PKIKeyMetadata {
    /// Base enhanced metadata from capsula-key
    pub enhanced: EnhancedKeyMetadata,
    /// Associated certificates (by serial number)
    pub associated_certificates: Vec<String>,
    /// PKI policy constraints
    pub policy_constraints: PolicyConstraints,
    /// Certificate template information
    pub certificate_template: Option<CertificateTemplate>,
    /// Key escrow information
    pub escrow_info: Option<EscrowInfo>,
}

/// PKI policy constraints for key usage
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyConstraints {
    /// Maximum certificate validity period this key can sign
    pub max_cert_validity_days: Option<u32>,
    /// Allowed certificate types
    pub allowed_cert_types: Vec<CertificateType>,
    /// Minimum key strength requirements
    pub min_key_strength: Option<u32>,
    /// Allowed signature algorithms
    pub allowed_signature_algorithms: Vec<String>,
    /// Key usage restrictions beyond basic usage
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
}

/// Certificate types that can be signed by this key
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateType {
    /// End entity certificates
    EndEntity,
    /// Intermediate CA certificates  
    IntermediateCA,
    /// Root CA certificates
    RootCA,
    /// Code signing certificates
    CodeSigning,
    /// TLS server certificates
    TLSServer,
    /// TLS client certificates
    TLSClient,
}

/// Extended key usage beyond basic signing/encryption
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtendedKeyUsage {
    /// Server authentication
    ServerAuth,
    /// Client authentication
    ClientAuth,
    /// Code signing
    CodeSigning,
    /// Email protection
    EmailProtection,
    /// Time stamping
    TimeStamping,
    /// OCSP signing
    OCSPSigning,
}

/// Certificate template information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateTemplate {
    /// Template name
    pub template_name: String,
    /// Default validity period
    pub default_validity_days: u32,
    /// Default subject template
    pub subject_template: String,
    /// Default extensions
    pub default_extensions: HashMap<String, String>,
}

/// Key escrow information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowInfo {
    /// Escrow agent identifier
    pub agent_id: String,
    /// Escrow timestamp
    pub escrowed_at: time::OffsetDateTime,
    /// Recovery information (encrypted)
    pub recovery_info: Vec<u8>,
}

/// PKI KeyStore adapter that wraps EnhancedKeyStore
pub struct PKIKeyStore {
    /// Underlying enhanced key store
    inner: EnhancedKeyStore,
    /// PKI-specific metadata cache
    pki_metadata_cache: HashMap<capsula_key::store::KeyHandle, PKIKeyMetadata>,
    /// Certificate-to-key mapping
    cert_key_mapping: HashMap<String, capsula_key::store::KeyHandle>,
    /// Default PKI policies
    default_policies: PolicyConstraints,
}

impl PKIKeyStore {
    /// Create a new PKI KeyStore adapter
    pub fn new(enhanced_store: EnhancedKeyStore) -> Self {
        Self {
            inner: enhanced_store,
            pki_metadata_cache: HashMap::new(),
            cert_key_mapping: HashMap::new(),
            default_policies: Self::default_policy_constraints(),
        }
    }

    /// Create PKI KeyStore with file backend
    pub fn with_file_backend<P: AsRef<std::path::Path>>(
        path: P,
        encryption_key: Option<Vec<u8>>,
    ) -> Result<Self> {
        use capsula_key::store::{create_key_store, KeyStoreConfig};
        
        let key_store = create_key_store(KeyStoreConfig::File {
            path: path.as_ref().to_path_buf(),
            encryption_key,
        }).map_err(|e| PkiError::KeyError(format!("Failed to create key store: {}", e)))?;
        
        let enhanced_store = EnhancedKeyStore::new(key_store);
        Ok(Self::new(enhanced_store))
    }

    /// Create PKI KeyStore with memory backend (for testing)
    pub fn with_memory_backend() -> Result<Self> {
        use capsula_key::store::{create_key_store, KeyStoreConfig};
        
        let key_store = create_key_store(KeyStoreConfig::Memory)
            .map_err(|e| PkiError::KeyError(format!("Failed to create key store: {}", e)))?;
        
        let enhanced_store = EnhancedKeyStore::new(key_store);
        Ok(Self::new(enhanced_store))
    }

    /// Store a key with PKI-specific metadata
    pub fn store_pki_key(
        &mut self,
        key: &dyn Key,
        usage: Vec<StoreKeyUsage>,
        validity: Option<KeyValidity>,
        policy_constraints: Option<PolicyConstraints>,
    ) -> Result<capsula_key::store::KeyHandle> {
        // Store in underlying enhanced store
        let handle = self.inner.store_key_object(key, usage.clone(), validity.clone())
            .map_err(|e| PkiError::KeyError(format!("Failed to store key: {}", e)))?;

        // Get the enhanced metadata
        let enhanced_metadata = self.inner.get_enhanced_metadata(handle)
            .map_err(|e| PkiError::KeyError(format!("Failed to get enhanced metadata: {}", e)))?;

        // Create PKI metadata
        let pki_metadata = PKIKeyMetadata {
            enhanced: enhanced_metadata,
            associated_certificates: Vec::new(),
            policy_constraints: policy_constraints.unwrap_or_else(|| self.default_policies.clone()),
            certificate_template: None,
            escrow_info: None,
        };

        // Cache PKI metadata
        self.pki_metadata_cache.insert(handle, pki_metadata);

        Ok(handle)
    }

    /// Retrieve a key by handle
    pub fn get_pki_key(&self, handle: capsula_key::store::KeyHandle) -> Result<Box<dyn Key>> {
        self.inner.get_key_object(handle)
            .map_err(|e| PkiError::KeyError(format!("Failed to retrieve key: {}", e)))
    }

    /// Get PKI-specific metadata for a key
    pub fn get_pki_metadata(&self, handle: capsula_key::store::KeyHandle) -> Result<&PKIKeyMetadata> {
        self.pki_metadata_cache.get(&handle)
            .ok_or_else(|| PkiError::KeyError(format!("PKI metadata not found for key: {:?}", handle)))
    }

    /// Associate a certificate with a key
    pub fn associate_certificate(
        &mut self,
        key_handle: capsula_key::store::KeyHandle,
        _certificate: &X509Certificate,
        cert_serial: String,
    ) -> Result<()> {
        // Update the enhanced store
        self.inner.associate_certificate(key_handle, cert_serial.clone())
            .map_err(|e| PkiError::KeyError(format!("Failed to associate certificate: {}", e)))?;

        // Update PKI metadata
        if let Some(pki_metadata) = self.pki_metadata_cache.get_mut(&key_handle) {
            if !pki_metadata.associated_certificates.contains(&cert_serial) {
                pki_metadata.associated_certificates.push(cert_serial.clone());
            }
        }

        // Update certificate-to-key mapping
        self.cert_key_mapping.insert(cert_serial, key_handle);

        Ok(())
    }

    /// Find key by associated certificate serial number
    pub fn find_key_by_certificate(&self, cert_serial: &str) -> Option<capsula_key::store::KeyHandle> {
        self.cert_key_mapping.get(cert_serial).copied()
    }

    /// Update PKI policy constraints for a key
    pub fn update_policy_constraints(
        &mut self,
        handle: capsula_key::store::KeyHandle,
        constraints: PolicyConstraints,
    ) -> Result<()> {
        if let Some(pki_metadata) = self.pki_metadata_cache.get_mut(&handle) {
            pki_metadata.policy_constraints = constraints;
            Ok(())
        } else {
            Err(PkiError::KeyError(format!("Key not found: {:?}", handle)))
        }
    }

    /// Set certificate template for a key
    pub fn set_certificate_template(
        &mut self,
        handle: capsula_key::store::KeyHandle,
        template: CertificateTemplate,
    ) -> Result<()> {
        if let Some(pki_metadata) = self.pki_metadata_cache.get_mut(&handle) {
            pki_metadata.certificate_template = Some(template);
            Ok(())
        } else {
            Err(PkiError::KeyError(format!("Key not found: {:?}", handle)))
        }
    }

    /// List all keys with their PKI information
    pub fn list_pki_keys(&self) -> Result<Vec<(capsula_key::store::KeyHandle, KeyAlgorithm, String, Vec<String>)>> {
        let basic_info = self.inner.list_keys_with_info()
            .map_err(|e| PkiError::KeyError(format!("Failed to list keys: {}", e)))?;

        let mut result = Vec::new();
        for (handle, algorithm, key_id) in basic_info {
            let associated_certs = self.pki_metadata_cache.get(&handle)
                .map(|meta| meta.associated_certificates.clone())
                .unwrap_or_default();
            result.push((handle, algorithm, key_id, associated_certs));
        }

        Ok(result)
    }

    /// Check if a key can be used for a specific certificate type
    pub fn can_sign_certificate_type(
        &self,
        handle: capsula_key::store::KeyHandle,
        cert_type: CertificateType,
    ) -> Result<bool> {
        let pki_metadata = self.get_pki_metadata(handle)?;
        Ok(pki_metadata.policy_constraints.allowed_cert_types.contains(&cert_type))
    }

    /// Delete a key and all its PKI metadata
    pub fn delete_pki_key(&mut self, handle: capsula_key::store::KeyHandle) -> Result<()> {
        // Remove from enhanced store
        self.inner.delete_key_complete(handle)
            .map_err(|e| PkiError::KeyError(format!("Failed to delete key: {}", e)))?;

        // Clean up PKI metadata and mappings
        if let Some(pki_metadata) = self.pki_metadata_cache.remove(&handle) {
            // Remove certificate mappings
            for cert_serial in &pki_metadata.associated_certificates {
                self.cert_key_mapping.remove(cert_serial);
            }
        }

        Ok(())
    }

    /// Get default PKI policy constraints
    fn default_policy_constraints() -> PolicyConstraints {
        PolicyConstraints {
            max_cert_validity_days: Some(365 * 2), // 2 years max
            allowed_cert_types: vec![CertificateType::EndEntity, CertificateType::TLSServer],
            min_key_strength: Some(2048), // RSA 2048 minimum
            allowed_signature_algorithms: vec![
                "sha256WithRSAEncryption".to_string(),
                "ecdsa-with-SHA256".to_string(),
                "ed25519".to_string(),
            ],
            extended_key_usage: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
        }
    }

    /// Check if key meets policy constraints for certificate generation
    pub fn validate_key_policy(
        &self,
        handle: capsula_key::store::KeyHandle,
        cert_type: CertificateType,
        validity_days: u32,
    ) -> Result<()> {
        let pki_metadata = self.get_pki_metadata(handle)?;
        let constraints = &pki_metadata.policy_constraints;

        // Check certificate type
        if !constraints.allowed_cert_types.contains(&cert_type) {
            return Err(PkiError::PolicyViolation(format!(
                "Certificate type {:?} not allowed for this key",
                cert_type
            )));
        }

        // Check validity period
        if let Some(max_days) = constraints.max_cert_validity_days {
            if validity_days > max_days {
                return Err(PkiError::PolicyViolation(format!(
                    "Certificate validity period {} days exceeds maximum {} days",
                    validity_days, max_days
                )));
            }
        }

        Ok(())
    }

    /// Get statistics about the PKI key store
    pub fn get_statistics(&self) -> Result<PKIKeyStoreStatistics> {
        let all_keys = self.list_pki_keys()?;
        
        let mut stats = PKIKeyStoreStatistics {
            total_keys: all_keys.len(),
            keys_by_algorithm: HashMap::new(),
            keys_by_certificate_type: HashMap::new(),
            total_associated_certificates: 0,
            keys_with_escrow: 0,
        };

        for (handle, algorithm, _, associated_certs) in &all_keys {
            // Count by algorithm
            *stats.keys_by_algorithm.entry(format!("{:?}", algorithm)).or_insert(0) += 1;
            
            // Count associated certificates
            stats.total_associated_certificates += associated_certs.len();

            // Check for escrow
            if let Ok(pki_metadata) = self.get_pki_metadata(*handle) {
                if pki_metadata.escrow_info.is_some() {
                    stats.keys_with_escrow += 1;
                }

                // Count by allowed certificate types
                for cert_type in &pki_metadata.policy_constraints.allowed_cert_types {
                    *stats.keys_by_certificate_type.entry(format!("{:?}", cert_type)).or_insert(0) += 1;
                }
            }
        }

        Ok(stats)
    }
}

/// PKI KeyStore statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PKIKeyStoreStatistics {
    pub total_keys: usize,
    pub keys_by_algorithm: HashMap<String, usize>,
    pub keys_by_certificate_type: HashMap<String, usize>,
    pub total_associated_certificates: usize,
    pub keys_with_escrow: usize,
}

impl Default for PolicyConstraints {
    fn default() -> Self {
        PKIKeyStore::default_policy_constraints()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsula_key::{Curve25519, P256Key};

    #[test]
    fn test_pki_keystore_creation() {
        let pki_store = PKIKeyStore::with_memory_backend().unwrap();
        assert_eq!(pki_store.pki_metadata_cache.len(), 0);
    }

    #[test]
    fn test_store_and_retrieve_pki_key() {
        let mut pki_store = PKIKeyStore::with_memory_backend().unwrap();
        
        // Generate test key
        let key = Curve25519::generate().unwrap();
        
        // Store with custom policy
        let custom_policy = PolicyConstraints {
            max_cert_validity_days: Some(90),
            allowed_cert_types: vec![CertificateType::EndEntity],
            ..Default::default()
        };
        
        let handle = pki_store.store_pki_key(
            &key,
            vec![StoreKeyUsage::DigitalSignature],
            None,
            Some(custom_policy.clone()),
        ).unwrap();

        // Retrieve key
        let retrieved_key = pki_store.get_pki_key(handle).unwrap();
        assert_eq!(retrieved_key.algorithm(), KeyAlgorithm::Ed25519);

        // Check PKI metadata
        let pki_metadata = pki_store.get_pki_metadata(handle).unwrap();
        assert_eq!(pki_metadata.policy_constraints.max_cert_validity_days, Some(90));
        assert_eq!(pki_metadata.policy_constraints.allowed_cert_types, vec![CertificateType::EndEntity]);
    }

    #[test]
    #[ignore] // TODO: Complete when X509Certificate integration is ready
    fn test_certificate_association() {
        let mut pki_store = PKIKeyStore::with_memory_backend().unwrap();
        
        let key = P256Key::generate().unwrap();
        let handle = pki_store.store_pki_key(
            &key,
            vec![StoreKeyUsage::DigitalSignature],
            None,
            None,
        ).unwrap();

        // TODO: This test will be completed once X509Certificate integration is ready
        let cert_serial = "test-cert-123";
        
        // For now, just test that the handle was created successfully
        assert!(pki_store.get_pki_key(handle).is_ok());
        
        // Future implementation:
        // let test_cert = create_test_certificate();
        // pki_store.associate_certificate(handle, &test_cert, cert_serial.to_string()).unwrap();
        // let found_handle = pki_store.find_key_by_certificate(cert_serial);
        // assert_eq!(found_handle, Some(handle));
    }

    #[test]
    fn test_policy_validation() {
        let mut pki_store = PKIKeyStore::with_memory_backend().unwrap();
        
        let key = Curve25519::generate().unwrap();
        let custom_policy = PolicyConstraints {
            max_cert_validity_days: Some(30),
            allowed_cert_types: vec![CertificateType::EndEntity],
            ..Default::default()
        };
        
        let handle = pki_store.store_pki_key(
            &key,
            vec![StoreKeyUsage::DigitalSignature],
            None,
            Some(custom_policy),
        ).unwrap();

        // Test valid policy
        assert!(pki_store.validate_key_policy(
            handle,
            CertificateType::EndEntity,
            30
        ).is_ok());

        // Test invalid certificate type
        assert!(pki_store.validate_key_policy(
            handle,
            CertificateType::RootCA,
            30
        ).is_err());

        // Test invalid validity period
        assert!(pki_store.validate_key_policy(
            handle,
            CertificateType::EndEntity,
            365
        ).is_err());
    }

    #[test]
    fn test_pki_keystore_statistics() {
        let mut pki_store = PKIKeyStore::with_memory_backend().unwrap();
        
        // Store different types of keys
        let curve25519_key = Curve25519::generate().unwrap();
        let p256_key = P256Key::generate().unwrap();
        
        pki_store.store_pki_key(
            &curve25519_key,
            vec![StoreKeyUsage::DigitalSignature],
            None,
            None,
        ).unwrap();
        
        pki_store.store_pki_key(
            &p256_key,
            vec![StoreKeyUsage::KeyAgreement],
            None,
            None,
        ).unwrap();

        let stats = pki_store.get_statistics().unwrap();
        assert_eq!(stats.total_keys, 2);
        assert!(stats.keys_by_algorithm.contains_key("Ed25519"));
        assert!(stats.keys_by_algorithm.contains_key("P256"));
    }
}