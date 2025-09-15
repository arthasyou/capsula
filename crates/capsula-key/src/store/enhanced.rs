//! Enhanced KeyStore implementation with Key trait integration
//!
//! This module provides a higher-level KeyStore API that works directly with
//! Key trait objects, providing automatic serialization/deserialization.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::{KeyHandle, KeyMetadata, KeyStore};
use crate::{
    error::{Error, Result},
    key::{Algorithm, Curve25519, ExportablePrivateKey, Key, P256Key, RsaKey},
};

/// Enhanced key metadata with more PKI-specific information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnhancedKeyMetadata {
    /// Basic key metadata
    pub base: KeyMetadata,
    /// Key usage restrictions
    pub usage: Vec<KeyUsage>,
    /// Key validity period
    pub validity: Option<KeyValidity>,
    /// Associated certificate serial number (if any)
    pub cert_serial: Option<String>,
    /// Key backup status
    pub backup_status: BackupStatus,
    /// Custom attributes for PKI-specific metadata
    pub pki_attributes: HashMap<String, String>,
}

/// Key usage types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUsage {
    /// Digital signature
    DigitalSignature,
    /// Key encipherment  
    KeyEncipherment,
    /// Data encipherment
    DataEncipherment,
    /// Key agreement
    KeyAgreement,
    /// Certificate signing
    CertSigning,
    /// CRL signing
    CRLSigning,
    /// OCSP signing
    OCSPSigning,
}

/// Key validity period
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyValidity {
    /// Key activation time
    pub not_before: std::time::SystemTime,
    /// Key expiration time
    pub not_after: std::time::SystemTime,
}

/// Key backup status
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupStatus {
    /// No backup
    None,
    /// Backed up to secure storage
    SecureStorage,
    /// Backed up with key escrow
    Escrow,
    /// HSM-protected (cannot backup)
    HsmProtected,
}

/// Enhanced KeyStore that works with Key trait objects
pub struct EnhancedKeyStore {
    inner: Box<dyn KeyStore>,
    key_registry: HashMap<KeyHandle, Algorithm>,
    metadata_cache: HashMap<KeyHandle, EnhancedKeyMetadata>,
}

impl EnhancedKeyStore {
    /// Create a new enhanced key store
    pub fn new(inner: Box<dyn KeyStore>) -> Self {
        Self {
            inner,
            key_registry: HashMap::new(),
            metadata_cache: HashMap::new(),
        }
    }

    /// Store a Key trait object with enhanced metadata
    pub fn store_key_object(
        &mut self,
        key: &dyn Key,
        usage: Vec<KeyUsage>,
        validity: Option<KeyValidity>,
    ) -> Result<KeyHandle> {
        let handle = self.generate_handle();
        let algorithm = key.algorithm();

        // Create base metadata with enhanced data in attributes for persistence
        let mut attributes = HashMap::new();
        attributes.insert("usage".to_string(), serde_json::to_string(&usage)?);
        attributes.insert("validity".to_string(), serde_json::to_string(&validity)?);
        attributes.insert(
            "cert_serial".to_string(),
            serde_json::to_string(&None::<String>)?,
        );
        attributes.insert(
            "backup_status".to_string(),
            serde_json::to_string(&BackupStatus::None)?,
        );

        let metadata = KeyMetadata {
            handle,
            algorithm,
            created_at: std::time::SystemTime::now(),
            label: Some(key.key_id_hex()),
            attributes,
        };

        let enhanced_metadata = EnhancedKeyMetadata {
            base: metadata.clone(),
            usage,
            validity,
            cert_serial: None,
            backup_status: BackupStatus::None,
            pki_attributes: HashMap::new(),
        };

        // Serialize the key using PKCS#8 format
        let pkcs8_der_bytes = self.serialize_key(key)?;

        // Store the key and metadata
        self.inner.store_key(metadata, pkcs8_der_bytes)?;

        // Cache enhanced metadata
        self.metadata_cache.insert(handle, enhanced_metadata);

        // Update registry
        self.key_registry.insert(handle, algorithm);

        Ok(handle)
    }

    /// Retrieve a Key trait object by handle
    pub fn get_key_object(&self, handle: KeyHandle) -> Result<Box<dyn Key>> {
        let (metadata, pkcs8_der_bytes) = self.inner.get_key(handle)?;

        // Deserialize based on algorithm
        let key = self.deserialize_key(metadata.algorithm, &pkcs8_der_bytes)?;

        Ok(key)
    }

    /// Get enhanced metadata for a key
    pub fn get_enhanced_metadata(&self, handle: KeyHandle) -> Result<EnhancedKeyMetadata> {
        // First try cache
        if let Some(cached_metadata) = self.metadata_cache.get(&handle) {
            return Ok(cached_metadata.clone());
        }

        // Fallback to loading from stored attributes
        let base_metadata = self.inner.get_metadata(handle)?;

        let usage = base_metadata
            .attributes
            .get("usage")
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or_else(|| vec![KeyUsage::DigitalSignature]);

        let validity = base_metadata
            .attributes
            .get("validity")
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or(None);

        let cert_serial = base_metadata
            .attributes
            .get("cert_serial")
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or(None);

        let backup_status = base_metadata
            .attributes
            .get("backup_status")
            .and_then(|v| serde_json::from_str(v).ok())
            .unwrap_or(BackupStatus::None);

        // Extract PKI attributes (those with pki_ prefix)
        let mut pki_attributes = HashMap::new();
        for (key, value) in &base_metadata.attributes {
            if let Some(pki_key) = key.strip_prefix("pki_") {
                pki_attributes.insert(pki_key.to_string(), value.clone());
            }
        }

        Ok(EnhancedKeyMetadata {
            base: base_metadata,
            usage,
            validity,
            cert_serial,
            backup_status,
            pki_attributes,
        })
    }

    /// Update enhanced metadata for a key
    pub fn update_enhanced_metadata(
        &mut self,
        handle: KeyHandle,
        metadata: &EnhancedKeyMetadata,
    ) -> Result<()> {
        // Update cache
        self.metadata_cache.insert(handle, metadata.clone());

        // Note: This doesn't update the persistent storage since KeyStore doesn't provide
        // a method to update metadata. The updated metadata will be lost when the
        // EnhancedKeyStore is dropped. For full persistence, consider using a separate
        // metadata store or extending the KeyStore trait.

        Ok(())
    }

    /// List all keys with their basic information
    pub fn list_keys_with_info(&self) -> Result<Vec<(KeyHandle, Algorithm, String)>> {
        let handles = self.inner.list_keys()?;
        let mut result = Vec::new();

        for handle in handles {
            if let Ok(metadata) = self.inner.get_metadata(handle) {
                let key_id = metadata.label.unwrap_or_else(|| "unlabeled".to_string());
                result.push((handle, metadata.algorithm, key_id));
            }
        }

        Ok(result)
    }

    /// Delete a key and its metadata
    pub fn delete_key_complete(&mut self, handle: KeyHandle) -> Result<()> {
        self.inner.delete_key(handle)?;
        self.metadata_cache.remove(&handle);
        self.key_registry.remove(&handle);
        Ok(())
    }

    /// Check if a key exists
    pub fn exists(&self, handle: KeyHandle) -> Result<bool> {
        self.inner.exists(handle)
    }

    /// Associate a certificate with a key
    pub fn associate_certificate(&mut self, handle: KeyHandle, cert_serial: String) -> Result<()> {
        let mut metadata = self.get_enhanced_metadata(handle)?;
        metadata.cert_serial = Some(cert_serial);
        self.update_enhanced_metadata(handle, &metadata)
    }

    /// Update key backup status
    pub fn update_backup_status(&mut self, handle: KeyHandle, status: BackupStatus) -> Result<()> {
        let mut metadata = self.get_enhanced_metadata(handle)?;
        metadata.backup_status = status;
        self.update_enhanced_metadata(handle, &metadata)
    }

    // Private helper methods

    /// Generate a new unique key handle
    fn generate_handle(&self) -> KeyHandle {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
            time::SystemTime,
        };

        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        self.key_registry.len().hash(&mut hasher);

        KeyHandle(hasher.finish())
    }

    /// Serialize a Key trait object to bytes using PKCS#8
    fn serialize_key(&self, key: &dyn Key) -> Result<Vec<u8>> {
        match key.algorithm() {
            Algorithm::Ed25519 => {
                // Safely downcast to Curve25519
                let curve25519 = key.as_any().downcast_ref::<Curve25519>().ok_or_else(|| {
                    Error::KeyError("Failed to downcast to Curve25519".to_string())
                })?;

                curve25519.to_pkcs8_der().map_err(|e| {
                    Error::EncodingError(format!("Failed to serialize Curve25519: {}", e))
                })
            }
            Algorithm::P256 => {
                let p256_key = key
                    .as_any()
                    .downcast_ref::<P256Key>()
                    .ok_or_else(|| Error::KeyError("Failed to downcast to P256Key".to_string()))?;

                p256_key.to_pkcs8_der().map_err(|e| {
                    Error::EncodingError(format!("Failed to serialize P256Key: {}", e))
                })
            }
            Algorithm::Rsa => {
                let rsa_key = key
                    .as_any()
                    .downcast_ref::<RsaKey>()
                    .ok_or_else(|| Error::KeyError("Failed to downcast to RsaKey".to_string()))?;

                rsa_key
                    .to_pkcs8_der()
                    .map_err(|e| Error::EncodingError(format!("Failed to serialize RsaKey: {}", e)))
            }
            Algorithm::X25519 => {
                // X25519 is handled as part of Curve25519
                Err(Error::KeyError(
                    "X25519 should be part of Curve25519".to_string(),
                ))
            }
        }
    }

    /// Deserialize bytes to a Key trait object
    fn deserialize_key(
        &self,
        algorithm: Algorithm,
        pkcs8_der_bytes: &[u8],
    ) -> Result<Box<dyn Key>> {
        match algorithm {
            Algorithm::Ed25519 => {
                let curve25519 = Curve25519::from_pkcs8_der(pkcs8_der_bytes).map_err(|e| {
                    Error::EncodingError(format!("Failed to deserialize Curve25519: {}", e))
                })?;
                Ok(Box::new(curve25519))
            }
            Algorithm::P256 => {
                let p256_key = P256Key::from_pkcs8_der(pkcs8_der_bytes).map_err(|e| {
                    Error::EncodingError(format!("Failed to deserialize P256Key: {}", e))
                })?;
                Ok(Box::new(p256_key))
            }
            Algorithm::Rsa => {
                let rsa_key = RsaKey::from_pkcs8_der(pkcs8_der_bytes).map_err(|e| {
                    Error::EncodingError(format!("Failed to deserialize RsaKey: {}", e))
                })?;
                Ok(Box::new(rsa_key))
            }
            Algorithm::X25519 => Err(Error::KeyError(
                "X25519 should be part of Curve25519".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{create_key_store, KeyStoreConfig};

    #[test]
    fn test_enhanced_key_store_basic_operations() {
        let memory_store = create_key_store(KeyStoreConfig::Memory).unwrap();
        let mut enhanced_store = EnhancedKeyStore::new(memory_store);

        // Generate a test key
        let key = Curve25519::generate().unwrap();
        let key_id_before = key.key_id_hex();

        // Store the key
        let handle = enhanced_store
            .store_key_object(
                &key,
                vec![KeyUsage::DigitalSignature, KeyUsage::CertSigning],
                None,
            )
            .unwrap();

        // Check if key exists
        assert!(enhanced_store.exists(handle).unwrap());

        // Retrieve the key
        let retrieved_key = enhanced_store.get_key_object(handle).unwrap();
        assert_eq!(retrieved_key.key_id_hex(), key_id_before);

        // Get metadata
        let metadata = enhanced_store.get_enhanced_metadata(handle).unwrap();
        assert_eq!(metadata.base.handle, handle);
        assert_eq!(metadata.base.algorithm, Algorithm::Ed25519);

        // List keys
        let keys = enhanced_store.list_keys_with_info().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, handle);

        // Associate with certificate
        enhanced_store
            .associate_certificate(handle, "cert-123".to_string())
            .unwrap();

        // Update backup status
        enhanced_store
            .update_backup_status(handle, BackupStatus::SecureStorage)
            .unwrap();

        // Delete key
        enhanced_store.delete_key_complete(handle).unwrap();
        assert!(!enhanced_store.exists(handle).unwrap());
    }

    #[test]
    fn test_multiple_key_types() {
        let memory_store = create_key_store(KeyStoreConfig::Memory).unwrap();
        let mut enhanced_store = EnhancedKeyStore::new(memory_store);

        // Store Curve25519 key
        let curve25519_key = Curve25519::generate().unwrap();
        let handle1 = enhanced_store
            .store_key_object(&curve25519_key, vec![KeyUsage::DigitalSignature], None)
            .unwrap();

        // Store P256 key
        let p256_key = P256Key::generate().unwrap();
        let handle2 = enhanced_store
            .store_key_object(&p256_key, vec![KeyUsage::KeyAgreement], None)
            .unwrap();

        // Store RSA key
        let rsa_key = RsaKey::generate_2048().unwrap();
        let handle3 = enhanced_store
            .store_key_object(
                &rsa_key,
                vec![KeyUsage::DigitalSignature, KeyUsage::DataEncipherment],
                None,
            )
            .unwrap();

        // Verify all keys can be retrieved
        let retrieved1 = enhanced_store.get_key_object(handle1).unwrap();
        let retrieved2 = enhanced_store.get_key_object(handle2).unwrap();
        let retrieved3 = enhanced_store.get_key_object(handle3).unwrap();

        assert_eq!(retrieved1.algorithm(), Algorithm::Ed25519);
        assert_eq!(retrieved2.algorithm(), Algorithm::P256);
        assert_eq!(retrieved3.algorithm(), Algorithm::Rsa);

        // List should show all keys
        let keys = enhanced_store.list_keys_with_info().unwrap();
        assert_eq!(keys.len(), 3);

        // Test metadata persistence and caching
        let metadata3 = enhanced_store.get_enhanced_metadata(handle3).unwrap();
        assert_eq!(
            metadata3.usage,
            vec![KeyUsage::DigitalSignature, KeyUsage::DataEncipherment]
        );
        assert_eq!(metadata3.backup_status, BackupStatus::None);
    }
}
