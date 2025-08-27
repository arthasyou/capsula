use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    Signature, Signer, SigningKey, VerifyingKey,
};
use std::sync::{Arc, Mutex};

use crate::{
    error::{Error, Result},
    provider::KeyProvider,
    store::{KeyMetadata, KeyStore, KeyStoreConfig, create_key_store},
    types::{Algorithm, KeyHandle},
};

pub struct Ed25519Provider {
    store: Arc<dyn KeyStore>,
    next_handle: Arc<Mutex<u64>>,
}

impl Ed25519Provider {
    /// Create a new Ed25519Provider with memory storage (backward compatibility)
    pub fn new() -> Result<Self> {
        Self::with_store_config(KeyStoreConfig::Memory)
    }
    
    /// Create a new Ed25519Provider with specified storage configuration
    pub fn with_store_config(config: KeyStoreConfig) -> Result<Self> {
        let store = create_key_store(config)?;
        
        Ok(Self {
            store: Arc::from(store),
            next_handle: Arc::new(Mutex::new(1)),
        })
    }
    
    /// Create a new Ed25519Provider with file storage
    pub fn with_file_store(path: std::path::PathBuf, encryption_key: Option<Vec<u8>>) -> Result<Self> {
        Self::with_store_config(KeyStoreConfig::File { path, encryption_key })
    }
    
    /// Create a new Ed25519Provider with HSM storage
    pub fn with_hsm_store(module_path: String, slot: u64, pin: Option<String>) -> Result<Self> {
        Self::with_store_config(KeyStoreConfig::Hsm { module_path, slot, pin })
    }

    fn generate_handle(&self) -> KeyHandle {
        let mut handle = self.next_handle.lock().unwrap();
        let current = *handle;
        *handle += 1;
        KeyHandle(current)
    }
}

impl Default for Ed25519Provider {
    fn default() -> Self {
        Self::new().expect("Failed to create default Ed25519Provider")
    }
}

impl KeyProvider for Ed25519Provider {
    fn generate(&self) -> Result<KeyHandle> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| Error::KeyError(format!("Failed to generate random bytes: {}", e)))?;
        let signing_key = SigningKey::from_bytes(&bytes);

        let handle = self.generate_handle();
        
        // Create metadata
        let metadata = KeyMetadata {
            handle,
            algorithm: Algorithm::Ed25519,
            created_at: std::time::SystemTime::now(),
            label: None,
            attributes: std::collections::HashMap::new(),
        };
        
        // Store the key material
        let key_material = signing_key.to_bytes().to_vec();
        self.store.store_key(metadata, key_material)?;

        Ok(handle)
    }

    fn get_alg(&self) -> Result<Algorithm> {
        Ok(Algorithm::Ed25519)
    }

    fn import_pkcs8_der(&self, der: &[u8]) -> Result<KeyHandle> {
        let signing_key = SigningKey::from_pkcs8_der(der)
            .map_err(|e| Error::ImportError(format!("Failed to import PKCS8 DER: {}", e)))?;

        let handle = self.generate_handle();
        
        // Create metadata
        let metadata = KeyMetadata {
            handle,
            algorithm: Algorithm::Ed25519,
            created_at: std::time::SystemTime::now(),
            label: Some("imported".to_string()),
            attributes: std::collections::HashMap::new(),
        };
        
        // Store the key material
        let key_material = signing_key.to_bytes().to_vec();
        self.store.store_key(metadata, key_material)?;

        Ok(handle)
    }

    fn export_pkcs8_der(&self, handle: KeyHandle) -> Result<Vec<u8>> {
        let (metadata, key_material) = self.store.get_key(handle)?;
        
        // Verify this is Ed25519
        if metadata.algorithm != Algorithm::Ed25519 {
            return Err(Error::KeyError("Invalid algorithm for Ed25519 provider".to_string()));
        }
        
        if key_material.len() != 32 {
            return Err(Error::KeyError("Invalid key material length".to_string()));
        }
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&key_material);
        let signing_key = SigningKey::from_bytes(&bytes);
        
        signing_key
            .to_pkcs8_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| Error::ExportError(format!("Failed to export PKCS8 DER: {}", e)))
    }

    fn public_spki_der(&self, handle: KeyHandle) -> Result<Vec<u8>> {
        let (metadata, key_material) = self.store.get_key(handle)?;
        
        // Verify this is Ed25519
        if metadata.algorithm != Algorithm::Ed25519 {
            return Err(Error::KeyError("Invalid algorithm for Ed25519 provider".to_string()));
        }
        
        if key_material.len() != 32 {
            return Err(Error::KeyError("Invalid key material length".to_string()));
        }
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&key_material);
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();

        verifying_key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| Error::ExportError(format!("Failed to export public key SPKI DER: {}", e)))
    }

    fn sign(&self, handle: KeyHandle, msg: &[u8]) -> Result<Vec<u8>> {
        let (metadata, key_material) = self.store.get_key(handle)?;
        
        // Verify this is Ed25519
        if metadata.algorithm != Algorithm::Ed25519 {
            return Err(Error::KeyError("Invalid algorithm for Ed25519 provider".to_string()));
        }
        
        if key_material.len() != 32 {
            return Err(Error::KeyError("Invalid key material length".to_string()));
        }
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&key_material);
        let signing_key = SigningKey::from_bytes(&bytes);

        let signature = signing_key.sign(msg);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::from_public_key_der(spki_der)
            .map_err(|e| Error::KeyError(format!("Failed to parse public key: {}", e)))?;

        let signature = Signature::from_slice(sig)
            .map_err(|e| Error::SignatureError(format!("Invalid signature format: {}", e)))?;

        Ok(verifying_key.verify_strict(msg, &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_generate_and_sign() {
        let provider = Ed25519Provider::new().unwrap();

        // Generate a key
        let handle = provider.generate().unwrap();

        // Sign a message
        let message = b"Hello, world!";
        let signature = provider.sign(handle, message).unwrap();

        // Get public key
        let public_key = provider.public_spki_der(handle).unwrap();

        // Verify signature
        let is_valid = provider.verify(&public_key, message, &signature).unwrap();
        assert!(is_valid);

        // Verify with wrong message should fail
        let wrong_message = b"Hello, world";
        let is_valid = provider
            .verify(&public_key, wrong_message, &signature)
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_import_export() {
        let provider = Ed25519Provider::new().unwrap();

        // Generate a key
        let handle1 = provider.generate().unwrap();

        // Export as PKCS8 DER
        let der = provider.export_pkcs8_der(handle1).unwrap();

        // Import the key
        let handle2 = provider.import_pkcs8_der(&der).unwrap();

        // Sign with both handles
        let message = b"Test message";
        let sig1 = provider.sign(handle1, message).unwrap();
        let sig2 = provider.sign(handle2, message).unwrap();

        // They should be different signatures (due to Ed25519 randomness)
        // But verification should work for both
        let pub1 = provider.public_spki_der(handle1).unwrap();
        let pub2 = provider.public_spki_der(handle2).unwrap();
        
        assert_eq!(pub1, pub2); // Same public key
        assert!(provider.verify(&pub1, message, &sig1).unwrap());
        assert!(provider.verify(&pub2, message, &sig2).unwrap());
    }
    
    #[test]
    fn test_file_storage() {
        let temp_dir = TempDir::new().unwrap();
        let provider = Ed25519Provider::with_file_store(
            temp_dir.path().to_path_buf(), 
            None
        ).unwrap();
        
        // Generate key
        let handle = provider.generate().unwrap();
        
        // Verify files were created
        assert!(temp_dir.path().join(format!("{}.key", handle.0)).exists());
        assert!(temp_dir.path().join(format!("{}.json", handle.0)).exists());
        
        // Use the key
        let message = b"File storage test";
        let signature = provider.sign(handle, message).unwrap();
        let public_key = provider.public_spki_der(handle).unwrap();
        
        assert!(provider.verify(&public_key, message, &signature).unwrap());
    }
    
    #[test]
    fn test_encrypted_file_storage() {
        let temp_dir = TempDir::new().unwrap();
        let encryption_key = vec![42u8; 32];
        let provider = Ed25519Provider::with_file_store(
            temp_dir.path().to_path_buf(), 
            Some(encryption_key)
        ).unwrap();
        
        // Generate key
        let handle = provider.generate().unwrap();
        
        // Use the key
        let message = b"Encrypted storage test";
        let signature = provider.sign(handle, message).unwrap();
        let public_key = provider.public_spki_der(handle).unwrap();
        
        assert!(provider.verify(&public_key, message, &signature).unwrap());
        
        // Verify the file is encrypted (different from plaintext)
        let key_file = temp_dir.path().join(format!("{}.key", handle.0));
        let encrypted_content = std::fs::read(&key_file).unwrap();
        assert_ne!(encrypted_content.len(), 32); // Should include nonce
    }
}