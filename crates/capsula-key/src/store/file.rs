use super::{KeyMetadata, KeyStore};
use crate::error::{Error, Result};
use crate::types::KeyHandle;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// File-based key store with optional encryption
pub struct FileKeyStore {
    path: PathBuf,
    cipher: Option<ChaCha20Poly1305>,
    lock: Arc<RwLock<()>>,
}

impl FileKeyStore {
    pub fn new(path: PathBuf, encryption_key: Option<Vec<u8>>) -> Result<Self> {
        // Validate encryption key if provided
        let cipher = if let Some(key) = encryption_key {
            if key.len() != 32 {
                return Err(Error::invalid_configuration(
                    "Encryption key must be 32 bytes for ChaCha20Poly1305"
                ));
            }
            let cipher = ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|e| Error::invalid_configuration(e))?;
            Some(cipher)
        } else {
            None
        };
        
        Ok(Self {
            path,
            cipher,
            lock: Arc::new(RwLock::new(())),
        })
    }
    
    /// Generate filename identifier for key material files
    fn key_filename(handle: KeyHandle) -> String {
        format!("{}.key", handle.0)
    }
    
    /// Generate metadata filename
    fn metadata_filename(handle: KeyHandle) -> String {
        format!("{}.json", handle.0)
    }
    
    /// Encrypt data using ChaCha20Poly1305
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if let Some(cipher) = &self.cipher {
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            
            let ciphertext = cipher
                .encrypt(&nonce, plaintext)
                .map_err(|e| Error::encryption(e))?;
            
            // Prepend nonce to ciphertext
            let mut result = nonce.to_vec();
            result.extend_from_slice(&ciphertext);
            
            Ok(result)
        } else {
            Ok(plaintext.to_vec())
        }
    }
    
    /// Decrypt data using ChaCha20Poly1305
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if let Some(cipher) = &self.cipher {
            if ciphertext.len() < 12 {
                return Err(Error::decryption("Invalid ciphertext length"));
            }
            
            let (nonce_bytes, encrypted) = ciphertext.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);
            
            cipher
                .decrypt(nonce, encrypted)
                .map_err(|e| Error::decryption(e))
        } else {
            Ok(ciphertext.to_vec())
        }
    }
}

impl KeyStore for FileKeyStore {
    fn store_key(&self, metadata: KeyMetadata, key_material: Vec<u8>) -> Result<()> {
        // Ensure directory exists
        if !self.path.exists() {
            std::fs::create_dir_all(&self.path)?;
        }
        
        let _guard = self.lock.write().map_err(|_| Error::Other("Failed to acquire write lock".to_string()))?;
        
        // Check if key already exists
        let key_path = self.path.join(Self::key_filename(metadata.handle));
        if key_path.exists() {
            return Err(Error::key_exists(metadata.handle));
        }
        
        // Encrypt key material if encryption is enabled
        let encrypted_material = self.encrypt(&key_material)?;
        
        // Write key material
        std::fs::write(&key_path, &encrypted_material)?;
        
        // Write metadata
        let metadata_path = self.path.join(Self::metadata_filename(metadata.handle));
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        std::fs::write(&metadata_path, metadata_json)?;
        
        Ok(())
    }
    
    fn get_key(&self, handle: KeyHandle) -> Result<(KeyMetadata, Vec<u8>)> {
        let _guard = self.lock.read().map_err(|_| Error::Other("Failed to acquire read lock".to_string()))?;
        
        // Read metadata
        let metadata_path = self.path.join(Self::metadata_filename(handle));
        let metadata_json = std::fs::read_to_string(&metadata_path)
            .map_err(|_| Error::key_not_found(handle))?;
        let metadata: KeyMetadata = serde_json::from_str(&metadata_json)?;
        
        // Read and decrypt key material
        let key_path = self.path.join(Self::key_filename(handle));
        let encrypted_material = std::fs::read(&key_path)
            .map_err(|_| Error::key_not_found(handle))?;
        let key_material = self.decrypt(&encrypted_material)?;
        
        Ok((metadata, key_material))
    }
    
    fn delete_key(&self, handle: KeyHandle) -> Result<()> {
        let _guard = self.lock.write().map_err(|_| Error::Other("Failed to acquire write lock".to_string()))?;
        
        let key_path = self.path.join(Self::key_filename(handle));
        let metadata_path = self.path.join(Self::metadata_filename(handle));
        
        // Check if key exists
        if !key_path.exists() {
            return Err(Error::key_not_found(handle));
        }
        
        // Delete both files
        std::fs::remove_file(&key_path)?;
        std::fs::remove_file(&metadata_path)?;
        
        Ok(())
    }
    
    fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        let _guard = self.lock.read().map_err(|_| Error::Other("Failed to acquire read lock".to_string()))?;
        
        let mut handles = Vec::new();
        
        let entries = std::fs::read_dir(&self.path)?;
        for entry in entries {
            let entry = entry?;
            if let Some(filename) = entry.file_name().to_str() {
                if filename.ends_with(".json") {
                    // Parse handle from filename
                    if let Some(handle_str) = filename.strip_suffix(".json") {
                        if let Ok(handle_num) = handle_str.parse::<u64>() {
                            handles.push(KeyHandle(handle_num));
                        }
                    }
                }
            }
        }
        
        handles.sort_by_key(|h| h.0);
        Ok(handles)
    }
    
    fn exists(&self, handle: KeyHandle) -> Result<bool> {
        let _guard = self.lock.read().map_err(|_| Error::Other("Failed to acquire read lock".to_string()))?;
        let key_path = self.path.join(Self::key_filename(handle));
        Ok(key_path.exists())
    }
    
    fn get_metadata(&self, handle: KeyHandle) -> Result<KeyMetadata> {
        let _guard = self.lock.read().map_err(|_| Error::Other("Failed to acquire read lock".to_string()))?;
        
        let metadata_path = self.path.join(Self::metadata_filename(handle));
        let metadata_json = std::fs::read_to_string(&metadata_path)
            .map_err(|_| Error::key_not_found(handle))?;
        
        let metadata: KeyMetadata = serde_json::from_str(&metadata_json)?;
        Ok(metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Algorithm;
    use tempfile::TempDir;
    use std::collections::HashMap;
    
    #[test]
    fn test_file_store() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileKeyStore::new(temp_dir.path().to_path_buf(), None).unwrap();
        
        // Create test metadata
        let metadata = KeyMetadata {
            handle: KeyHandle(1),
            algorithm: Algorithm::Ed25519,
            created_at: std::time::SystemTime::now(),
            label: Some("test-key".to_string()),
            attributes: HashMap::new(),
        };
        
        let key_material = vec![1, 2, 3, 4, 5];
        
        // Store key
        store.store_key(metadata.clone(), key_material.clone()).unwrap();
        
        // Check files were created
        assert!(temp_dir.path().join("1.key").exists());
        assert!(temp_dir.path().join("1.json").exists());
        
        // Get key
        let (retrieved_metadata, retrieved_material) = store.get_key(KeyHandle(1)).unwrap();
        assert_eq!(retrieved_metadata.handle, metadata.handle);
        assert_eq!(retrieved_material, key_material);
        
        // List keys
        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&KeyHandle(1)));
        
        // Delete key
        store.delete_key(KeyHandle(1)).unwrap();
        assert!(!temp_dir.path().join("1.key").exists());
        assert!(!temp_dir.path().join("1.json").exists());
    }
    
    #[test]
    fn test_file_store_with_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let encryption_key = vec![0u8; 32]; // 32 bytes for ChaCha20Poly1305
        let store = FileKeyStore::new(temp_dir.path().to_path_buf(), Some(encryption_key)).unwrap();
        
        let metadata = KeyMetadata {
            handle: KeyHandle(1),
            algorithm: Algorithm::Ed25519,
            created_at: std::time::SystemTime::now(),
            label: Some("encrypted-key".to_string()),
            attributes: HashMap::new(),
        };
        
        let key_material = vec![42; 32];
        
        // Store encrypted key
        store.store_key(metadata.clone(), key_material.clone()).unwrap();
        
        // Read raw file - should be encrypted
        let raw_key = std::fs::read(temp_dir.path().join("1.key")).unwrap();
        assert_ne!(raw_key, key_material); // Should be different due to encryption
        
        // Get key through store - should be decrypted
        let (_, retrieved_material) = store.get_key(KeyHandle(1)).unwrap();
        assert_eq!(retrieved_material, key_material);
    }
}