use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use super::{KeyHandle, KeyMetadata, KeyStore};
use crate::error::{Error, Result};

/// Type alias for the key storage map
type KeyStorage = Arc<RwLock<HashMap<KeyHandle, (KeyMetadata, Vec<u8>)>>>;

/// In-memory key store implementation
pub struct MemoryKeyStore {
    keys: KeyStorage,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for MemoryKeyStore {
    fn store_key(&self, metadata: KeyMetadata, pkcs8_der_bytes: Vec<u8>) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| Error::Other("Failed to acquire write lock".to_string()))?;

        if keys.contains_key(&metadata.handle) {
            return Err(Error::key_exists(metadata.handle));
        }

        keys.insert(metadata.handle, (metadata, pkcs8_der_bytes));
        Ok(())
    }

    fn get_key(&self, handle: KeyHandle) -> Result<(KeyMetadata, Vec<u8>)> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::Other("Failed to acquire read lock".to_string()))?;

        keys.get(&handle)
            .cloned()
            .ok_or_else(|| Error::key_not_found(handle))
    }

    fn delete_key(&self, handle: KeyHandle) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| Error::Other("Failed to acquire write lock".to_string()))?;

        keys.remove(&handle)
            .ok_or_else(|| Error::key_not_found(handle))
            .map(|_| ())
    }

    fn list_keys(&self) -> Result<Vec<KeyHandle>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::Other("Failed to acquire read lock".to_string()))?;

        let mut handles: Vec<KeyHandle> = keys.keys().cloned().collect();
        handles.sort_by_key(|h| h.0);
        Ok(handles)
    }

    fn exists(&self, handle: KeyHandle) -> Result<bool> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::Other("Failed to acquire read lock".to_string()))?;

        Ok(keys.contains_key(&handle))
    }

    fn get_metadata(&self, handle: KeyHandle) -> Result<KeyMetadata> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::Other("Failed to acquire read lock".to_string()))?;

        keys.get(&handle)
            .map(|(metadata, _)| metadata.clone())
            .ok_or_else(|| Error::key_not_found(handle))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use capsula_crypto::Algorithm;

    use super::*;

    #[test]
    fn test_memory_store_basic_operations() {
        let store = MemoryKeyStore::new();
        let handle = KeyHandle(1);

        let metadata = KeyMetadata {
            handle,
            algorithm: Algorithm::Ed25519,
            created_at: std::time::SystemTime::now(),
            label: Some("test-key".to_string()),
            attributes: HashMap::new(),
        };

        let pkcs8_der_bytes = vec![42; 32];

        // Store key
        store
            .store_key(metadata.clone(), pkcs8_der_bytes.clone())
            .unwrap();

        // Check exists
        assert!(store.exists(handle).unwrap());

        // Get key
        let (retrieved_metadata, retrieved_material) = store.get_key(handle).unwrap();
        assert_eq!(retrieved_metadata.handle, metadata.handle);
        assert_eq!(retrieved_material, pkcs8_der_bytes);

        // Get metadata only
        let retrieved_metadata = store.get_metadata(handle).unwrap();
        assert_eq!(retrieved_metadata.handle, metadata.handle);

        // List keys
        let keys = store.list_keys().unwrap();
        assert_eq!(keys, vec![handle]);

        // Delete key
        store.delete_key(handle).unwrap();
        assert!(!store.exists(handle).unwrap());
    }

    #[test]
    fn test_memory_store_duplicate_key() {
        let store = MemoryKeyStore::new();
        let handle = KeyHandle(1);

        let metadata = KeyMetadata {
            handle,
            algorithm: Algorithm::Ed25519,
            created_at: std::time::SystemTime::now(),
            label: None,
            attributes: HashMap::new(),
        };

        let pkcs8_der_bytes = vec![42; 32];

        // First store should succeed
        store
            .store_key(metadata.clone(), pkcs8_der_bytes.clone())
            .unwrap();

        // Second store should fail
        let result = store.store_key(metadata, pkcs8_der_bytes);
        assert!(result.is_err());
    }
}
