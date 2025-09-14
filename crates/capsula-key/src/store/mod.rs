mod enhanced;
mod file;
mod hsm;
mod memory;

pub use enhanced::{EnhancedKeyStore, EnhancedKeyMetadata, KeyUsage, KeyValidity, BackupStatus};
pub use file::FileKeyStore;
pub use hsm::HsmKeyStore;
pub use memory::MemoryKeyStore;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::key::Algorithm;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct KeyHandle(pub u64);

/// Key metadata stored alongside the key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub handle: KeyHandle,
    pub algorithm: Algorithm,
    pub created_at: std::time::SystemTime,
    pub label: Option<String>,
    pub attributes: std::collections::HashMap<String, String>,
}

/// Trait for key storage backends (synchronous)
pub trait KeyStore: Send + Sync {
    /// Store a key with its metadata
    fn store_key(&self, metadata: KeyMetadata, key_material: Vec<u8>) -> Result<()>;

    /// Retrieve a key by its handle
    fn get_key(&self, handle: KeyHandle) -> Result<(KeyMetadata, Vec<u8>)>;

    /// Delete a key by its handle
    fn delete_key(&self, handle: KeyHandle) -> Result<()>;

    /// List all key handles
    fn list_keys(&self) -> Result<Vec<KeyHandle>>;

    /// Check if a key exists
    fn exists(&self, handle: KeyHandle) -> Result<bool>;

    /// Get metadata without the key material (for listing purposes)
    fn get_metadata(&self, handle: KeyHandle) -> Result<KeyMetadata>;
}

/// Key storage configuration
#[derive(Clone, Debug)]
pub enum KeyStoreConfig {
    Memory,
    File {
        path: std::path::PathBuf,
        encryption_key: Option<Vec<u8>>,
    },
    Hsm {
        module_path: String,
        slot: u64,
        pin: Option<String>,
    },
}

/// Factory function to create a key store based on configuration
pub fn create_key_store(config: KeyStoreConfig) -> Result<Box<dyn KeyStore>> {
    match config {
        KeyStoreConfig::Memory => Ok(Box::new(MemoryKeyStore::new())),
        KeyStoreConfig::File {
            path,
            encryption_key,
        } => Ok(Box::new(FileKeyStore::new(path, encryption_key)?)),
        KeyStoreConfig::Hsm {
            module_path,
            slot,
            pin,
        } => Ok(Box::new(HsmKeyStore::new(module_path, slot, pin)?)),
    }
}
