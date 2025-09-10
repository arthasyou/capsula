pub mod error;
pub mod key;
pub mod signature;
pub mod store;

// Re-export core functionality
pub use key::{verify, Key, KeyMetadata, PublicKeyInfo};

// Re-export signature types
pub use signature::{
    verify_signature_standalone, DigitalSignature, ExtendedSignatureInfo, LocationInfo,
};

// Re-export store types
pub use store::{create_key_store, KeyStore, KeyStoreConfig};