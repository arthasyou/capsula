pub mod error;
pub mod key;
pub mod signature;
pub mod store;

// Re-export core functionality
pub use key::{
    util::{load_signing_key_from_pkcs8_der, load_signing_key_from_pkcs8_pem},
    Curve25519, Key, KeyAgree, KeyCapabilities, KeyEncDec, KeyExport, KeyExportInfo, KeyFileIO,
    KeyMetadata, KeySign, KeyUsage, P256Key, PublicKeyExportInfo, PublicKeyInfo, PublicKeySet,
    RsaKey, SigningKey,
};
// Re-export signature types
pub use signature::DigitalSignature;
// Re-export store types
pub use store::{create_key_store, KeyStore, KeyStoreConfig};

// For backward compatibility
pub type OldKey = Curve25519;
