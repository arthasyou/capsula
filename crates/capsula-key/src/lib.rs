pub mod error;
pub mod key;
pub mod signature;
pub mod store;

// Re-export core functionality
pub use key::{
    Algorithm, Curve25519, ExportablePrivateKey, Key, KeyAgree, KeyCapabilities, KeyEncDec,
    KeyExportInfo, KeyFileIO, KeyMetadata, KeySign, KeyUsage, P256Key, PublicKeyExportInfo,
    PublicKeyInfo, PublicKeySet, RsaKey,
};
// Re-export signature types
pub use signature::{
    verify_signature_standalone, DigitalSignature, ExtendedSignatureInfo, LocationInfo,
};
// Re-export store types
pub use store::{create_key_store, KeyStore, KeyStoreConfig};

// For backward compatibility
pub type OldKey = Curve25519;
