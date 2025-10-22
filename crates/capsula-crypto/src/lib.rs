//! Capsula Cryptography Library
//!
//! This library provides cryptographic primitives for the Capsula project,
//! including asymmetric encryption, symmetric encryption, key derivation,
//! and hashing algorithms.

pub mod error;
pub mod utils;

// Cryptographic algorithm modules
pub mod asymmetric;
pub mod encoding;
pub mod hash;
pub mod kdf;
pub mod symmetric;

// Re-export commonly used types for convenience

pub use asymmetric::{ed25519::Ed25519, p256::P256, rsa::Rsa, verify_signature, x25519::X25519};
pub use encoding::{
    decrypt_dek_with_algorithm, encrypt_dek_with_algorithm, parse_algorithm_from_spki, Algorithm,
};
pub use hash::{
    base64, hash, hash_hex, quick_hash, quick_hash_hex, sha256, sha256_hex, sha256_verify, sha512,
    sha512_hex, sha512_verify, verify, HashAlgorithm,
};
pub use kdf::{derive_key32, derive_many};
pub use symmetric::{
    aead::{decrypt_aead, encrypt_aead, generate_id, generate_key, generate_nonce, AeadCipher},
    aes::Aes,
    chacha::ChaCha,
};
