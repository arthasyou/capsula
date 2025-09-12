//! Capsula Cryptography Library
//!
//! This library provides cryptographic primitives for the Capsula project,
//! including asymmetric encryption, symmetric encryption, key derivation,
//! and hashing algorithms.

pub mod error;
pub mod utils;

// Cryptographic algorithm modules
pub mod asymmetric;
pub mod hash;
pub mod kdf;
pub mod symmetric;

// Re-export commonly used types for convenience
pub use asymmetric::{ed25519::Ed25519, p256::P256, rsa::Rsa, x25519::X25519, verify_signature};
pub use hash::{
    hash, hash_hex, verify, HashAlgorithm,
    sha256, sha256_hex, sha256_verify, 
    sha512, sha512_hex, sha512_verify,
    quick_hash, quick_hash_hex
};
pub use kdf::{derive_key32, derive_many};
pub use symmetric::{aes::Aes, chacha::ChaCha};
