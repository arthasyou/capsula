//! Cryptographic hash functions and encoding utilities
//!
//! This module provides cryptographic hash functions for data integrity
//! and key derivation purposes, including SHA-256 and SHA-512.
//! It also includes Base64 encoding utilities.

pub mod base64;
pub mod sha;

// Re-export the hash algorithm enum
pub use sha::HashAlgorithm;
// Re-export generic hash functions
pub use sha::{hash, hash_hex, verify};
// Re-export convenience functions
pub use sha::{quick_hash, quick_hash_hex};
// Re-export SHA-256 specific functions
pub use sha::{sha256, sha256_hex, sha256_verify};
// Re-export SHA-512 specific functions
pub use sha::{sha512, sha512_hex, sha512_verify};
// Re-export SHA types from sha2 crate for convenience
pub use sha2::{Sha256, Sha512};
