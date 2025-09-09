//! Capsula Cryptographic Library
//! 
//! A simple, direct cryptographic library providing essential algorithms:
//! - Ed25519 for signatures
//! - X25519 for key exchange
//! - P256 for ECDSA signatures
//! - SHA-256 for hashing
//! 
//! All functions are stateless and take keys as byte arrays directly.

pub mod algorithm;
pub mod ed25519;
pub mod p256;
pub mod sha256;
pub mod utils;
pub mod x25519;

// Re-export commonly used functions at the crate root for convenience
pub use algorithm::{Algorithm, KeyPair, generate_key, generate_key_from_seed, generate_key_to_file, generate_key_to_file_auto};
pub use ed25519::{generate_keypair as generate_ed25519_keypair, sign as sign_ed25519, verify as verify_ed25519};
pub use p256::{generate_keypair as generate_p256_keypair, sign as sign_p256, verify as verify_p256};
pub use sha256::{hash as sha256_hash, hash_hex as sha256_hex, verify as verify_sha256};
pub use utils::{from_hex, from_pem, load_from_file, load_pem_from_file, save_pem_to_file, save_to_file, to_hex, to_pem};
pub use x25519::{compute_shared_secret, generate_keypair as generate_x25519_keypair};