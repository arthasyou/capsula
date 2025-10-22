//! Symmetric encryption algorithms
//!
//! This module provides authenticated encryption with associated data (AEAD)
//! using modern symmetric cipher algorithms.

pub mod aead;
pub mod aes;
pub mod chacha;

pub use aead::{
    decrypt_aead, decrypt_aead_with_algorithm, decrypt_aead_with_nonce, detect_algorithm,
    encrypt_aead, encrypt_aead_with_algorithm, encrypt_aead_with_nonce, generate_id, generate_key,
    generate_nonce, AeadAlgorithm, AeadCipher,
};
pub use aes::Aes;
pub use chacha::ChaCha;
