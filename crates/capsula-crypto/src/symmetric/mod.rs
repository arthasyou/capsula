//! Symmetric encryption algorithms
//! 
//! This module provides authenticated encryption with associated data (AEAD)
//! using modern symmetric cipher algorithms.

pub mod aead;
pub mod aes;
pub mod chacha;

pub use aead::{
    AeadCipher, AeadAlgorithm, 
    encrypt_aead, decrypt_aead, 
    encrypt_aead_with_algorithm, decrypt_aead_with_algorithm,
    encrypt_aead_with_nonce, decrypt_aead_with_nonce,
    generate_key, generate_nonce, generate_id,
    detect_algorithm
};
pub use aes::Aes;
pub use chacha::ChaCha;