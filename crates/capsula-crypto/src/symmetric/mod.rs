//! Symmetric encryption algorithms
//! 
//! This module provides authenticated encryption with associated data (AEAD)
//! using modern symmetric cipher algorithms.

pub mod aead;
pub mod aes;
pub mod chacha;

pub use aead::{AeadCipher, encrypt_aead, decrypt_aead, generate_key, generate_nonce, generate_id};
pub use aes::Aes;
pub use chacha::ChaCha;