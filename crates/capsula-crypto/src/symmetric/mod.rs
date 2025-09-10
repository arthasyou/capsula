//! Symmetric encryption algorithms
//! 
//! This module provides authenticated encryption with associated data (AEAD)
//! using modern symmetric cipher algorithms.

pub mod aes;
pub mod chacha;

pub use aes::Aes;
pub use chacha::ChaCha;