//! Cryptographic key encoding and format parsing
//!
//! This module provides utilities for parsing and working with various
//! cryptographic key encoding formats like SPKI, JWK, PEM, etc.

pub mod spki;

pub use spki::{encrypt_dek_with_algorithm, parse_algorithm_from_spki, Algorithm};