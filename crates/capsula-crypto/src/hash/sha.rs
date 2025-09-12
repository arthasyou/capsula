//! SHA hash functions (SHA-256 and SHA-512)
//!
//! Provides secure hash functions for data integrity and key derivation.

use sha2::{Digest, Sha256 as Sha256Hasher, Sha512 as Sha512Hasher};

// ============================================================================
// Hash Algorithm Selection
// ============================================================================

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum HashAlgorithm {
    /// SHA-256 (32-byte output)
    #[default]
    Sha256,
    /// SHA-512 (64-byte output)
    Sha512,
}


// ============================================================================
// Generic Hash Functions
// ============================================================================

/// Compute hash of data using specified algorithm
///
/// # Arguments
/// * `data` - Data to hash
/// * `algorithm` - Hash algorithm to use
///
/// # Returns
/// Hash as vector of bytes (32 bytes for SHA-256, 64 bytes for SHA-512)
///
/// # Example
/// ```
/// use capsula_crypto::hash::{hash, HashAlgorithm};
///
/// let data = b"Hello, World!";
/// let hash256 = hash(data, HashAlgorithm::Sha256);
/// assert_eq!(hash256.len(), 32);
///
/// let hash512 = hash(data, HashAlgorithm::Sha512);
/// assert_eq!(hash512.len(), 64);
/// ```
pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => sha256(data).to_vec(),
        HashAlgorithm::Sha512 => sha512(data).to_vec(),
    }
}

/// Compute hash and return as hex string
///
/// # Arguments
/// * `data` - Data to hash
/// * `algorithm` - Hash algorithm to use
///
/// # Returns
/// Hex string (64 chars for SHA-256, 128 chars for SHA-512)
pub fn hash_hex(data: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Sha256 => sha256_hex(data),
        HashAlgorithm::Sha512 => sha512_hex(data),
    }
}

/// Verify that data matches a given hash
///
/// # Arguments
/// * `data` - Data to verify
/// * `expected_hash` - Expected hash bytes
/// * `algorithm` - Hash algorithm to use
///
/// # Returns
/// true if hash matches, false otherwise
pub fn verify(data: &[u8], expected_hash: &[u8], algorithm: HashAlgorithm) -> bool {
    let computed = hash(data, algorithm);
    computed == expected_hash
}

// ============================================================================
// SHA-256 Functions
// ============================================================================

/// Compute SHA-256 hash of data
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// 32-byte hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 hash and return as hex string
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// 64-character hex string
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Verify that data matches a given SHA-256 hash
///
/// # Arguments
/// * `data` - Data to verify
/// * `expected_hash` - Expected 32-byte hash
///
/// # Returns
/// true if hash matches, false otherwise
pub fn sha256_verify(data: &[u8], expected_hash: &[u8; 32]) -> bool {
    &sha256(data) == expected_hash
}

// ============================================================================
// SHA-512 Functions
// ============================================================================

/// Compute SHA-512 hash of data
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// 64-byte hash
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-512 hash and return as hex string
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// 128-character hex string
pub fn sha512_hex(data: &[u8]) -> String {
    hex::encode(sha512(data))
}

/// Verify that data matches a given SHA-512 hash
///
/// # Arguments
/// * `data` - Data to verify
/// * `expected_hash` - Expected 64-byte hash
///
/// # Returns
/// true if hash matches, false otherwise
pub fn sha512_verify(data: &[u8], expected_hash: &[u8; 64]) -> bool {
    &sha512(data) == expected_hash
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Quick hash function using default algorithm (SHA-256)
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// Hash as vector of bytes
#[inline]
pub fn quick_hash(data: &[u8]) -> Vec<u8> {
    hash(data, HashAlgorithm::default())
}

/// Quick hex hash function using default algorithm (SHA-256)
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// Hex string
#[inline]
pub fn quick_hash_hex(data: &[u8]) -> String {
    hash_hex(data, HashAlgorithm::default())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_with_algorithm() {
        let data = b"test data";

        // Test SHA-256
        let hash256 = hash(data, HashAlgorithm::Sha256);
        assert_eq!(hash256.len(), 32);
        assert_eq!(hash256, sha256(data).to_vec());

        // Test SHA-512
        let hash512 = hash(data, HashAlgorithm::Sha512);
        assert_eq!(hash512.len(), 64);
        assert_eq!(hash512, sha512(data).to_vec());
    }

    #[test]
    fn test_hash_hex_with_algorithm() {
        let data = b"test";

        // Test SHA-256
        let hex256 = hash_hex(data, HashAlgorithm::Sha256);
        assert_eq!(hex256.len(), 64);
        assert_eq!(
            hex256,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );

        // Test SHA-512
        let hex512 = hash_hex(data, HashAlgorithm::Sha512);
        assert_eq!(hex512.len(), 128);
        assert_eq!(hex512, "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff");
    }

    #[test]
    fn test_verify_with_algorithm() {
        let data = b"test data";

        // Test SHA-256
        let hash256 = sha256(data);
        assert!(verify(data, &hash256.to_vec(), HashAlgorithm::Sha256));
        assert!(!verify(
            b"wrong data",
            &hash256.to_vec(),
            HashAlgorithm::Sha256
        ));

        // Test SHA-512
        let hash512 = sha512(data);
        assert!(verify(data, &hash512.to_vec(), HashAlgorithm::Sha512));
        assert!(!verify(
            b"wrong data",
            &hash512.to_vec(),
            HashAlgorithm::Sha512
        ));
    }

    #[test]
    fn test_default_algorithm() {
        assert_eq!(HashAlgorithm::default(), HashAlgorithm::Sha256);

        let data = b"test";
        let quick = quick_hash(data);
        let sha256_result = sha256(data);
        assert_eq!(quick, sha256_result.to_vec());
    }

    #[test]
    fn test_sha256() {
        let data = b"Hello, SHA-256!";
        let hash1 = sha256(data);
        let hash2 = sha256(data);

        // Same data should produce same hash
        assert_eq!(hash1, hash2);

        // Different data should produce different hash
        let different_data = b"Different data";
        let different_hash = sha256(different_data);
        assert_ne!(hash1, different_hash);
    }

    #[test]
    fn test_sha256_hex() {
        let data = b"test";
        let hex = sha256_hex(data);

        // Hex string should be 64 characters (32 bytes * 2)
        assert_eq!(hex.len(), 64);

        // Known hash value for "test"
        assert_eq!(
            hex,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_sha256_verify() {
        let data = b"Hello, SHA-256!";
        let correct_hash = sha256(data);

        assert!(sha256_verify(data, &correct_hash));

        // Wrong hash should fail
        let mut wrong_hash = correct_hash;
        wrong_hash[0] ^= 0xFF;
        assert!(!sha256_verify(data, &wrong_hash));
    }

    #[test]
    fn test_sha512() {
        let data = b"Hello, SHA-512!";
        let hash1 = sha512(data);
        let hash2 = sha512(data);

        // Same data should produce same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-512 produces 64 bytes

        // Different data should produce different hash
        let different_data = b"Different data";
        let different_hash = sha512(different_data);
        assert_ne!(hash1, different_hash);
    }

    #[test]
    fn test_sha512_hex() {
        let data = b"test";
        let hex = sha512_hex(data);

        // Hex string should be 128 characters (64 bytes * 2)
        assert_eq!(hex.len(), 128);

        // Known hash value for "test"
        assert_eq!(
            hex,
            "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"
        );
    }

    #[test]
    fn test_sha512_verify() {
        let data = b"Hello, SHA-512!";
        let correct_hash = sha512(data);

        assert!(sha512_verify(data, &correct_hash));

        // Wrong hash should fail
        let mut wrong_hash = correct_hash;
        wrong_hash[0] ^= 0xFF;
        assert!(!sha512_verify(data, &wrong_hash));
    }
}
