//! SHA-256 hash function
//! 
//! Simple, direct function for SHA-256 hashing.

use sha2::{Digest, Sha256};

/// Compute SHA-256 hash of data
/// 
/// # Arguments
/// * `data` - Data to hash
/// 
/// # Returns
/// 32-byte hash
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
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
pub fn hash_hex(data: &[u8]) -> String {
    hex::encode(hash(data))
}

/// Verify that data matches a given SHA-256 hash
/// 
/// # Arguments
/// * `data` - Data to verify
/// * `expected_hash` - Expected 32-byte hash
/// 
/// # Returns
/// true if hash matches, false otherwise
pub fn verify(data: &[u8], expected_hash: &[u8; 32]) -> bool {
    &hash(data) == expected_hash
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash() {
        let data = b"Hello, SHA-256!";
        let hash1 = hash(data);
        let hash2 = hash(data);
        
        // Same data should produce same hash
        assert_eq!(hash1, hash2);
        
        // Different data should produce different hash
        let different_data = b"Different data";
        let different_hash = hash(different_data);
        assert_ne!(hash1, different_hash);
    }
    
    #[test]
    fn test_hash_hex() {
        let data = b"test";
        let hex = hash_hex(data);
        
        // Hex string should be 64 characters (32 bytes * 2)
        assert_eq!(hex.len(), 64);
        
        // Known hash value for "test"
        assert_eq!(
            hex,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }
    
    #[test]
    fn test_verify() {
        let data = b"Hello, SHA-256!";
        let correct_hash = hash(data);
        
        assert!(verify(data, &correct_hash));
        
        // Wrong hash should fail
        let mut wrong_hash = correct_hash;
        wrong_hash[0] ^= 0xFF;
        assert!(!verify(data, &wrong_hash));
    }
}