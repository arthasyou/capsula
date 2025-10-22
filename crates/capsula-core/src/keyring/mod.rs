//! Keyring management for data encapsulation
//!
//! This module provides keyring data structures for storing encrypted data encryption keys (DEKs)
//! in the capsula protocol. The keyring is serialized into the data capsule.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Key wrapping information for transmitting encrypted keys
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyWrap {
    /// Recipient public key identifier
    pub kid: String,
    /// Key wrapping algorithm (e.g., "X25519+HKDF", "RSA-OAEP")
    pub alg: String,
    /// Base64-encoded wrapped content encryption key
    pub cek_wrapped: String,
}

/// Keyring data structure for storing encrypted DEKs
///
/// Maps dek_id to the corresponding KeyWrap. Each DEK has a unique ID and is
/// wrapped for a specific recipient. This structure is serialized into the
/// data capsule and can be used across different programming languages.
pub type Keyring = HashMap<String, KeyWrap>;

impl KeyWrap {
    /// Create a new KeyWrap
    pub fn new(kid: String, alg: String, cek_wrapped: String) -> Self {
        Self {
            kid,
            alg,
            cek_wrapped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_basic_operations() {
        let mut keyring = Keyring::new();
        assert!(keyring.is_empty());

        let dek_id = "dek_123".to_string();
        let key_wrap = KeyWrap::new(
            "recipient_1".to_string(),
            "X25519+HKDF+AES256GCM".to_string(),
            "base64_encoded_wrapped_key".to_string(),
        );

        // Test add and find
        keyring.insert(dek_id.clone(), key_wrap.clone());
        assert!(!keyring.is_empty());
        assert_eq!(keyring.len(), 1);
        assert!(keyring.contains_key(&dek_id));
        assert_eq!(keyring.get(&dek_id), Some(&key_wrap));

        // Test dek_ids
        let ids: Vec<&String> = keyring.keys().collect();
        assert_eq!(ids.len(), 1);
        assert!(ids.contains(&&dek_id));

        // Test remove
        let removed = keyring.remove(&dek_id);
        assert_eq!(removed, Some(key_wrap));
        assert!(keyring.is_empty());
    }

    #[test]
    fn test_keyring_serialization() {
        let mut keyring = Keyring::new();

        let key_wrap = KeyWrap::new(
            "recipient_1".to_string(),
            "X25519+HKDF+AES256GCM".to_string(),
            "base64_encoded_wrapped_key".to_string(),
        );

        keyring.insert("dek_123".to_string(), key_wrap);

        // Test JSON serialization
        let json = serde_json::to_string(&keyring).unwrap();
        let deserialized: Keyring = serde_json::from_str(&json).unwrap();

        assert_eq!(keyring, deserialized);
    }

    #[test]
    fn test_keyring_multiple_wraps() {
        let mut keyring = Keyring::new();

        // Add multiple key wraps
        for i in 1 ..= 3 {
            let dek_id = format!("dek_{}", i);
            let key_wrap = KeyWrap::new(
                format!("recipient_{}", i),
                "X25519+HKDF+AES256GCM".to_string(),
                format!("wrapped_key_{}", i),
            );
            keyring.insert(dek_id, key_wrap);
        }

        assert_eq!(keyring.len(), 3);
        assert!(keyring.contains_key("dek_1"));
        assert!(keyring.contains_key("dek_2"));
        assert!(keyring.contains_key("dek_3"));

        // Clear all
        keyring.clear();
        assert!(keyring.is_empty());
    }
}
