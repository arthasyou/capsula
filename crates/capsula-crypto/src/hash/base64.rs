//! Simple Base64 utilities for Capsula
//!
//! This module provides 4 simple base64 functions covering all common use cases:
//!
//! ## Standard Functions (RFC 4648)
//! - `encode()` / `decode()` - Standard alphabet with padding
//! - `encode_no_pad()` / `decode_no_pad()` - Standard alphabet without padding
//!
//! ## URL-Safe Functions (RFC 4648 §5)  
//! - `encode_url_safe()` / `decode_url_safe()` - URL-safe alphabet with padding
//! - `encode_url_safe_no_pad()` / `decode_url_safe_no_pad()` - URL-safe alphabet without padding
//!
//! ## Examples
//! ```
//! use capsula_crypto::base64;
//!
//! let data = b"Hello, World!";
//!
//! // Standard base64 (most common)
//! let encoded = base64::encode(data); // "SGVsbG8sIFdvcmxkIQ=="
//! let decoded = base64::decode(&encoded).unwrap(); // b"Hello, World!"
//!
//! // URL-safe for use in URLs
//! let url_safe = base64::encode_url_safe(data); // Safe for URLs
//!
//! // Without padding for some protocols
//! let no_pad = base64::encode_no_pad(data); // "SGVsbG8sIFdvcmxkIQ"
//! ```

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};

use crate::error::{Error, Result};

// =============================================================================
// Standard Base64 Functions (RFC 4648)
// =============================================================================

/// Encode bytes to standard base64 string with padding
///
/// Uses the standard RFC 4648 alphabet: `A-Z`, `a-z`, `0-9`, `+`, `/`
/// Includes padding with `=` characters.
///
/// # Arguments
/// * `data` - The bytes to encode
///
/// # Returns
/// Base64-encoded string
///
/// # Example
/// ```
/// use capsula_crypto::base64;
///
/// let data = b"Hello, World!";
/// let encoded = base64::encode(data);
/// assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
/// ```
pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
    STANDARD.encode(data)
}

/// Decode standard base64 string to bytes
///
/// Decodes strings encoded with the standard RFC 4648 alphabet.
/// Expects padding with `=` characters.
///
/// # Arguments
/// * `encoded` - The base64-encoded string
///
/// # Returns
/// Decoded bytes
///
/// # Example
/// ```
/// use capsula_crypto::base64;
///
/// let encoded = "SGVsbG8sIFdvcmxkIQ==";
/// let decoded = base64::decode(encoded).unwrap();
/// assert_eq!(decoded, b"Hello, World!");
/// ```
pub fn decode<T: AsRef<[u8]>>(encoded: T) -> Result<Vec<u8>> {
    STANDARD
        .decode(encoded)
        .map_err(|e| Error::Other(format!("Base64 decode error: {}", e)))
}

/// Encode bytes to standard base64 string without padding
///
/// Uses the standard RFC 4648 alphabet but omits padding characters.
/// Some protocols prefer this format.
///
/// # Arguments
/// * `data` - The bytes to encode
///
/// # Returns
/// Base64-encoded string without padding
///
/// # Example
/// ```
/// use capsula_crypto::base64;
///
/// let data = b"Hello, World!";
/// let encoded = base64::encode_no_pad(data);
/// assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ"); // No trailing ==
/// ```
pub fn encode_no_pad<T: AsRef<[u8]>>(data: T) -> String {
    STANDARD_NO_PAD.encode(data)
}

/// Decode standard base64 string without padding
///
/// Decodes strings that use standard alphabet but omit padding.
///
/// # Arguments
/// * `encoded` - The base64-encoded string without padding
///
/// # Returns
/// Decoded bytes
///
/// # Example
/// ```
/// use capsula_crypto::base64;
///
/// let encoded = "SGVsbG8sIFdvcmxkIQ"; // No padding
/// let decoded = base64::decode_no_pad(encoded).unwrap();
/// assert_eq!(decoded, b"Hello, World!");
/// ```
pub fn decode_no_pad<T: AsRef<[u8]>>(encoded: T) -> Result<Vec<u8>> {
    STANDARD_NO_PAD
        .decode(encoded)
        .map_err(|e| Error::Other(format!("Base64 decode error: {}", e)))
}

// =============================================================================
// URL-Safe Base64 Functions (RFC 4648 §5)
// =============================================================================

/// Encode bytes to URL-safe base64 string with padding
///
/// Uses URL-safe alphabet: `A-Z`, `a-z`, `0-9`, `-`, `_`
/// Replaces `+` with `-` and `/` with `_` to be safe for URLs.
/// Includes padding with `=` characters.
///
/// # Arguments
/// * `data` - The bytes to encode
///
/// # Returns
/// URL-safe base64-encoded string
///
/// # Example
/// ```
/// use capsula_crypto::base64;
///
/// let data = b"\xfa\xec \x55\x00"; // Data that would produce +/ in standard encoding
/// let encoded = base64::encode_url_safe(data);
/// // Result contains - and _ instead of + and /
/// assert!(!encoded.contains('+'));
/// assert!(!encoded.contains('/'));
/// ```
pub fn encode_url_safe<T: AsRef<[u8]>>(data: T) -> String {
    URL_SAFE.encode(data)
}

/// Decode URL-safe base64 string to bytes
///
/// Decodes strings that use URL-safe alphabet (`-_` instead of `+/`).
/// Expects padding with `=` characters.
///
/// # Arguments
/// * `encoded` - The URL-safe base64-encoded string
///
/// # Returns
/// Decoded bytes
///
/// # Example
/// ```
/// use capsula_crypto::base64;
///
/// let url_safe_encoded = "SGVsbG8sIFdvcmxkIQ=="; // Same as standard for this data
/// let decoded = base64::decode_url_safe(url_safe_encoded).unwrap();
/// assert_eq!(decoded, b"Hello, World!");
/// ```
pub fn decode_url_safe<T: AsRef<[u8]>>(encoded: T) -> Result<Vec<u8>> {
    URL_SAFE
        .decode(encoded)
        .map_err(|e| Error::Other(format!("Base64 decode error: {}", e)))
}

/// Encode bytes to URL-safe base64 string without padding
///
/// Uses URL-safe alphabet and omits padding characters.
/// Ideal for URLs where `=` characters might cause issues.
///
/// # Arguments
/// * `data` - The bytes to encode
///
/// # Returns
/// URL-safe base64-encoded string without padding
///
/// # Example
/// ```
/// use capsula_crypto::base64;
///
/// let data = b"Hello, World!";
/// let encoded = base64::encode_url_safe_no_pad(data);
/// assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ"); // No padding, URL-safe
/// assert!(!encoded.contains('='));
/// ```
pub fn encode_url_safe_no_pad<T: AsRef<[u8]>>(data: T) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode URL-safe base64 string without padding
///
/// Decodes strings that use URL-safe alphabet and omit padding.
///
/// # Arguments
/// * `encoded` - The URL-safe base64-encoded string without padding
///
/// # Returns
/// Decoded bytes
///
/// # Example
/// ```
/// use capsula_crypto::base64;
///
/// let encoded = "SGVsbG8sIFdvcmxkIQ"; // URL-safe, no padding
/// let decoded = base64::decode_url_safe_no_pad(encoded).unwrap();
/// assert_eq!(decoded, b"Hello, World!");
/// ```
pub fn decode_url_safe_no_pad<T: AsRef<[u8]>>(encoded: T) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| Error::Other(format!("Base64 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_encode_decode() {
        let data = b"Hello, World!";

        // Test standard base64
        let encoded = encode(data);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_standard_no_pad() {
        let test_cases = [
            (&b"f"[..], "Zg==", "Zg"),
            (&b"fo"[..], "Zm8=", "Zm8"),
            (&b"foo"[..], "Zm9v", "Zm9v"), // No padding needed
            (&b"foob"[..], "Zm9vYg==", "Zm9vYg"),
            (&b"fooba"[..], "Zm9vYmE=", "Zm9vYmE"),
            (&b"foobar"[..], "Zm9vYmFy", "Zm9vYmFy"), // No padding needed
        ];

        for (data, with_pad, without_pad) in test_cases {
            // Standard with padding
            assert_eq!(encode(data), with_pad);

            // Standard without padding
            assert_eq!(encode_no_pad(data), without_pad);

            // Both should decode correctly
            assert_eq!(decode(with_pad).unwrap(), data);
            assert_eq!(decode_no_pad(without_pad).unwrap(), data);
        }
    }

    #[test]
    fn test_url_safe_encode_decode() {
        // Data that would normally contain + and / in standard encoding
        let data = b"\xfa\xec \x55\x00";

        let standard = encode(data);
        let url_safe = encode_url_safe(data);

        // URL-safe should replace + with -, / with _
        assert_ne!(standard, url_safe);
        assert!(!url_safe.contains('+'));
        assert!(!url_safe.contains('/'));

        // Both should decode to same data
        let decoded_standard = decode(&standard).unwrap();
        let decoded_url_safe = decode_url_safe(&url_safe).unwrap();
        assert_eq!(decoded_standard, decoded_url_safe);
        assert_eq!(decoded_standard, data);
    }

    #[test]
    fn test_url_safe_no_pad() {
        let data = b"\xfa\xec \x55\x00";

        let url_safe_with_pad = encode_url_safe(data);
        let url_safe_no_pad = encode_url_safe_no_pad(data);

        // No pad version should not have = characters
        assert!(!url_safe_no_pad.contains('='));
        if url_safe_with_pad.contains('=') {
            assert_ne!(url_safe_with_pad, url_safe_no_pad);
        }

        // Both should decode to same data
        let decoded1 = decode_url_safe(&url_safe_with_pad).unwrap();
        let decoded2 = decode_url_safe_no_pad(&url_safe_no_pad).unwrap();
        assert_eq!(decoded1, decoded2);
        assert_eq!(decoded1, data);
    }

    #[test]
    fn test_all_functions_roundtrip() {
        let data = b"Test data for all 4 functions";

        // Test all 4 functions
        let standard = encode(data);
        let url_safe = encode_url_safe(data);
        let no_pad = encode_no_pad(data);
        let url_safe_no_pad = encode_url_safe_no_pad(data);

        // All should decode back to original data
        assert_eq!(decode(&standard).unwrap(), data);
        assert_eq!(decode_url_safe(&url_safe).unwrap(), data);
        assert_eq!(decode_no_pad(&no_pad).unwrap(), data);
        assert_eq!(decode_url_safe_no_pad(&url_safe_no_pad).unwrap(), data);
    }

    #[test]
    fn test_empty_input() {
        let empty = b"";

        // All functions should handle empty input
        assert_eq!(encode(empty), "");
        assert_eq!(encode_url_safe(empty), "");
        assert_eq!(encode_no_pad(empty), "");
        assert_eq!(encode_url_safe_no_pad(empty), "");

        assert_eq!(decode("").unwrap(), empty);
        assert_eq!(decode_url_safe("").unwrap(), empty);
        assert_eq!(decode_no_pad("").unwrap(), empty);
        assert_eq!(decode_url_safe_no_pad("").unwrap(), empty);
    }

    #[test]
    fn test_invalid_input() {
        let invalid_inputs = ["Invalid base64!", "Zg===", "Z==="];

        for invalid in invalid_inputs {
            assert!(decode(invalid).is_err());
            assert!(decode_url_safe(invalid).is_err());
            assert!(decode_no_pad(invalid).is_err());
            assert!(decode_url_safe_no_pad(invalid).is_err());
        }
    }

    #[test]
    fn test_known_values() {
        // Test some known base64 values
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");

        assert_eq!(decode("Zg==").unwrap(), b"f");
        assert_eq!(decode("Zm8=").unwrap(), b"fo");
        assert_eq!(decode("Zm9v").unwrap(), b"foo");
    }
}
