//! Utility functions for key import/export
//!
//! Simple functions to convert between raw bytes and PEM format.

use std::{fs, path::Path};

use pem::{encode, parse, Pem};

/// Convert raw bytes to PEM format with specified label
///
/// # Arguments
/// * `bytes` - Raw key bytes
/// * `label` - PEM label (e.g., "PRIVATE KEY", "PUBLIC KEY", "EC PRIVATE KEY")
///
/// # Returns
/// PEM-encoded string
pub fn to_pem(bytes: &[u8], label: &str) -> String {
    let pem = Pem::new(label, bytes);
    encode(&pem)
}

/// Convert PEM format back to raw bytes
///
/// # Arguments
/// * `pem_str` - PEM-encoded string
///
/// # Returns
/// Raw bytes and the PEM label
pub fn from_pem(pem_str: &str) -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    let pem = parse(pem_str)?;
    Ok((pem.contents().to_vec(), pem.tag().to_string()))
}

/// Convert raw bytes to hex string
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to raw bytes
pub fn from_hex(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(hex::decode(hex_str)?)
}

/// Save raw bytes to a file
///
/// # Arguments
/// * `bytes` - Raw bytes to save
/// * `path` - File path to save to
///
/// # Returns
/// Ok(()) on success
pub fn save_to_file(
    bytes: &[u8],
    path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, bytes)?;
    Ok(())
}

/// Load raw bytes from a file
///
/// # Arguments
/// * `path` - File path to load from
///
/// # Returns
/// Raw bytes from the file
pub fn load_from_file(path: impl AsRef<Path>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(fs::read(path)?)
}

/// Save bytes as PEM format to a file
///
/// # Arguments
/// * `bytes` - Raw bytes to save
/// * `label` - PEM label (e.g., "PRIVATE KEY", "PUBLIC KEY")
/// * `path` - File path to save to
///
/// # Returns
/// Ok(()) on success
pub fn save_pem_to_file(
    bytes: &[u8],
    label: &str,
    path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pem_string = to_pem(bytes, label);
    fs::write(path, pem_string)?;
    Ok(())
}

/// Load PEM format from a file
///
/// # Arguments
/// * `path` - File path to load from
///
/// # Returns
/// Raw bytes and the PEM label
pub fn load_pem_from_file(
    path: impl AsRef<Path>,
) -> Result<(Vec<u8>, String), Box<dyn std::error::Error>> {
    let pem_string = fs::read_to_string(path)?;
    from_pem(&pem_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pem_roundtrip() {
        let data = b"This is some key data";
        let label = "PRIVATE KEY";

        let pem_string = to_pem(data, label);
        assert!(pem_string.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem_string.contains("-----END PRIVATE KEY-----"));

        let (recovered_data, recovered_label) = from_pem(&pem_string).unwrap();
        assert_eq!(data.to_vec(), recovered_data);
        assert_eq!(label, recovered_label);
    }

    #[test]
    fn test_different_labels() {
        let data = b"Some public key";

        // Test with PUBLIC KEY label
        let pem_public = to_pem(data, "PUBLIC KEY");
        assert!(pem_public.contains("-----BEGIN PUBLIC KEY-----"));

        // Test with EC PRIVATE KEY label
        let pem_ec = to_pem(data, "EC PRIVATE KEY");
        assert!(pem_ec.contains("-----BEGIN EC PRIVATE KEY-----"));

        // Test with RSA PRIVATE KEY label
        let pem_rsa = to_pem(data, "RSA PRIVATE KEY");
        assert!(pem_rsa.contains("-----BEGIN RSA PRIVATE KEY-----"));
    }

    #[test]
    fn test_hex_conversion() {
        let data = b"Hello, World!";
        let hex = to_hex(data);
        assert_eq!(hex, "48656c6c6f2c20576f726c6421");

        let recovered = from_hex(&hex).unwrap();
        assert_eq!(data.to_vec(), recovered);
    }

    #[test]
    fn test_real_key_pem() {
        // Test with a real 32-byte key
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];

        let pem = to_pem(&key, "PRIVATE KEY");
        let (recovered, label) = from_pem(&pem).unwrap();

        assert_eq!(key.to_vec(), recovered);
        assert_eq!("PRIVATE KEY", label);
    }

    #[test]
    fn test_file_operations() {
        use std::fs;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_key.bin");

        let data = b"This is test key data";

        // Test save and load raw bytes
        save_to_file(data, &file_path).unwrap();
        let loaded = load_from_file(&file_path).unwrap();
        assert_eq!(data.to_vec(), loaded);

        // Clean up
        fs::remove_file(file_path).ok();
    }

    #[test]
    fn test_pem_file_operations() {
        use std::fs;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_key.pem");

        let key = b"This is a private key";
        let label = "PRIVATE KEY";

        // Test save and load PEM
        save_pem_to_file(key, label, &file_path).unwrap();
        let (loaded_key, loaded_label) = load_pem_from_file(&file_path).unwrap();

        assert_eq!(key.to_vec(), loaded_key);
        assert_eq!(label, loaded_label);

        // Verify the file contains PEM format
        let file_content = fs::read_to_string(&file_path).unwrap();
        assert!(file_content.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(file_content.contains("-----END PRIVATE KEY-----"));

        // Clean up
        fs::remove_file(file_path).ok();
    }
}
