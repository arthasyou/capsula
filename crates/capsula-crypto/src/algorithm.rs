//! Unified algorithm interface for key generation
//!
//! Provides a single entry point for generating keys for different algorithms.

use crate::{ed25519, p256, utils, x25519};
use std::path::Path;

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Ed25519 signature algorithm
    Ed25519,
    /// X25519 key exchange algorithm
    X25519,
    /// P256 (NIST P-256/secp256r1) ECDSA algorithm
    P256,
}

/// Key pair containing private and public keys
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    /// Private key bytes
    pub private_key: Vec<u8>,
    /// Public key bytes
    pub public_key: Vec<u8>,
    /// Algorithm used to generate the keys
    pub algorithm: Algorithm,
}

impl KeyPair {
    /// Create a new KeyPair
    pub fn new(private_key: Vec<u8>, public_key: Vec<u8>, algorithm: Algorithm) -> Self {
        Self {
            private_key,
            public_key,
            algorithm,
        }
    }
}

/// Generate a key pair for the specified algorithm
///
/// # Arguments
/// * `algorithm` - The cryptographic algorithm to use
///
/// # Returns
/// A KeyPair containing the private and public keys
///
/// # Example
/// ```
/// use capsula_crypto::algorithm::{Algorithm, generate_key};
///
/// let keypair = generate_key(Algorithm::Ed25519);
/// assert_eq!(keypair.private_key.len(), 32);
/// assert_eq!(keypair.public_key.len(), 32);
/// ```
pub fn generate_key(algorithm: Algorithm) -> KeyPair {
    match algorithm {
        Algorithm::Ed25519 => {
            let (private_key, public_key) = ed25519::generate_keypair();
            KeyPair::new(private_key.to_vec(), public_key.to_vec(), algorithm)
        }
        Algorithm::X25519 => {
            let (private_key, public_key) = x25519::generate_keypair();
            KeyPair::new(private_key.to_vec(), public_key.to_vec(), algorithm)
        }
        Algorithm::P256 => {
            let (private_key, public_key) = p256::generate_keypair();
            KeyPair::new(private_key, public_key, algorithm)
        }
    }
}

/// Generate a key pair from a seed for the specified algorithm
///
/// # Arguments
/// * `algorithm` - The cryptographic algorithm to use
/// * `seed` - A 32-byte seed for deterministic key generation
///
/// # Returns
/// A KeyPair containing the private and public keys
///
/// # Example
/// ```
/// use capsula_crypto::algorithm::{Algorithm, generate_key_from_seed};
///
/// let seed = [0u8; 32]; // Use a proper random seed in practice
/// let keypair = generate_key_from_seed(Algorithm::Ed25519, &seed);
/// assert_eq!(keypair.private_key.len(), 32);
/// assert_eq!(keypair.public_key.len(), 32);
/// ```
pub fn generate_key_from_seed(algorithm: Algorithm, seed: &[u8; 32]) -> KeyPair {
    match algorithm {
        Algorithm::Ed25519 => {
            let (private_key, public_key) = ed25519::generate_keypair_from_seed(seed);
            KeyPair::new(private_key.to_vec(), public_key.to_vec(), algorithm)
        }
        Algorithm::X25519 => {
            let (private_key, public_key) = x25519::generate_keypair_from_seed(seed);
            KeyPair::new(private_key.to_vec(), public_key.to_vec(), algorithm)
        }
        Algorithm::P256 => {
            let (private_key, public_key) = p256::generate_keypair_from_seed(seed);
            KeyPair::new(private_key, public_key, algorithm)
        }
    }
}

impl Algorithm {
    /// Get the appropriate PEM label for private keys
    pub fn private_key_label(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ED25519 PRIVATE KEY",
            Algorithm::X25519 => "X25519 PRIVATE KEY",
            Algorithm::P256 => "EC PRIVATE KEY",
        }
    }

    /// Get the appropriate PEM label for public keys
    pub fn public_key_label(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ED25519 PUBLIC KEY",
            Algorithm::X25519 => "X25519 PUBLIC KEY",
            Algorithm::P256 => "EC PUBLIC KEY",
        }
    }
    
    /// Get the expected private key size in bytes
    pub fn private_key_size(&self) -> usize {
        match self {
            Algorithm::Ed25519 => 32,
            Algorithm::X25519 => 32,
            Algorithm::P256 => 32,
        }
    }
    
    /// Get the expected public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Algorithm::Ed25519 => 32,
            Algorithm::X25519 => 32,
            Algorithm::P256 => 33, // Compressed format
        }
    }
}

/// Generate a key pair and save to files
///
/// # Arguments
/// * `algorithm` - The cryptographic algorithm to use
/// * `private_key_path` - Path to save the private key
/// * `public_key_path` - Path to save the public key
/// * `format` - File format: "pem" or "raw"
///
/// # Returns
/// The generated KeyPair on success
///
/// # Example
/// ```no_run
/// use capsula_crypto::algorithm::{Algorithm, generate_key_to_file};
///
/// let keypair = generate_key_to_file(
///     Algorithm::Ed25519,
///     "private_key.pem",
///     "public_key.pem",
///     "pem"
/// ).unwrap();
/// ```
pub fn generate_key_to_file(
    algorithm: Algorithm,
    private_key_path: impl AsRef<Path>,
    public_key_path: impl AsRef<Path>,
    format: &str,
) -> Result<KeyPair, Box<dyn std::error::Error>> {
    let keypair = generate_key(algorithm);
    
    match format.to_lowercase().as_str() {
        "pem" => {
            utils::save_pem_to_file(
                &keypair.private_key,
                algorithm.private_key_label(),
                private_key_path,
            )?;
            utils::save_pem_to_file(
                &keypair.public_key,
                algorithm.public_key_label(),
                public_key_path,
            )?;
        }
        "raw" | "bin" | "binary" => {
            utils::save_to_file(&keypair.private_key, private_key_path)?;
            utils::save_to_file(&keypair.public_key, public_key_path)?;
        }
        _ => {
            return Err(format!("Unsupported format: {}. Use 'pem' or 'raw'", format).into());
        }
    }
    
    Ok(keypair)
}

/// Generate a key pair and save to files with automatic file extensions
///
/// # Arguments
/// * `algorithm` - The cryptographic algorithm to use
/// * `base_path` - Base path for the files (extensions will be added)
/// * `format` - File format: "pem" or "raw"
///
/// # Returns
/// The generated KeyPair and the actual file paths used
///
/// # Example
/// ```no_run
/// use capsula_crypto::algorithm::{Algorithm, generate_key_to_file_auto};
///
/// // Will create "mykey.private.pem" and "mykey.public.pem"
/// let (keypair, private_path, public_path) = generate_key_to_file_auto(
///     Algorithm::Ed25519,
///     "mykey",
///     "pem"
/// ).unwrap();
/// ```
pub fn generate_key_to_file_auto(
    algorithm: Algorithm,
    base_path: impl AsRef<Path>,
    format: &str,
) -> Result<(KeyPair, String, String), Box<dyn std::error::Error>> {
    let base = base_path.as_ref();
    let base_str = base.to_string_lossy();
    
    let (private_path, public_path) = match format.to_lowercase().as_str() {
        "pem" => (
            format!("{}.private.pem", base_str),
            format!("{}.public.pem", base_str),
        ),
        "raw" | "bin" | "binary" => (
            format!("{}.private.key", base_str),
            format!("{}.public.key", base_str),
        ),
        _ => {
            return Err(format!("Unsupported format: {}. Use 'pem' or 'raw'", format).into());
        }
    };
    
    let keypair = generate_key_to_file(algorithm, &private_path, &public_path, format)?;
    
    Ok((keypair, private_path, public_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519() {
        let keypair = generate_key(Algorithm::Ed25519);
        assert_eq!(keypair.algorithm, Algorithm::Ed25519);
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 32);
    }

    #[test]
    fn test_generate_x25519() {
        let keypair = generate_key(Algorithm::X25519);
        assert_eq!(keypair.algorithm, Algorithm::X25519);
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 32);
    }

    #[test]
    fn test_generate_p256() {
        let keypair = generate_key(Algorithm::P256);
        assert_eq!(keypair.algorithm, Algorithm::P256);
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 33); // Compressed format
    }

    #[test]
    fn test_pem_labels() {
        assert_eq!(Algorithm::Ed25519.private_key_label(), "ED25519 PRIVATE KEY");
        assert_eq!(Algorithm::Ed25519.public_key_label(), "ED25519 PUBLIC KEY");
        
        assert_eq!(Algorithm::X25519.private_key_label(), "X25519 PRIVATE KEY");
        assert_eq!(Algorithm::X25519.public_key_label(), "X25519 PUBLIC KEY");
        
        assert_eq!(Algorithm::P256.private_key_label(), "EC PRIVATE KEY");
        assert_eq!(Algorithm::P256.public_key_label(), "EC PUBLIC KEY");
    }
    
    #[test]
    fn test_key_sizes() {
        assert_eq!(Algorithm::Ed25519.private_key_size(), 32);
        assert_eq!(Algorithm::Ed25519.public_key_size(), 32);
        
        assert_eq!(Algorithm::X25519.private_key_size(), 32);
        assert_eq!(Algorithm::X25519.public_key_size(), 32);
        
        assert_eq!(Algorithm::P256.private_key_size(), 32);
        assert_eq!(Algorithm::P256.public_key_size(), 33);
    }
    
    #[test]
    fn test_generate_key_to_file_pem() {
        use std::fs;
        
        let temp_dir = tempfile::tempdir().unwrap();
        let private_path = temp_dir.path().join("test.private.pem");
        let public_path = temp_dir.path().join("test.public.pem");
        
        let keypair = generate_key_to_file(
            Algorithm::Ed25519,
            &private_path,
            &public_path,
            "pem"
        ).unwrap();
        
        // Verify files were created
        assert!(private_path.exists());
        assert!(public_path.exists());
        
        // Verify PEM format
        let private_content = fs::read_to_string(&private_path).unwrap();
        assert!(private_content.contains("-----BEGIN ED25519 PRIVATE KEY-----"));
        
        let public_content = fs::read_to_string(&public_path).unwrap();
        assert!(public_content.contains("-----BEGIN ED25519 PUBLIC KEY-----"));
        
        // Load and verify keys match
        let (loaded_private, _) = utils::load_pem_from_file(&private_path).unwrap();
        let (loaded_public, _) = utils::load_pem_from_file(&public_path).unwrap();
        
        assert_eq!(keypair.private_key, loaded_private);
        assert_eq!(keypair.public_key, loaded_public);
    }
    
    #[test]
    fn test_generate_key_to_file_raw() {
        let temp_dir = tempfile::tempdir().unwrap();
        let private_path = temp_dir.path().join("test.private.key");
        let public_path = temp_dir.path().join("test.public.key");
        
        let keypair = generate_key_to_file(
            Algorithm::P256,
            &private_path,
            &public_path,
            "raw"
        ).unwrap();
        
        // Verify files were created
        assert!(private_path.exists());
        assert!(public_path.exists());
        
        // Load and verify keys match
        let loaded_private = utils::load_from_file(&private_path).unwrap();
        let loaded_public = utils::load_from_file(&public_path).unwrap();
        
        assert_eq!(keypair.private_key, loaded_private);
        assert_eq!(keypair.public_key, loaded_public);
    }
    
    #[test]
    fn test_generate_key_to_file_auto() {
        let temp_dir = tempfile::tempdir().unwrap();
        let base_path = temp_dir.path().join("mykey");
        
        let (keypair, private_path, public_path) = generate_key_to_file_auto(
            Algorithm::X25519,
            &base_path,
            "pem"
        ).unwrap();
        
        // Verify the paths have correct extensions
        assert!(private_path.ends_with(".private.pem"));
        assert!(public_path.ends_with(".public.pem"));
        
        // Verify files exist
        assert!(Path::new(&private_path).exists());
        assert!(Path::new(&public_path).exists());
        
        // Verify keys
        let (loaded_private, _) = utils::load_pem_from_file(&private_path).unwrap();
        assert_eq!(keypair.private_key, loaded_private);
    }
    
    #[test]
    fn test_generate_from_seed() {
        let seed = [0x42u8; 32]; // Fixed seed for testing
        
        // Ed25519
        let keypair1 = generate_key_from_seed(Algorithm::Ed25519, &seed);
        let keypair2 = generate_key_from_seed(Algorithm::Ed25519, &seed);
        assert_eq!(keypair1.private_key, keypair2.private_key);
        assert_eq!(keypair1.public_key, keypair2.public_key);
        
        // X25519
        let keypair1 = generate_key_from_seed(Algorithm::X25519, &seed);
        let keypair2 = generate_key_from_seed(Algorithm::X25519, &seed);
        assert_eq!(keypair1.private_key, keypair2.private_key);
        assert_eq!(keypair1.public_key, keypair2.public_key);
        
        // P256
        let keypair1 = generate_key_from_seed(Algorithm::P256, &seed);
        let keypair2 = generate_key_from_seed(Algorithm::P256, &seed);
        assert_eq!(keypair1.private_key, keypair2.private_key);
        assert_eq!(keypair1.public_key, keypair2.public_key);
    }
    
    #[test]
    fn test_different_seeds_different_keys() {
        let seed1 = [0x01u8; 32];
        let seed2 = [0x02u8; 32];
        
        let keypair1 = generate_key_from_seed(Algorithm::Ed25519, &seed1);
        let keypair2 = generate_key_from_seed(Algorithm::Ed25519, &seed2);
        
        assert_ne!(keypair1.private_key, keypair2.private_key);
        assert_ne!(keypair1.public_key, keypair2.public_key);
    }
    
    #[test]
    fn test_invalid_format() {
        let temp_dir = tempfile::tempdir().unwrap();
        let private_path = temp_dir.path().join("test.private");
        let public_path = temp_dir.path().join("test.public");
        
        let result = generate_key_to_file(
            Algorithm::Ed25519,
            &private_path,
            &public_path,
            "invalid"
        );
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported format"));
    }
}