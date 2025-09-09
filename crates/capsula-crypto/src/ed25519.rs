//! Ed25519 signature algorithm implementation
//!
//! Simple, direct functions for Ed25519 operations.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Generate a new Ed25519 keypair
///
/// Returns (private_key, public_key) as 32-byte arrays
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut private_key = [0u8; 32];
    getrandom::fill(&mut private_key).expect("failed to generate random bytes");

    let signing_key = SigningKey::from_bytes(&private_key);
    let verifying_key = signing_key.verifying_key();

    (private_key, verifying_key.to_bytes())
}

/// Generate an Ed25519 keypair from a seed
///
/// # Arguments
/// * `seed` - A 32-byte seed for deterministic key generation
///
/// Returns (private_key, public_key) as 32-byte arrays
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();

    (*seed, verifying_key.to_bytes())
}

/// Sign a message with Ed25519
///
/// # Arguments
/// * `private_key` - 32-byte private key
/// * `message` - Message to sign
///
/// # Returns
/// 64-byte signature
pub fn sign(private_key: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(message);
    signature.to_bytes()
}

/// Verify an Ed25519 signature
///
/// # Arguments
/// * `public_key` - 32-byte public key
/// * `message` - Original message
/// * `signature` - 64-byte signature to verify
///
/// # Returns
/// true if signature is valid, false otherwise
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let signature = Signature::from_bytes(signature);

    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_sign_verify() {
        let (private_key, public_key) = generate_keypair();
        let message = b"Hello, world!";

        let signature = sign(&private_key, message);
        assert!(verify(&public_key, message, &signature));

        // Wrong message should fail
        assert!(!verify(&public_key, b"Wrong message", &signature));

        // Wrong signature should fail
        let mut bad_signature = signature;
        bad_signature[0] ^= 0xFF;
        assert!(!verify(&public_key, message, &bad_signature));
    }
}
