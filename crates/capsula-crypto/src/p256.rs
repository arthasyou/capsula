//! P256 (NIST P-256/secp256r1) ECDSA implementation
//! 
//! Simple, direct functions for P256 operations.

use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    SecretKey,
};

/// Generate a new P256 keypair
/// 
/// Returns (private_key, public_key) as byte vectors
/// Private key is 32 bytes, public key is 33 bytes (compressed format)
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut private_key_bytes = [0u8; 32];
    getrandom::fill(&mut private_key_bytes).expect("failed to generate random bytes");
    
    let secret_key = SecretKey::from_bytes(&private_key_bytes.into()).expect("invalid key");
    let signing_key = SigningKey::from(secret_key);
    let verifying_key = signing_key.verifying_key();
    
    // Return private key as bytes and public key in compressed format
    let public_key_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();
    
    (private_key_bytes.to_vec(), public_key_bytes)
}

/// Generate a P256 keypair from a seed
///
/// # Arguments
/// * `seed` - A 32-byte seed for deterministic key generation
///
/// Returns (private_key, public_key) as byte vectors
/// Private key is 32 bytes, public key is 33 bytes (compressed format)
pub fn generate_keypair_from_seed(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let secret_key = SecretKey::from_bytes(&(*seed).into()).expect("invalid key");
    let signing_key = SigningKey::from(secret_key);
    let verifying_key = signing_key.verifying_key();
    
    // Return private key as bytes and public key in compressed format
    let public_key_bytes = verifying_key.to_encoded_point(true).as_bytes().to_vec();
    
    (seed.to_vec(), public_key_bytes)
}

/// Sign a message with P256 ECDSA
/// 
/// # Arguments
/// * `private_key` - 32-byte private key
/// * `message` - Message to sign
/// 
/// # Returns
/// DER-encoded signature (variable length, typically 70-72 bytes)
pub fn sign(private_key: &[u8], message: &[u8]) -> Vec<u8> {
    let secret_key = SecretKey::from_slice(private_key).expect("invalid private key");
    let signing_key = SigningKey::from(secret_key);
    let signature: Signature = signing_key.sign(message);
    
    signature.to_der().as_bytes().to_vec()
}

/// Verify a P256 ECDSA signature
/// 
/// # Arguments
/// * `public_key` - Compressed public key (33 bytes)
/// * `message` - Original message
/// * `signature` - DER-encoded signature
/// 
/// # Returns
/// true if signature is valid, false otherwise
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let verifying_key = match VerifyingKey::from_sec1_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };
    
    let signature = match Signature::from_der(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    
    verifying_key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_sign_verify() {
        let (private_key, public_key) = generate_keypair();
        let message = b"Hello, P256!";
        
        let signature = sign(&private_key, message);
        assert!(verify(&public_key, message, &signature));
        
        // Wrong message should fail
        assert!(!verify(&public_key, b"Wrong message", &signature));
        
        // Wrong signature should fail  
        let mut bad_signature = signature.clone();
        if bad_signature.len() > 0 {
            bad_signature[0] ^= 0xFF;
        }
        assert!(!verify(&public_key, message, &bad_signature));
    }
    
    #[test]
    fn test_key_sizes() {
        let (private_key, public_key) = generate_keypair();
        
        // Private key should be 32 bytes
        assert_eq!(private_key.len(), 32);
        
        // Compressed public key should be 33 bytes
        assert_eq!(public_key.len(), 33);
        
        // First byte of compressed public key should be 0x02 or 0x03
        assert!(public_key[0] == 0x02 || public_key[0] == 0x03);
    }
}