//! Key Derivation Functions (KDF)
//! 
//! This module provides key derivation functions for deriving cryptographic keys
//! from shared secrets using HKDF (HMAC-based Key Derivation Function).

use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 32-byte symmetric key from X25519 shared secret using HKDF-SHA256
/// 
/// # Arguments
/// - `shared`: 32-byte shared secret from X25519 key exchange
/// - `salt`: Non-secret random salt (recommended 16 bytes), can be transmitted with message
/// - `info`: Context binding information (e.g. b"capsula:aead:v1" + public keys)
/// 
/// # Returns
/// 32-byte symmetric key suitable for AES-256-GCM or ChaCha20-Poly1305
pub fn derive_key32(shared: &[u8; 32], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("hkdf expand");
    okm
}

/// Derive multiple keys of the same length from a shared secret
/// 
/// # Arguments
/// - `shared`: 32-byte shared secret from X25519 key exchange
/// - `salt`: Non-secret random salt
/// - `labels`: Array of context labels, one for each key to derive
/// 
/// # Returns
/// Vector of N-byte keys, one for each label
pub fn derive_many<const N: usize>(
    shared: &[u8; 32],
    salt: &[u8],
    labels: &[&[u8]],
) -> Vec<[u8; N]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared);
    labels
        .iter()
        .map(|label| {
            let mut okm = [0u8; N];
            hk.expand(label, &mut okm).expect("hkdf expand");
            okm
        })
        .collect()
}

// Re-export with legacy names for backward compatibility
#[deprecated(since = "0.2.0", note = "Use `derive_key32` instead")]
pub fn hkdf_sha256_derive_key32(shared: &[u8; 32], salt: &[u8], info: &[u8]) -> [u8; 32] {
    derive_key32(shared, salt, info)
}

#[deprecated(since = "0.2.0", note = "Use `derive_many` instead")]
pub fn hkdf_sha256_derive_many<const N: usize>(
    shared: &[u8; 32],
    salt: &[u8],
    labels: &[&[u8]],
) -> Vec<[u8; N]> {
    derive_many(shared, salt, labels)
}