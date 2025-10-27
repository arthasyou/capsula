//! Asymmetric cryptography algorithms
//!
//! This module provides implementations of asymmetric cryptographic algorithms
//! including digital signatures, key exchange, and encryption.

pub mod ed25519;
pub mod p256;
pub mod rsa;
pub mod x25519;

use der::Decode;
use pkcs8::spki::SubjectPublicKeyInfoOwned;

use crate::error::{Error, Result};

/// Verify signature using standard SPKI DER format (algorithm auto-detection)
///
/// This is the unified signature verification function that automatically
/// detects the algorithm from the SPKI DER format and uses the appropriate
/// verification method.
pub fn verify_signature(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    // Parse the SPKI to get the algorithm OID

    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der)?;
    let algorithm_oid = spki.algorithm.oid;

    // Dispatch to the appropriate algorithm based on public key algorithm OID
    match algorithm_oid {
        const_oid::db::rfc8410::ID_ED_25519 => {
            ed25519::verify_with_spki_der(spki_der, message, signature)
        }
        const_oid::db::rfc5912::ID_EC_PUBLIC_KEY => {
            p256::verify_with_spki_der(spki_der, message, signature)
        }
        const_oid::db::rfc5912::RSA_ENCRYPTION => {
            rsa::verify_with_spki_der(spki_der, message, signature)
        }
        _ => Err(crate::error::Error::Other(format!(
            "Unsupported public key algorithm: {}",
            algorithm_oid
        ))),
    }
}

pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem).map_err(|e| Error::Other(format!("Failed to parse PEM: {e}")))?;
    Ok(parsed.contents().to_vec())
}
