//! SPKI (Subject Public Key Info) parsing utilities
//!
//! This module provides utilities for parsing and working with SPKI DER format,
//! including algorithm identification and public key extraction.

use pkcs8::spki::AlgorithmIdentifierRef;

use crate::error::{Error, Result};

/// 支持的算法类型枚举
/// Note: This is separate from capsula_key::key::Algorithm to avoid circular dependencies
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    X25519,
    P256,
    Rsa,
}

impl Algorithm {
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "Ed25519",
            Algorithm::X25519 => "X25519",
            Algorithm::P256 => "P256",
            Algorithm::Rsa => "RSA",
        }
    }
}

/// 从SPKI算法标识符解析算法类型
pub fn parse_algorithm_from_spki(algorithm: &AlgorithmIdentifierRef) -> Result<Algorithm> {
    match algorithm.oid {
        const_oid::db::rfc5912::RSA_ENCRYPTION => Ok(Algorithm::Rsa),
        const_oid::db::rfc8410::ID_ED_25519 => Ok(Algorithm::Ed25519),
        const_oid::db::rfc8410::ID_X_25519 => Ok(Algorithm::X25519),
        const_oid::db::rfc5912::ID_EC_PUBLIC_KEY => {
            // For P256, we need to check the parameters
            // This is a simplified version - in practice you'd check the curve parameters
            Ok(Algorithm::P256)
        }
        _ => Err(Error::Other(format!(
            "Unsupported algorithm OID: {}",
            algorithm.oid
        ))),
    }
}

/// 根据算法类型加密DEK
pub fn encrypt_dek_with_algorithm(
    dek: &[u8],
    algorithm: Algorithm,
    spki_der: &[u8],
) -> Result<(Vec<u8>, String)> {
    match algorithm {
        Algorithm::Rsa => {
            // 解析RSA公钥并加密
            let public_key = crate::asymmetric::rsa::public_key_from_spki_der(spki_der)
                .map_err(|e| Error::Other(format!("Failed to parse RSA public key: {}", e)))?;

            let encrypted_dek = crate::asymmetric::rsa::encrypt(&public_key, dek)
                .map_err(|e| Error::Other(format!("RSA encryption failed: {}", e)))?;

            Ok((encrypted_dek, "RSA".to_string()))
        }
        _ => Err(Error::Other(
            "Unsupported algorithm for DEK encryption".to_string(),
        )),
    }
}

/// 根据算法类型解密DEK
pub fn decrypt_dek_with_algorithm(
    encrypted_dek: &[u8],
    algorithm_name: &str,
    private_key_der: &[u8],
) -> Result<Vec<u8>> {
    match algorithm_name {
        "RSA" => {
            // 解析RSA私钥并解密
            let rsa_key = crate::asymmetric::rsa::Rsa::from_pkcs8_der(private_key_der)
                .map_err(|e| Error::Other(format!("Failed to parse RSA private key: {}", e)))?;

            let decrypted_dek = rsa_key
                .decrypt(encrypted_dek)
                .map_err(|e| Error::Other(format!("RSA decryption failed: {}", e)))?;

            Ok(decrypted_dek)
        }
        _ => Err(Error::Other(format!(
            "Unsupported algorithm for DEK decryption: {}",
            algorithm_name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use pkcs8::spki::AlgorithmIdentifierRef;

    use super::*;

    #[test]
    fn test_parse_rsa_algorithm() {
        let algorithm = AlgorithmIdentifierRef {
            oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
            parameters: None,
        };

        let parsed = parse_algorithm_from_spki(&algorithm).unwrap();
        assert_eq!(parsed, Algorithm::Rsa);
        assert_eq!(parsed.name(), "RSA");
    }

    #[test]
    fn test_parse_ed25519_algorithm() {
        let algorithm = AlgorithmIdentifierRef {
            oid: const_oid::db::rfc8410::ID_ED_25519,
            parameters: None,
        };

        let parsed = parse_algorithm_from_spki(&algorithm).unwrap();
        assert_eq!(parsed, Algorithm::Ed25519);
        assert_eq!(parsed.name(), "Ed25519");
    }

    #[test]
    fn test_unsupported_algorithm() {
        let algorithm = AlgorithmIdentifierRef {
            oid: const_oid::db::rfc5912::MD_5_WITH_RSA_ENCRYPTION, // Unsupported
            parameters: None,
        };

        let result = parse_algorithm_from_spki(&algorithm);
        assert!(result.is_err());
    }
}
