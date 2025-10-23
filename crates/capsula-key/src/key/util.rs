use std::convert::TryFrom;

use const_oid::ObjectIdentifier;
use pkcs8::{der::pem::PemLabel, spki::der::asn1::AnyRef, PrivateKeyInfo, SecretDocument};

use super::{curve25519::Curve25519, p256::P256Key, rsa::RsaKey, SigningKey};
use crate::error::{Error, Result};

/// 根据 PKCS#8 PEM 内容加载具备签名能力的密钥。
///
/// 会自动识别常见算法（Ed25519/Curve25519、P-256、RSA），并返回实现 `SigningKey` 的 trait object。
pub fn load_signing_key_from_pkcs8_pem(pem: &str) -> Result<Box<dyn SigningKey>> {
    let algorithm = detect_signing_algorithm_from_pem(pem)?;

    match algorithm {
        SigningAlgorithm::Curve25519 => {
            let key = Curve25519::from_pkcs8_pem(pem)?;
            Ok(Box::new(key))
        }
        SigningAlgorithm::P256 => {
            let key = P256Key::from_pkcs8_pem(pem)?;
            Ok(Box::new(key))
        }
        SigningAlgorithm::Rsa => {
            let key = RsaKey::from_pkcs8_pem(pem)?;
            Ok(Box::new(key))
        }
    }
}

/// 根据 PKCS#8 DER 数据加载具备签名能力的密钥。
pub fn load_signing_key_from_pkcs8_der(der: &[u8]) -> Result<Box<dyn SigningKey>> {
    let algorithm = detect_signing_algorithm_from_der(der)?;

    match algorithm {
        SigningAlgorithm::Curve25519 => {
            let key = Curve25519::from_pkcs8_der(der)?;
            Ok(Box::new(key))
        }
        SigningAlgorithm::P256 => {
            let key = P256Key::from_pkcs8_der(der)?;
            Ok(Box::new(key))
        }
        SigningAlgorithm::Rsa => {
            let key = RsaKey::from_pkcs8_der(der)?;
            Ok(Box::new(key))
        }
    }
}

enum SigningAlgorithm {
    Curve25519,
    P256,
    Rsa,
}

fn detect_signing_algorithm(info: &PrivateKeyInfo<'_>) -> Result<SigningAlgorithm> {
    let oid = info.algorithm.oid;

    if oid == const_oid::db::rfc8410::ID_ED_25519 {
        return Ok(SigningAlgorithm::Curve25519);
    }

    if oid == const_oid::db::rfc5912::RSA_ENCRYPTION {
        return Ok(SigningAlgorithm::Rsa);
    }

    if oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        if let Some(params) = info.algorithm.parameters {
            let curve_oid = parse_curve_oid(params)?;
            if curve_oid == const_oid::db::rfc5912::SECP_256_R_1 {
                return Ok(SigningAlgorithm::P256);
            }
            return Err(Error::ImportError(format!(
                "Unsupported EC curve OID: {curve_oid}"
            )));
        } else {
            return Err(Error::ImportError(
                "EC key is missing curve parameters".to_string(),
            ));
        }
    }

    Err(Error::ImportError(format!(
        "Unsupported signing algorithm OID: {}",
        oid
    )))
}

fn parse_curve_oid(any: AnyRef<'_>) -> Result<ObjectIdentifier> {
    ObjectIdentifier::try_from(any)
        .map_err(|e| Error::ImportError(format!("Failed to parse curve OID: {e}")))
}

fn detect_signing_algorithm_from_pem(pem: &str) -> Result<SigningAlgorithm> {
    let (label, doc) = SecretDocument::from_pem(pem)
        .map_err(|e| Error::ImportError(format!("Failed to decode PEM: {e}")))?;

    if label != PrivateKeyInfo::PEM_LABEL {
        return Err(Error::ImportError(format!("Invalid PKCS#8 label: {label}")));
    }

    let info = PrivateKeyInfo::try_from(doc.as_bytes())
        .map_err(|e| Error::ImportError(format!("Failed to parse PKCS#8: {e}")))?;

    detect_signing_algorithm(&info)
}

fn detect_signing_algorithm_from_der(der: &[u8]) -> Result<SigningAlgorithm> {
    let info = PrivateKeyInfo::try_from(der)
        .map_err(|e| Error::ImportError(format!("Failed to parse PKCS#8: {e}")))?;

    detect_signing_algorithm(&info)
}
