//! 数字签名 API
//!
//! 提供统一的数字签名接口，所有语言绑定必须遵循此标准

use capsula_key::{Curve25519, P256Key, RsaKey, KeySign};
use crate::{Result, ApiError, KeyPair};

/// 数字签名 API
pub struct SigningApi;

impl SigningApi {
    /// 使用密钥对对消息进行签名
    ///
    /// 所有语言绑定必须提供此功能。
    ///
    /// # 参数
    ///
    /// * `keypair` - 密钥对
    /// * `message` - 要签名的消息
    ///
    /// # 返回
    ///
    /// 签名结果（二进制格式）
    pub fn sign(keypair: &KeyPair, message: &[u8]) -> Result<Vec<u8>> {
        keypair.sign(message)
    }

    /// 使用私钥 DER 格式直接签名（自动检测算法）
    ///
    /// 所有语言绑定必须提供此功能，作为便捷方法。
    ///
    /// # 参数
    ///
    /// * `private_key_der` - PKCS#8 DER 格式的私钥
    /// * `message` - 要签名的消息
    ///
    /// # 返回
    ///
    /// 签名结果（二进制格式）
    pub fn sign_with_der(private_key_der: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        // 尝试不同的算法
        if let Ok(key) = Curve25519::from_pkcs8_der(private_key_der) {
            return key
                .sign(message)
                .map_err(|e| ApiError::SigningError(e.to_string()));
        }

        if let Ok(key) = P256Key::from_pkcs8_der(private_key_der) {
            return key
                .sign(message)
                .map_err(|e| ApiError::SigningError(e.to_string()));
        }

        if let Ok(key) = RsaKey::from_pkcs8_der(private_key_der) {
            return key
                .sign(message)
                .map_err(|e| ApiError::SigningError(e.to_string()));
        }

        Err(ApiError::UnsupportedAlgorithm(
            "无法识别私钥格式，不支持的算法".to_string(),
        ))
    }

    // 注意：验证签名需要公钥验证功能，这个功能在 capsula-crypto 中实现
    // 这里暂时不实现，等需要时再添加
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Algorithm;

    #[test]
    fn test_sign_curve25519() {
        let keypair = KeyPair::generate(Algorithm::Curve25519).unwrap();
        let message = b"Test message";
        let signature = SigningApi::sign(&keypair, message).unwrap();

        assert!(!signature.is_empty());
        // Ed25519 签名固定为 64 字节
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_sign_p256() {
        let keypair = KeyPair::generate(Algorithm::P256).unwrap();
        let message = b"Test message";
        let signature = SigningApi::sign(&keypair, message).unwrap();

        assert!(!signature.is_empty());
    }

    #[test]
    fn test_sign_rsa2048() {
        let keypair = KeyPair::generate(Algorithm::Rsa2048).unwrap();
        let message = b"Test message";
        let signature = SigningApi::sign(&keypair, message).unwrap();

        assert!(!signature.is_empty());
    }

    #[test]
    fn test_sign_with_der() {
        let keypair = KeyPair::generate(Algorithm::Curve25519).unwrap();
        let message = b"Test message";
        let private_der = keypair.private_key_to_der().unwrap();
        let signature = SigningApi::sign_with_der(&private_der, message).unwrap();

        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 64);
    }
}
