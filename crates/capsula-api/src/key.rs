//! 密钥管理 API
//!
//! 提供统一的跨语言密钥接口，作为所有语言绑定的标准规范。
//!
//! 设计原则：
//! 1. 使用 trait object 保持类型抽象性和灵活性
//! 2. 提供统一的接口供所有语言使用
//! 3. 避免不必要的序列化/反序列化开销

use capsula_key::{Curve25519, P256Key, RsaKey, SigningKey};
use serde::{Serialize, Deserialize};
use std::str::FromStr;
use crate::{Result, ApiError, EncodingApi};

/// 支持的密钥算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// Curve25519 (Ed25519 签名 + X25519 密钥交换)
    Curve25519,
    /// NIST P-256 (secp256r1)
    P256,
    /// RSA 2048-bit
    Rsa2048,
    /// RSA 4096-bit
    Rsa4096,
}

impl Algorithm {
    /// 获取算法名称
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Curve25519 => "Curve25519",
            Algorithm::P256 => "P256",
            Algorithm::Rsa2048 => "RSA2048",
            Algorithm::Rsa4096 => "RSA4096",
        }
    }
}

impl FromStr for Algorithm {
    type Err = ApiError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "CURVE25519" | "ED25519" | "X25519" => Ok(Algorithm::Curve25519),
            "P256" | "SECP256R1" => Ok(Algorithm::P256),
            "RSA2048" | "RSA-2048" => Ok(Algorithm::Rsa2048),
            "RSA4096" | "RSA-4096" => Ok(Algorithm::Rsa4096),
            _ => Err(ApiError::InvalidAlgorithm(format!(
                "不支持的算法: {}. 支持的算法: Curve25519, P256, RSA2048, RSA4096",
                s
            ))),
        }
    }
}

/// 密钥 API（统一的跨语言接口）
///
/// 使用 trait object 包装不同类型的密钥，提供统一的接口。
/// 所有语言绑定都应该遵循这个接口标准。
pub struct KeyPair {
    inner: Box<dyn SigningKey>,
    algorithm: Algorithm,
}

impl KeyPair {
    /// 生成新的密钥对
    ///
    /// 所有语言绑定必须提供此功能。
    ///
    /// # 示例（Rust）
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use capsula_api::{KeyPair, Algorithm};
    ///
    /// let keypair = KeyPair::generate(Algorithm::Curve25519)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # 对应的语言绑定示例
    ///
    /// Python: `KeyPair.generate(Algorithm.CURVE25519)`
    /// Java: `KeyPair.generate(Algorithm.CURVE25519)`
    /// JavaScript: `KeyPair.generate(Algorithm.CURVE25519)`
    pub fn generate(algorithm: Algorithm) -> Result<Self> {
        let inner: Box<dyn SigningKey> = match algorithm {
            Algorithm::Curve25519 => Box::new(Curve25519::generate()?),
            Algorithm::P256 => Box::new(P256Key::generate()?),
            Algorithm::Rsa2048 => Box::new(RsaKey::generate_2048()?),
            Algorithm::Rsa4096 => Box::new(RsaKey::generate_4096()?),
        };
        Ok(KeyPair { inner, algorithm })
    }

    /// 获取密钥算法类型
    ///
    /// 所有语言绑定必须提供此功能。
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// 从 PKCS#8 DER 格式导入私钥（自动检测算法）
    ///
    /// 所有语言绑定必须提供此功能。
    /// 这是跨语言传输密钥时的标准导入方法。
    pub fn from_pkcs8_der_auto_detect(der: &[u8]) -> Result<Self> {
        // 尝试不同的算法
        if let Ok(key) = Curve25519::from_pkcs8_der(der) {
            return Ok(KeyPair {
                inner: Box::new(key),
                algorithm: Algorithm::Curve25519,
            });
        }

        if let Ok(key) = P256Key::from_pkcs8_der(der) {
            return Ok(KeyPair {
                inner: Box::new(key),
                algorithm: Algorithm::P256,
            });
        }

        if let Ok(key) = RsaKey::from_pkcs8_der(der) {
            // RSA 根据密钥长度判断是 2048 还是 4096
            let algorithm = if key.size_bits() >= 4096 {
                Algorithm::Rsa4096
            } else {
                Algorithm::Rsa2048
            };
            return Ok(KeyPair {
                inner: Box::new(key),
                algorithm,
            });
        }

        Err(ApiError::UnsupportedAlgorithm(
            "无法识别密钥格式，不支持的算法".to_string(),
        ))
    }

    /// 从指定算法的 PKCS#8 DER 格式导入私钥
    ///
    /// 当算法已知时使用，比自动检测更高效。
    pub fn from_pkcs8_der(algorithm: Algorithm, der: &[u8]) -> Result<Self> {
        let inner: Box<dyn SigningKey> = match algorithm {
            Algorithm::Curve25519 => Box::new(Curve25519::from_pkcs8_der(der)?),
            Algorithm::P256 => Box::new(P256Key::from_pkcs8_der(der)?),
            Algorithm::Rsa2048 | Algorithm::Rsa4096 => Box::new(RsaKey::from_pkcs8_der(der)?),
        };
        Ok(KeyPair { inner, algorithm })
    }

    /// 从 PKCS#8 PEM 格式导入私钥（自动检测算法）
    ///
    /// 所有语言绑定必须提供此功能。
    pub fn from_pkcs8_pem_auto_detect(pem: &str) -> Result<Self> {
        // 尝试不同的算法
        if let Ok(key) = Curve25519::from_pkcs8_pem(pem) {
            return Ok(KeyPair {
                inner: Box::new(key),
                algorithm: Algorithm::Curve25519,
            });
        }

        if let Ok(key) = P256Key::from_pkcs8_pem(pem) {
            return Ok(KeyPair {
                inner: Box::new(key),
                algorithm: Algorithm::P256,
            });
        }

        if let Ok(key) = RsaKey::from_pkcs8_pem(pem) {
            // RSA 根据密钥长度判断是 2048 还是 4096
            let algorithm = if key.size_bits() >= 4096 {
                Algorithm::Rsa4096
            } else {
                Algorithm::Rsa2048
            };
            return Ok(KeyPair {
                inner: Box::new(key),
                algorithm,
            });
        }

        Err(ApiError::UnsupportedAlgorithm(
            "无法识别 PEM 格式，不支持的算法".to_string(),
        ))
    }

    /// 从指定算法的 PKCS#8 PEM 格式导入私钥
    pub fn from_pkcs8_pem(algorithm: Algorithm, pem: &str) -> Result<Self> {
        let inner: Box<dyn SigningKey> = match algorithm {
            Algorithm::Curve25519 => Box::new(Curve25519::from_pkcs8_pem(pem)?),
            Algorithm::P256 => Box::new(P256Key::from_pkcs8_pem(pem)?),
            Algorithm::Rsa2048 | Algorithm::Rsa4096 => Box::new(RsaKey::from_pkcs8_pem(pem)?),
        };
        Ok(KeyPair { inner, algorithm })
    }

    /// 导出私钥为 PKCS#8 PEM 格式
    ///
    /// 所有语言绑定必须提供此功能。
    pub fn private_key_to_pem(&self) -> Result<String> {
        Ok(self.inner.to_pkcs8_pem()?)
    }

    /// 导出私钥为 PKCS#8 DER 格式
    ///
    /// 所有语言绑定必须提供此功能。
    pub fn private_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.to_pkcs8_der()?)
    }

    /// 导出公钥为 SPKI PEM 格式
    ///
    /// 所有语言绑定必须提供此功能。
    pub fn public_key_to_pem(&self) -> Result<String> {
        Ok(self.inner.to_spki_pem()?)
    }

    /// 导出公钥为 SPKI DER 格式
    ///
    /// 所有语言绑定必须提供此功能。
    pub fn public_key_to_der(&self) -> Result<Vec<u8>> {
        Ok(self.inner.to_spki_der()?)
    }

    /// 导出为 Base64 格式（便于 JSON 传输）
    ///
    /// 所有语言绑定必须提供此功能，用于跨语言序列化。
    pub fn to_base64(&self) -> Result<Base64KeyPair> {
        Ok(Base64KeyPair {
            algorithm: self.algorithm(),
            private_key: EncodingApi::encode_base64(&self.private_key_to_der()?),
            public_key: EncodingApi::encode_base64(&self.public_key_to_der()?),
        })
    }

    /// 从 Base64 格式导入
    ///
    /// 所有语言绑定必须提供此功能，用于跨语言反序列化。
    pub fn from_base64(base64: &Base64KeyPair) -> Result<Self> {
        let private_key_der = EncodingApi::decode_base64(&base64.private_key)?;
        Self::from_pkcs8_der(base64.algorithm, &private_key_der)
    }

    /// 导出为 JSON 字符串
    ///
    /// 所有语言绑定必须提供此功能，用于跨语言数据传输。
    pub fn to_json(&self) -> Result<String> {
        let base64 = self.to_base64()?;
        Ok(serde_json::to_string(&base64)?)
    }

    /// 从 JSON 字符串导入
    ///
    /// 所有语言绑定必须提供此功能，用于跨语言数据接收。
    pub fn from_json(json: &str) -> Result<Self> {
        let base64: Base64KeyPair = serde_json::from_str(json)?;
        Self::from_base64(&base64)
    }

    /// 对消息进行签名
    ///
    /// 所有语言绑定必须提供此功能。
    ///
    /// # 参数
    ///
    /// * `message` - 要签名的消息
    ///
    /// # 返回
    ///
    /// 签名结果（二进制格式）
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.inner.sign(message).map_err(|e| ApiError::SigningError(e.to_string()))
    }
}

/// Base64 编码的密钥对（用于 JSON 序列化）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Base64KeyPair {
    /// 算法类型
    pub algorithm: Algorithm,
    /// Base64 编码的私钥 (PKCS#8 DER)
    pub private_key: String,
    /// Base64 编码的公钥 (SPKI DER)
    pub public_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_curve25519() {
        let keypair = KeyPair::generate(Algorithm::Curve25519).unwrap();
        assert_eq!(keypair.algorithm(), Algorithm::Curve25519);
        assert!(!keypair.private_key_to_der().unwrap().is_empty());
        assert!(!keypair.public_key_to_der().unwrap().is_empty());
    }

    #[test]
    fn test_generate_p256() {
        let keypair = KeyPair::generate(Algorithm::P256).unwrap();
        assert_eq!(keypair.algorithm(), Algorithm::P256);
        assert!(!keypair.private_key_to_der().unwrap().is_empty());
        assert!(!keypair.public_key_to_der().unwrap().is_empty());
    }

    #[test]
    fn test_generate_rsa2048() {
        let keypair = KeyPair::generate(Algorithm::Rsa2048).unwrap();
        assert_eq!(keypair.algorithm(), Algorithm::Rsa2048);
        assert!(!keypair.private_key_to_der().unwrap().is_empty());
        assert!(!keypair.public_key_to_der().unwrap().is_empty());
    }

    #[test]
    fn test_pem_export() {
        let keypair = KeyPair::generate(Algorithm::Curve25519).unwrap();
        let private_pem = keypair.private_key_to_pem().unwrap();
        let public_pem = keypair.public_key_to_pem().unwrap();

        assert!(private_pem.contains("BEGIN PRIVATE KEY"));
        assert!(public_pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn test_to_base64_and_back() {
        let keypair = KeyPair::generate(Algorithm::Curve25519).unwrap();
        let base64 = keypair.to_base64().unwrap();
        let restored = KeyPair::from_base64(&base64).unwrap();

        assert_eq!(keypair.algorithm(), restored.algorithm());
        assert_eq!(
            keypair.private_key_to_der().unwrap(),
            restored.private_key_to_der().unwrap()
        );
    }

    #[test]
    fn test_to_json_and_back() {
        let keypair = KeyPair::generate(Algorithm::P256).unwrap();
        let json = keypair.to_json().unwrap();
        let restored = KeyPair::from_json(&json).unwrap();

        assert_eq!(keypair.algorithm(), restored.algorithm());
        assert_eq!(
            keypair.private_key_to_der().unwrap(),
            restored.private_key_to_der().unwrap()
        );
    }

    #[test]
    fn test_auto_detect_from_der() {
        let keypair = KeyPair::generate(Algorithm::Curve25519).unwrap();
        let der = keypair.private_key_to_der().unwrap();

        let restored = KeyPair::from_pkcs8_der_auto_detect(&der).unwrap();
        assert_eq!(keypair.algorithm(), restored.algorithm());
    }

    #[test]
    fn test_auto_detect_from_pem() {
        let keypair = KeyPair::generate(Algorithm::P256).unwrap();
        let pem = keypair.private_key_to_pem().unwrap();

        let restored = KeyPair::from_pkcs8_pem_auto_detect(&pem).unwrap();
        assert_eq!(keypair.algorithm(), restored.algorithm());
    }

    #[test]
    fn test_algorithm_from_str() {
        assert_eq!(Algorithm::from_str("Curve25519").unwrap(), Algorithm::Curve25519);
        assert_eq!(Algorithm::from_str("ed25519").unwrap(), Algorithm::Curve25519);
        assert_eq!(Algorithm::from_str("P256").unwrap(), Algorithm::P256);
        assert_eq!(Algorithm::from_str("rsa2048").unwrap(), Algorithm::Rsa2048);
        assert!(Algorithm::from_str("invalid").is_err());
    }
}
