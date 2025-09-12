//! Key trait definition for cryptographic key abstraction
//!
//! This module defines the core Key trait that provides a unified interface
//! for different cryptographic key implementations.

use pkcs8::spki::AlgorithmIdentifierOwned;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// Import key implementations
pub mod curve25519;
pub mod p256;
pub mod rsa;

pub use curve25519::Curve25519;
pub use p256::P256Key;
pub use rsa::RsaKey;

/// Core trait for cryptographic keys
///
/// This trait provides a unified interface for different cryptographic key implementations,
/// enabling algorithm-agnostic code in the PKI layer. It focuses on key behaviors rather than
/// construction - use the concrete type's methods (e.g., `Curve25519::generate()`) for key
/// creation.

// ============================================================================
// Core Trait: Basic Key Identity
// ============================================================================

/// 核心密钥trait：任何密钥都至少能提供身份信息和公钥集合
pub trait Key: Send + Sync {
    /// 算法类型（使用枚举更稳定）
    fn algorithm(&self) -> Algorithm;

    /// 返回该密钥暴露的所有公钥及其用途
    fn public_keys(&self) -> PublicKeySet;

    /// SPKI指纹（SHA-256）- 标准化指纹算法
    fn fingerprint_sha256_spki(&self) -> Vec<u8>;

    /// 密钥唯一标识符
    fn key_id(&self) -> Vec<u8>;

    /// 声明支持的密码学能力
    fn capabilities(&self) -> KeyCapabilities;

    /// 获取hex编码的密钥ID
    fn key_id_hex(&self) -> String {
        hex::encode(self.key_id())
    }

    /// 获取hex编码的指纹
    fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint_sha256_spki())
    }
}

// ============================================================================
// Capability Traits: Optional Implementations
// ============================================================================

/// 数字签名能力（可选实现）
pub trait KeySign {
    /// 对消息进行数字签名
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// 获取签名算法标识符
    fn signature_algorithm_id(&self) -> AlgorithmIdentifierOwned;
}

/// 密钥协商能力（可选实现）
pub trait KeyAgree {
    /// 与对方公钥计算共享秘密（输入SPKI DER格式以减少歧义）
    fn compute_shared_secret(&self, peer_spki_der: &[u8]) -> Result<Vec<u8>>;

    /// 获取密钥交换算法标识符
    fn kex_algorithm_id(&self) -> AlgorithmIdentifierOwned;
}

/// 加密解密能力（可选实现，主要用于RSA）
pub trait KeyEncDec {
    /// 加密数据
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// 解密数据  
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// 获取加密算法标识符
    fn encryption_algorithm_id(&self) -> AlgorithmIdentifierOwned;
}

/// 私钥导出能力（可选实现，HSM可能不支持）
pub trait ExportablePrivateKey {
    /// 导出为PKCS#8 DER格式（使用安全内存）
    fn to_pkcs8_der(&self) -> Result<Vec<u8>>;

    /// 导出为PKCS#8 PEM格式
    fn to_pkcs8_pem(&self) -> Result<String>;

    /// 保存私钥到PEM文件
    fn save_pkcs8_pem_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let pem = self.to_pkcs8_pem()?;
        std::fs::write(path, pem).map_err(Error::from)
    }

    /// 保存私钥到DER文件
    fn save_pkcs8_der_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let der = self.to_pkcs8_der()?;
        std::fs::write(path, der).map_err(Error::from)
    }
}

/// 密钥文件I/O能力（导出所有密钥到文件）
pub trait KeyFileIO {
    /// 导出所有密钥（私钥和公钥）到指定目录
    /// 返回导出信息包含所有文件路径
    fn export_all_keys<P: AsRef<std::path::Path>>(&self, base_dir: P, name_prefix: &str) -> Result<KeyExportInfo>;
    
    /// 导出公钥到PEM文件
    fn export_public_keys_pem<P: AsRef<std::path::Path>>(&self, base_dir: P, name_prefix: &str) -> Result<Vec<PublicKeyExportInfo>>;
    
    /// 导出公钥到DER文件  
    fn export_public_keys_der<P: AsRef<std::path::Path>>(&self, base_dir: P, name_prefix: &str) -> Result<Vec<PublicKeyExportInfo>>;
}

// ============================================================================
// Supporting Data Structures
// ============================================================================

/// 算法枚举（比字符串更稳定）
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

/// 密钥能力标志位
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCapabilities {
    bits: u32,
}

impl KeyCapabilities {
    pub const SIGNING: Self = Self { bits: 0b0001 };
    pub const KEY_AGREEMENT: Self = Self { bits: 0b0010 };
    pub const ENCRYPTION: Self = Self { bits: 0b0100 };

    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub const fn new(bits: u32) -> Self {
        Self { bits }
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }

    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    pub fn supports_signing(self) -> bool {
        self.contains(Self::SIGNING)
    }

    pub fn supports_key_agreement(self) -> bool {
        self.contains(Self::KEY_AGREEMENT)
    }

    pub fn supports_encryption(self) -> bool {
        self.contains(Self::ENCRYPTION)
    }
}

/// 公钥集合
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeySet {
    pub keys: Vec<PublicKeyEntry>,
}

impl PublicKeySet {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn add_key(&mut self, usage: KeyUsage, spki_der: Vec<u8>) {
        self.keys.push(PublicKeyEntry {
            usage,
            spki_der,
            raw_public_key: None,
        });
    }

    pub fn add_key_with_raw(&mut self, usage: KeyUsage, spki_der: Vec<u8>, raw: Vec<u8>) {
        self.keys.push(PublicKeyEntry {
            usage,
            spki_der,
            raw_public_key: Some(raw),
        });
    }

    pub fn find_by_usage(&self, usage: KeyUsage) -> Option<&PublicKeyEntry> {
        self.keys.iter().find(|k| k.usage == usage)
    }

    pub fn signing_key(&self) -> Option<&PublicKeyEntry> {
        self.find_by_usage(KeyUsage::Signing)
    }

    pub fn key_agreement_key(&self) -> Option<&PublicKeyEntry> {
        self.find_by_usage(KeyUsage::KeyAgreement)
    }

    pub fn encryption_key(&self) -> Option<&PublicKeyEntry> {
        self.find_by_usage(KeyUsage::Encryption)
    }
}

/// 公钥条目
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyEntry {
    pub usage: KeyUsage,
    pub spki_der: Vec<u8>,
    pub raw_public_key: Option<Vec<u8>>,
}

/// 密钥用途枚举
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyUsage {
    Signing,
    KeyAgreement,
    Encryption,
}

impl KeyUsage {
    /// 获取字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyUsage::Signing => "signing",
            KeyUsage::KeyAgreement => "key_exchange",
            KeyUsage::Encryption => "encryption",
        }
    }

    /// 从字符串解析
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "signing" => Some(KeyUsage::Signing),
            "key_exchange" => Some(KeyUsage::KeyAgreement),
            "encryption" => Some(KeyUsage::Encryption),
            _ => None,
        }
    }
}

/// 公钥信息（重新设计以匹配新的trait系统）
///
/// 这个结构应该直接使用PublicKeySet，语义更清晰
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// 算法类型
    pub algorithm: Algorithm,
    /// 密钥ID（hex编码）
    pub key_id: String,
    /// 所有公钥及其用途
    pub public_keys: PublicKeySet,
    /// 支持的能力
    pub capabilities: KeyCapabilities,
    /// 可选的元数据
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<KeyMetadata>,
}

/// Optional metadata for key identification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyMetadata {
    /// Human-readable name for the key
    pub name: Option<String>,
    /// Email associated with the key
    pub email: Option<String>,
    /// Key creation timestamp (Unix timestamp)
    pub created_at: Option<u64>,
    /// Key expiration timestamp (Unix timestamp)
    pub expires_at: Option<u64>,
}

impl<K: Key> From<&K> for PublicKeyInfo {
    fn from(key: &K) -> Self {
        Self {
            algorithm: key.algorithm(),
            key_id: key.key_id_hex(),
            public_keys: key.public_keys(),
            capabilities: key.capabilities(),
            metadata: None,
        }
    }
}

impl PublicKeyInfo {
    /// 使用元数据创建PublicKeyInfo
    pub fn with_metadata<K: Key>(key: &K, metadata: KeyMetadata) -> Self {
        let mut info = Self::from(key);
        info.metadata = Some(metadata);
        info
    }

    /// 获取签名公钥（如果存在）
    pub fn signing_key(&self) -> Option<&PublicKeyEntry> {
        self.public_keys.signing_key()
    }

    /// 获取密钥交换公钥（如果存在）
    pub fn key_agreement_key(&self) -> Option<&PublicKeyEntry> {
        self.public_keys.key_agreement_key()
    }

    /// 获取加密公钥（如果存在）
    pub fn encryption_key(&self) -> Option<&PublicKeyEntry> {
        self.public_keys.encryption_key()
    }

    /// 检查是否支持指定能力
    pub fn supports_capability(&self, capability: KeyCapabilities) -> bool {
        self.capabilities.contains(capability)
    }

    /// 按用途查找公钥
    pub fn find_key_by_usage(&self, usage: KeyUsage) -> Option<&PublicKeyEntry> {
        self.public_keys.find_by_usage(usage)
    }
}

/// 密钥导出信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExportInfo {
    /// 算法名称
    pub algorithm: String,
    /// 密钥ID
    pub key_id: String,
    /// 私钥文件路径
    pub private_key_path: String,
    /// 所有公钥文件信息
    pub public_key_paths: Vec<PublicKeyExportInfo>,
}

/// 公钥导出信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyExportInfo {
    /// 公钥类型
    pub key_type: KeyUsage,
    /// 文件路径
    pub file_path: String,
}

impl KeyExportInfo {
    /// 保存导出信息到JSON文件
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| Error::EncodingError(format!("Failed to serialize export info: {}", e)))?;
        std::fs::write(path, json).map_err(Error::from)
    }

    /// 从JSON文件加载导出信息
    pub fn load_from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let json = std::fs::read_to_string(path).map_err(Error::from)?;
        serde_json::from_str(&json)
            .map_err(|e| Error::EncodingError(format!("Failed to deserialize export info: {}", e)))
    }

    /// 获取所有文件路径
    pub fn all_file_paths(&self) -> Vec<String> {
        let mut paths = vec![self.private_key_path.clone()];
        paths.extend(self.public_key_paths.iter().map(|p| p.file_path.clone()));
        paths
    }

    /// 按类型查找公钥文件路径
    pub fn find_public_key_path(&self, key_type: KeyUsage) -> Option<&str> {
        self.public_key_paths
            .iter()
            .find(|p| p.key_type == key_type)
            .map(|p| p.file_path.as_str())
    }

    /// 按字符串类型查找公钥文件路径（向后兼容）
    pub fn find_public_key_path_by_str(&self, key_type_str: &str) -> Option<&str> {
        KeyUsage::from_str(key_type_str).and_then(|key_type| self.find_public_key_path(key_type))
    }
}

/// Verify a signature using Ed25519 (for backward compatibility)
pub use curve25519::verify;
