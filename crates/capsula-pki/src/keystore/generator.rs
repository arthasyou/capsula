//! 密钥生成模块

use crate::error::Result;
use capsula_key::Key;

/// 密钥类型
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    /// RSA密钥
    RSA(u32), // 密钥长度
    /// ECDSA密钥  
    ECDSA(String), // 曲线名称
    /// Ed25519密钥
    Ed25519,
}

/// 密钥生成器
pub struct KeyGenerator;

impl KeyGenerator {
    /// 创建新的密钥生成器
    pub fn new() -> Self {
        Self
    }

    /// 生成密钥
    pub fn generate_key(&self, key_type: KeyType) -> Result<Box<dyn capsula_key::Key>> {
        match key_type {
            KeyType::Ed25519 => Ok(Box::new(capsula_key::Curve25519::generate()?)),
            KeyType::ECDSA(_) => Ok(Box::new(capsula_key::P256Key::generate()?)), // 使用P256实现
            KeyType::RSA(_) => Ok(Box::new(capsula_key::RsaKey::generate()?)),   // 使用RSA实现
        }
    }
}