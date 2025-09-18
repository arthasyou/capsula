//! 核心错误类型定义

use thiserror::Error;

/// 核心错误类型
#[derive(Error, Debug)]
pub enum CoreError {
    /// PKI错误
    #[error("PKI error: {0}")]
    PkiError(#[from] capsula_pki::PkiError),

    /// 密钥错误
    #[error("Key error: {0}")]
    KeyError(#[from] capsula_key::error::Error),

    /// 加密错误
    #[error("Crypto error: {0}")]
    CryptoError(#[from] capsula_crypto::error::Error),

    /// 封包错误
    #[error("Encapsulation error: {0}")]
    EncapsulationError(String),

    /// 解包错误  
    #[error("Decapsulation error: {0}")]
    DecapsulationError(String),

    /// 签名验证错误
    #[error("Signature verification error: {0}")]
    SignatureError(String),

    /// 访问控制错误
    #[error("Access control error: {0}")]
    AccessControlError(String),

    /// 策略验证错误
    #[error("Policy validation error: {0}")]
    PolicyError(String),

    /// 数据格式错误
    #[error("Data format error: {0}")]
    FormatError(String),

    /// 完整性验证错误
    #[error("Integrity check error: {0}")]
    IntegrityError(String),

    /// JSON序列化错误
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// 时间解析错误
    #[error("Time error: {0}")]
    TimeError(#[from] time::error::Parse),

    /// 数据错误
    #[error("Data error: {0}")]
    DataError(String),

    /// 其他错误
    #[error("Other error: {0}")]
    Other(String),
}

/// 核心操作结果类型
pub type Result<T> = std::result::Result<T, CoreError>;
