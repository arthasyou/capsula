//! 统一错误处理

use thiserror::Error;

/// API 层统一错误类型
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("密钥错误")]
    KeyError(#[from] capsula_key::error::Error),

    #[error("加密错误")]
    CryptoError(#[from] capsula_crypto::error::Error),

    #[error("编码错误: {0}")]
    EncodingError(String),

    #[error("签名错误: {0}")]
    SigningError(String),

    #[error("验证错误: {0}")]
    VerificationError(String),

    #[error("无效的算法: {0}")]
    InvalidAlgorithm(String),

    #[error("不支持的算法: {0}")]
    UnsupportedAlgorithm(String),

    #[error("无效的输入: {0}")]
    InvalidInput(String),

    #[error("序列化错误")]
    SerializationError(#[from] serde_json::Error),

    #[error("Base64 解码错误")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("内部错误: {0}")]
    InternalError(String),
}

/// API 层统一 Result 类型
pub type Result<T> = std::result::Result<T, ApiError>;
