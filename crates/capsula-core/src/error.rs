//! 核心错误类型定义

use thiserror::Error;

/// 核心错误类型
#[derive(Error, Debug)]
pub enum CoreError {
    /// 加密错误
    #[error("Crypto error: {0}")]
    CryptoError(#[from] capsula_crypto::Error),

    /// PKI错误
    #[error("PKI error: {0}")]
    PkiError(#[from] capsula_pki::PkiError),

    /// 访问控制错误
    #[error("Access control error: {0}")]
    AccessControlError(String),

    /// 数据错误
    #[error("Data error: {0}")]
    DataError(String),

    /// 其他错误
    #[error("Other error: {0}")]
    Other(String),
}

/// 核心操作结果类型
pub type Result<T> = std::result::Result<T, CoreError>;
