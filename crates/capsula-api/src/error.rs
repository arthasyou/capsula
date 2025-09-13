//! API错误类型定义

use thiserror::Error;

/// API错误类型
#[derive(Error, Debug)]
pub enum ApiError {
    /// 核心错误
    #[error("Core error: {0}")]
    CoreError(#[from] capsula_core::error::CoreError),

    /// 认证错误
    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    /// 授权错误
    #[error("Authorization error: {0}")]
    AuthorizationError(String),

    /// 请求错误
    #[error("Request error: {0}")]
    RequestError(String),

    /// 其他错误
    #[error("Other error: {0}")]
    Other(String),
}

/// API操作结果类型
pub type Result<T> = std::result::Result<T, ApiError>;
