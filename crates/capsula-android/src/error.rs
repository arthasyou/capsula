//! Android 库错误类型

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CapsulaAndroidError {
    #[error("JNI error: {0}")]
    JniError(String),

    #[error("API error: {0}")]
    ApiError(#[from] capsula_api::ApiError),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}
