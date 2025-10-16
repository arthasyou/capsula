//! 服务错误类型定义
//!
//! 提供统一的错误类型用于所有服务

use std::io;

/// 服务错误类型
#[derive(Debug)]
pub enum ServiceError {
    /// IO 错误
    Io(io::Error),

    /// 存储错误
    Storage(String),

    /// 文本提取错误
    TextExtraction(String),

    /// BNF 解析错误
    BnfParse(String),

    /// 元数据生成错误
    MetadataGeneration(String),

    /// 胶囊封装错误
    CapsuleSealing(String),

    /// 配置错误
    Configuration(String),

    /// 临时文件错误
    TempFile(String),

    /// 验证错误
    Validation(String),

    /// 不支持的操作
    Unsupported(String),

    /// 其他错误
    Other(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Io(e) => write!(f, "IO error: {}", e),
            ServiceError::Storage(msg) => write!(f, "Storage error: {}", msg),
            ServiceError::TextExtraction(msg) => write!(f, "Text extraction error: {}", msg),
            ServiceError::BnfParse(msg) => write!(f, "BNF parse error: {}", msg),
            ServiceError::MetadataGeneration(msg) => {
                write!(f, "Metadata generation error: {}", msg)
            }
            ServiceError::CapsuleSealing(msg) => write!(f, "Capsule sealing error: {}", msg),
            ServiceError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            ServiceError::TempFile(msg) => write!(f, "Temporary file error: {}", msg),
            ServiceError::Validation(msg) => write!(f, "Validation error: {}", msg),
            ServiceError::Unsupported(msg) => write!(f, "Unsupported operation: {}", msg),
            ServiceError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for ServiceError {}

// 从 IO 错误转换
impl From<io::Error> for ServiceError {
    fn from(error: io::Error) -> Self {
        ServiceError::Io(error)
    }
}

// 从 serde_json 错误转换
impl From<serde_json::Error> for ServiceError {
    fn from(error: serde_json::Error) -> Self {
        ServiceError::Other(format!("JSON error: {}", error))
    }
}

/// 服务结果类型
pub type ServiceResult<T> = Result<T, ServiceError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ServiceError::Storage("test error".to_string());
        assert_eq!(err.to_string(), "Storage error: test error");

        let err = ServiceError::Validation("invalid input".to_string());
        assert_eq!(err.to_string(), "Validation error: invalid input");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let service_err: ServiceError = io_err.into();

        match service_err {
            ServiceError::Io(_) => {}
            _ => panic!("Expected ServiceError::Io"),
        }
    }

    #[test]
    fn test_json_error_conversion() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let service_err: ServiceError = json_err.into();

        match service_err {
            ServiceError::Other(_) => {}
            _ => panic!("Expected ServiceError::Other"),
        }
    }
}
