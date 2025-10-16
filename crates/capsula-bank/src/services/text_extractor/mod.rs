//! 文本提取服务
//!
//! 从各种文件格式中提取文本内容

use async_trait::async_trait;
use std::path::Path;
use std::io;

pub mod simple;

pub use simple::SimpleTextExtractor;

/// 文本提取器 trait
///
/// 定义统一的文本提取接口，支持多种文件格式
#[async_trait]
pub trait TextExtractor: Send + Sync {
    /// 从文件中提取文本
    ///
    /// # 参数
    /// - `file_path`: 文件路径
    /// - `mime_type`: 文件 MIME 类型（可选）
    ///
    /// # 返回
    /// 提取的文本内容
    async fn extract(&self, file_path: &Path, mime_type: Option<&str>) -> io::Result<String>;

    /// 检查是否支持指定的 MIME 类型
    ///
    /// # 参数
    /// - `mime_type`: MIME 类型
    fn supports(&self, mime_type: &str) -> bool;

    /// 获取支持的 MIME 类型列表
    fn supported_types(&self) -> Vec<String>;
}

/// 文本提取错误
#[derive(Debug)]
pub enum ExtractionError {
    /// IO 错误
    Io(io::Error),
    /// 不支持的文件格式
    UnsupportedFormat(String),
    /// 解析错误
    ParseError(String),
    /// 编码错误
    EncodingError(String),
}

impl std::fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractionError::Io(e) => write!(f, "IO error: {}", e),
            ExtractionError::UnsupportedFormat(mime) => {
                write!(f, "Unsupported format: {}", mime)
            }
            ExtractionError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            ExtractionError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for ExtractionError {}

impl From<io::Error> for ExtractionError {
    fn from(error: io::Error) -> Self {
        ExtractionError::Io(error)
    }
}
