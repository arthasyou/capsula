//! 对象存储抽象层
//!
//! 提供统一的存储接口，支持本地文件系统、S3等多种存储后端

use async_trait::async_trait;
use std::io;

pub mod local;

pub use local::LocalStorage;

/// 存储提供者 trait
///
/// 定义统一的存储接口，可以支持多种后端实现
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// 存储文件
    ///
    /// # 参数
    /// - `key`: 存储键（如文件路径或对象键）
    /// - `data`: 要存储的数据
    ///
    /// # 返回
    /// 存储后的访问路径或 URL
    async fn store(&self, key: &str, data: &[u8]) -> io::Result<String>;

    /// 读取文件
    ///
    /// # 参数
    /// - `key`: 存储键
    ///
    /// # 返回
    /// 文件内容
    async fn retrieve(&self, key: &str) -> io::Result<Vec<u8>>;

    /// 删除文件
    ///
    /// # 参数
    /// - `key`: 存储键
    async fn delete(&self, key: &str) -> io::Result<()>;

    /// 检查文件是否存在
    ///
    /// # 参数
    /// - `key`: 存储键
    async fn exists(&self, key: &str) -> io::Result<bool>;

    /// 获取文件访问 URL
    ///
    /// # 参数
    /// - `key`: 存储键
    ///
    /// # 返回
    /// 文件访问 URL 或路径
    fn get_url(&self, key: &str) -> String;
}

/// 存储错误类型
#[derive(Debug)]
pub enum StorageError {
    /// IO 错误
    Io(io::Error),
    /// 文件不存在
    NotFound(String),
    /// 权限错误
    PermissionDenied(String),
    /// 其他错误
    Other(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "IO error: {}", e),
            StorageError::NotFound(key) => write!(f, "File not found: {}", key),
            StorageError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            StorageError::Other(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<io::Error> for StorageError {
    fn from(error: io::Error) -> Self {
        StorageError::Io(error)
    }
}
