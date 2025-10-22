//! 本地文件系统存储实现

use std::{
    io,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use tokio::{fs, io::AsyncWriteExt};

use super::StorageProvider;

/// 本地文件系统存储
///
/// 将文件存储在本地文件系统中
#[derive(Debug, Clone)]
pub struct LocalStorage {
    /// 存储根目录
    root_dir: PathBuf,
    /// URL 前缀（用于生成访问 URL）
    url_prefix: String,
}

impl LocalStorage {
    /// 创建新的本地存储实例
    ///
    /// # 参数
    /// - `root_dir`: 存储根目录
    /// - `url_prefix`: URL 前缀，如 "http://localhost:8080/files"
    pub fn new<P: AsRef<Path>>(root_dir: P, url_prefix: String) -> io::Result<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();

        // 确保根目录存在
        if !root_dir.exists() {
            std::fs::create_dir_all(&root_dir)?;
        }

        Ok(Self {
            root_dir,
            url_prefix,
        })
    }

    /// 获取完整的文件系统路径
    fn get_full_path(&self, key: &str) -> PathBuf {
        self.root_dir.join(key)
    }

    /// 确保文件的父目录存在
    async fn ensure_parent_dir(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl StorageProvider for LocalStorage {
    async fn store(&self, key: &str, data: &[u8]) -> io::Result<String> {
        let full_path = self.get_full_path(key);

        // 确保父目录存在
        self.ensure_parent_dir(&full_path).await?;

        // 写入文件
        let mut file = fs::File::create(&full_path).await?;
        file.write_all(data).await?;
        file.flush().await?;

        Ok(self.get_url(key))
    }

    async fn retrieve(&self, key: &str) -> io::Result<Vec<u8>> {
        let full_path = self.get_full_path(key);
        fs::read(&full_path).await
    }

    async fn delete(&self, key: &str) -> io::Result<()> {
        let full_path = self.get_full_path(key);
        fs::remove_file(&full_path).await
    }

    async fn exists(&self, key: &str) -> io::Result<bool> {
        let full_path = self.get_full_path(key);
        Ok(full_path.exists())
    }

    fn get_url(&self, key: &str) -> String {
        format!("{}/{}", self.url_prefix, key)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_local_storage_store_and_retrieve() {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            LocalStorage::new(temp_dir.path(), "http://localhost:8080/files".to_string()).unwrap();

        let key = "test/file.txt";
        let data = b"Hello, World!";

        // 存储文件
        let url = storage.store(key, data).await.unwrap();
        assert_eq!(url, "http://localhost:8080/files/test/file.txt");

        // 检查文件是否存在
        assert!(storage.exists(key).await.unwrap());

        // 读取文件
        let retrieved = storage.retrieve(key).await.unwrap();
        assert_eq!(retrieved, data);

        // 删除文件
        storage.delete(key).await.unwrap();
        assert!(!storage.exists(key).await.unwrap());
    }

    #[tokio::test]
    async fn test_local_storage_nested_directories() {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            LocalStorage::new(temp_dir.path(), "http://localhost:8080/files".to_string()).unwrap();

        let key = "a/b/c/d/file.txt";
        let data = b"Nested file";

        // 存储文件（自动创建父目录）
        storage.store(key, data).await.unwrap();

        // 验证文件存在
        assert!(storage.exists(key).await.unwrap());

        // 读取文件
        let retrieved = storage.retrieve(key).await.unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_local_storage_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let storage =
            LocalStorage::new(temp_dir.path(), "http://localhost:8080/files".to_string()).unwrap();

        let key = "nonexistent.txt";

        // 检查不存在的文件
        assert!(!storage.exists(key).await.unwrap());

        // 读取不存在的文件应该失败
        let result = storage.retrieve(key).await;
        assert!(result.is_err());
    }
}
