//! 元数据生成服务
//!
//! 从文件中生成结构化元数据

use std::{io, path::Path};

use serde::{Deserialize, Serialize};
use tokio::fs;

/// 文件元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// 文件名
    pub filename: String,
    /// 文件大小（字节）
    pub size: u64,
    /// MIME 类型
    pub mime_type: String,
    /// 创建时间（Unix 时间戳）
    pub created_at: Option<i64>,
    /// 修改时间（Unix 时间戳）
    pub modified_at: Option<i64>,
    /// 文件哈希（SHA-256）
    pub hash: Option<String>,
    /// 额外的键值对
    pub extra: std::collections::HashMap<String, String>,
}

/// 元数据生成器
///
/// 从文件中提取和生成元数据
#[derive(Debug, Clone)]
pub struct MetadataGenerator;

impl MetadataGenerator {
    /// 创建新的元数据生成器
    pub fn new() -> Self {
        Self
    }

    /// 从文件生成元数据
    ///
    /// # 参数
    /// - `file_path`: 文件路径
    /// - `mime_type`: 文件 MIME 类型（可选，如果为 None 则自动检测）
    ///
    /// # 返回
    /// 文件元数据
    pub async fn generate(
        &self,
        file_path: &Path,
        mime_type: Option<String>,
    ) -> io::Result<FileMetadata> {
        // 获取文件元数据
        let metadata = fs::metadata(file_path).await?;

        // 获取文件名
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // 获取文件大小
        let size = metadata.len();

        // 检测或使用提供的 MIME 类型
        let mime_type = mime_type.unwrap_or_else(|| self.detect_mime_type(&filename));

        // 获取创建和修改时间
        let created_at = metadata
            .created()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);

        let modified_at = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);

        // 计算文件哈希
        let hash = self.compute_hash(file_path).await.ok();

        Ok(FileMetadata {
            filename,
            size,
            mime_type,
            created_at,
            modified_at,
            hash,
            extra: std::collections::HashMap::new(),
        })
    }

    /// 检测文件的 MIME 类型
    ///
    /// # 参数
    /// - `filename`: 文件名
    ///
    /// # 返回
    /// MIME 类型字符串
    fn detect_mime_type(&self, filename: &str) -> String {
        // 从文件扩展名推断 MIME 类型
        let extension = Path::new(filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match extension.to_lowercase().as_str() {
            "txt" => "text/plain",
            "html" | "htm" => "text/html",
            "css" => "text/css",
            "js" => "text/javascript",
            "json" => "application/json",
            "xml" => "text/xml",
            "pdf" => "application/pdf",
            "png" => "image/png",
            "jpg" | "jpeg" => "image/jpeg",
            "gif" => "image/gif",
            "svg" => "image/svg+xml",
            "mp4" => "video/mp4",
            "mp3" => "audio/mpeg",
            "zip" => "application/zip",
            "md" => "text/markdown",
            "csv" => "text/csv",
            _ => "application/octet-stream",
        }
        .to_string()
    }

    /// 计算文件的 SHA-256 哈希
    ///
    /// # 参数
    /// - `file_path`: 文件路径
    ///
    /// # 返回
    /// 十六进制编码的哈希字符串
    async fn compute_hash(&self, file_path: &Path) -> io::Result<String> {
        use sha2::{Digest, Sha256};

        let content = fs::read(file_path).await?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let result = hasher.finalize();

        Ok(format!("{:x}", result))
    }

    /// 从元数据生成 JSON 字符串
    ///
    /// # 参数
    /// - `metadata`: 文件元数据
    ///
    /// # 返回
    /// JSON 字符串
    pub fn to_json(&self, metadata: &FileMetadata) -> serde_json::Result<String> {
        serde_json::to_string_pretty(metadata)
    }

    /// 从元数据生成字节数组
    ///
    /// # 参数
    /// - `metadata`: 文件元数据
    ///
    /// # 返回
    /// JSON 字节数组
    pub fn to_bytes(&self, metadata: &FileMetadata) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(metadata)
    }
}

impl Default for MetadataGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[tokio::test]
    async fn test_generate_metadata() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = b"Test content for metadata generation";
        temp_file.write_all(content).unwrap();
        temp_file.flush().unwrap();

        let generator = MetadataGenerator::new();
        let metadata = generator
            .generate(temp_file.path(), Some("text/plain".to_string()))
            .await
            .unwrap();

        assert_eq!(metadata.size, content.len() as u64);
        assert_eq!(metadata.mime_type, "text/plain");
        assert!(metadata.hash.is_some());
        assert!(metadata.filename.len() > 0);
    }

    #[tokio::test]
    async fn test_detect_mime_type() {
        let generator = MetadataGenerator::new();

        assert_eq!(generator.detect_mime_type("file.txt"), "text/plain");
        assert_eq!(generator.detect_mime_type("file.html"), "text/html");
        assert_eq!(generator.detect_mime_type("file.json"), "application/json");
        assert_eq!(generator.detect_mime_type("file.pdf"), "application/pdf");
        assert_eq!(generator.detect_mime_type("file.png"), "image/png");
        assert_eq!(
            generator.detect_mime_type("file.unknown"),
            "application/octet-stream"
        );
    }

    #[tokio::test]
    async fn test_compute_hash() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = b"Test content";
        temp_file.write_all(content).unwrap();
        temp_file.flush().unwrap();

        let generator = MetadataGenerator::new();
        let hash = generator.compute_hash(temp_file.path()).await.unwrap();

        // SHA-256 应该返回 64 字符的十六进制字符串
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_to_json() {
        let metadata = FileMetadata {
            filename: "test.txt".to_string(),
            size: 100,
            mime_type: "text/plain".to_string(),
            created_at: Some(1234567890),
            modified_at: Some(1234567900),
            hash: Some("abcd1234".to_string()),
            extra: std::collections::HashMap::new(),
        };

        let generator = MetadataGenerator::new();
        let json = generator.to_json(&metadata).unwrap();

        assert!(json.contains("test.txt"));
        assert!(json.contains("text/plain"));
        assert!(json.contains("100"));
    }

    #[tokio::test]
    async fn test_to_bytes() {
        let metadata = FileMetadata {
            filename: "test.txt".to_string(),
            size: 100,
            mime_type: "text/plain".to_string(),
            created_at: Some(1234567890),
            modified_at: Some(1234567900),
            hash: Some("abcd1234".to_string()),
            extra: std::collections::HashMap::new(),
        };

        let generator = MetadataGenerator::new();
        let bytes = generator.to_bytes(&metadata).unwrap();

        // 应该能够反序列化
        let deserialized: FileMetadata = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.filename, metadata.filename);
        assert_eq!(deserialized.size, metadata.size);
    }
}
