//! 简单文本提取器实现
//!
//! 支持纯文本文件的提取

use super::TextExtractor;
use async_trait::async_trait;
use std::path::Path;
use std::io;
use tokio::fs;

/// 简单文本提取器
///
/// 仅支持纯文本格式（text/plain, text/*)
#[derive(Debug, Clone, Default)]
pub struct SimpleTextExtractor;

impl SimpleTextExtractor {
    /// 创建新的简单文本提取器
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TextExtractor for SimpleTextExtractor {
    async fn extract(&self, file_path: &Path, _mime_type: Option<&str>) -> io::Result<String> {
        // 读取文件内容
        let bytes = fs::read(file_path).await?;

        // 尝试将字节转换为 UTF-8 字符串
        match String::from_utf8(bytes) {
            Ok(text) => Ok(text),
            Err(e) => {
                // 如果不是有效的 UTF-8，尝试从 Latin-1 转换
                let bytes = e.into_bytes();
                let text: String = bytes.iter().map(|&b| b as char).collect();
                Ok(text)
            }
        }
    }

    fn supports(&self, mime_type: &str) -> bool {
        mime_type.starts_with("text/")
    }

    fn supported_types(&self) -> Vec<String> {
        vec![
            "text/plain".to_string(),
            "text/html".to_string(),
            "text/css".to_string(),
            "text/javascript".to_string(),
            "text/csv".to_string(),
            "text/xml".to_string(),
            "text/markdown".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_extract_text_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = "Hello, World!\nThis is a test.";
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let extractor = SimpleTextExtractor::new();
        let result = extractor
            .extract(temp_file.path(), Some("text/plain"))
            .await
            .unwrap();

        assert_eq!(result, content);
    }

    #[tokio::test]
    async fn test_extract_utf8_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = "你好，世界！\nこんにちは世界\n안녕하세요 세계";
        temp_file.write_all(content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let extractor = SimpleTextExtractor::new();
        let result = extractor
            .extract(temp_file.path(), Some("text/plain; charset=utf-8"))
            .await
            .unwrap();

        assert_eq!(result, content);
    }

    #[tokio::test]
    async fn test_supports_mime_types() {
        let extractor = SimpleTextExtractor::new();

        assert!(extractor.supports("text/plain"));
        assert!(extractor.supports("text/html"));
        assert!(extractor.supports("text/csv"));
        assert!(extractor.supports("text/anything"));

        assert!(!extractor.supports("application/json"));
        assert!(!extractor.supports("image/png"));
    }

    #[tokio::test]
    async fn test_supported_types() {
        let extractor = SimpleTextExtractor::new();
        let types = extractor.supported_types();

        assert!(types.contains(&"text/plain".to_string()));
        assert!(types.contains(&"text/html".to_string()));
        assert!(types.contains(&"text/markdown".to_string()));
    }

    #[tokio::test]
    async fn test_extract_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();

        let extractor = SimpleTextExtractor::new();
        let result = extractor
            .extract(temp_file.path(), Some("text/plain"))
            .await
            .unwrap();

        assert_eq!(result, "");
    }
}
