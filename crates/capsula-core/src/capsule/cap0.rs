use serde::{Deserialize, Serialize};

use crate::block::SealedBlock;

/// 0阶数据胶囊：原始数据层
/// 
/// 0阶数据胶囊是数据胶囊体系的基础层，负责封装原始数据。
/// 它包含两个主要部分：
/// 1. origin: 原始数据的加密密文（图片、视频、音频、文档等）
/// 2. origin_text: 文字注释版本的加密密文（OCR提取、描述、摘要等）
/// 
/// 设计原则：
/// - 每个SealedBlock都是独立可验证的加密单元
/// - 原始数据和文字注释各自有独立的作者证明
/// - 支持ZKP证明的基础：文字注释提供结构化数据用于证明生成
/// - 明文永不直接暴露，只能通过密钥持有者解封
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap0 {
    /// 原始数据的加密密文
    /// 包含原始文件（如CT影像、血检报告PDF、病历记录等）的AEAD加密密文
    /// 以及对应的作者证明，确保数据来源可信且不可篡改
    pub origin: SealedBlock,

    /// 文字注释版本的加密密文（可选）
    /// 包含从原始数据中提取的结构化文字信息：
    /// - 图片：OCR提取的文字、医学影像的诊断描述
    /// - 文档：关键信息提取、标准化字段
    /// - 音频：语音识别转写文本
    /// - 视频：关键帧描述、操作记录
    /// 
    /// 这部分数据为后续ZKP证明提供基础，允许在不暴露原始数据的情况下
    /// 对特定片段或结论生成可验证证明
    pub origin_text: Option<SealedBlock>,
}

impl Cap0 {
    /// 创建新的0阶数据胶囊
    /// 
    /// # 参数
    /// - `origin`: 原始数据的封装块
    /// - `origin_text`: 可选的文字注释版本封装块
    /// 
    /// # 返回
    /// 新的Cap0实例
    pub fn new(origin: SealedBlock, origin_text: Option<SealedBlock>) -> Self {
        Self {
            origin,
            origin_text,
        }
    }

    /// 获取原始数据封装块的引用
    pub fn get_origin(&self) -> &SealedBlock {
        &self.origin
    }

    /// 获取文字注释封装块的引用（如果存在）
    pub fn get_origin_text(&self) -> Option<&SealedBlock> {
        self.origin_text.as_ref()
    }

    /// 检查是否包含文字注释版本
    pub fn has_text_version(&self) -> bool {
        self.origin_text.is_some()
    }

    /// 验证0阶胶囊的完整性
    /// 
    /// 检查：
    /// 1. 原始数据封装块的完整性
    /// 2. 文字注释封装块的完整性（如果存在）
    /// 3. 两个封装块的一致性（例如时间戳、作者等）
    pub fn verify_integrity(&self) -> crate::Result<bool> {
        // TODO: 实现完整性验证逻辑
        // 1. 验证原始数据块的签名和完整性
        // 2. 如果有文字注释，验证其签名和完整性
        // 3. 检查两个块之间的一致性（作者、时间戳等）
        // 4. 验证文字注释确实对应原始数据（通过某种绑定机制）
        
        Ok(true) // 临时返回，待实现具体验证逻辑
    }

    /// 获取0阶胶囊的摘要信息
    /// 
    /// 返回用于索引和检索的基本信息，不包含敏感数据
    pub fn get_summary(&self) -> Cap0Summary {
        Cap0Summary {
            origin_content_type: self.origin.content_type.clone(),
            origin_size: self.origin.ciphertext.len,
            has_text_version: self.has_text_version(),
            text_content_type: self.origin_text.as_ref().map(|t| t.content_type.clone()),
            text_size: self.origin_text.as_ref().map(|t| t.ciphertext.len),
            created_at: self.origin.proof.issued_at.clone(),
        }
    }
}

/// 0阶数据胶囊的摘要信息
/// 
/// 用于索引和检索，不包含敏感的密文数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap0Summary {
    /// 原始数据的内容类型
    pub origin_content_type: crate::ContentType,
    
    /// 原始数据的大小（字节）
    pub origin_size: u64,
    
    /// 是否包含文字注释版本
    pub has_text_version: bool,
    
    /// 文字注释的内容类型（如果存在）
    pub text_content_type: Option<crate::ContentType>,
    
    /// 文字注释的大小（如果存在）
    pub text_size: Option<u64>,
    
    /// 创建时间
    pub created_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block::SealedBlock,
        ContentType,
    };
    use capsula_key::{Key, RsaKey};

    #[test]
    fn test_cap0_creation() -> crate::Result<()> {
        // 创建测试用的密钥
        let signing_key = RsaKey::generate_2048()?;
        let recipient_key = RsaKey::generate_2048()?;
        let mut keyring = std::collections::HashMap::new();

        // 获取接收者公钥
        let public_keys = recipient_key.public_keys();
        let signing_key_entry = public_keys
            .signing_key()
            .ok_or_else(|| crate::error::CoreError::DataError("No signing key found".to_string()))?;
        let recipient_public_key_spki = signing_key_entry.spki_der.clone();

        // 创建原始数据封装块
        let origin_data = b"This is the original medical image data";
        let (origin_block, _) = SealedBlock::seal(
            origin_data,
            ContentType::Png, // 使用已有的图片类型
            b"medical_image_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        // 创建文字注释封装块
        let text_data = b"Patient: John Doe, Diagnosis: Normal chest X-ray, no abnormalities detected";
        let (text_block, _) = SealedBlock::seal(
            text_data,
            ContentType::Json,
            b"medical_text_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        // 创建0阶数据胶囊
        let cap0 = Cap0::new(origin_block, Some(text_block));

        // 验证基本属性
        assert_eq!(cap0.get_origin().content_type, ContentType::Png);
        assert!(cap0.has_text_version());
        assert_eq!(cap0.get_origin_text().unwrap().content_type, ContentType::Json);

        // 验证摘要信息
        let summary = cap0.get_summary();
        assert_eq!(summary.origin_content_type, ContentType::Png);
        assert_eq!(summary.origin_size, origin_data.len() as u64);
        assert!(summary.has_text_version);
        assert_eq!(summary.text_content_type, Some(ContentType::Json));
        assert_eq!(summary.text_size, Some(text_data.len() as u64));

        Ok(())
    }

    #[test]
    fn test_cap0_without_text() -> crate::Result<()> {
        // 创建测试用的密钥
        let signing_key = RsaKey::generate_2048()?;
        let recipient_key = RsaKey::generate_2048()?;
        let mut keyring = std::collections::HashMap::new();

        // 获取接收者公钥
        let public_keys = recipient_key.public_keys();
        let signing_key_entry = public_keys
            .signing_key()
            .ok_or_else(|| crate::error::CoreError::DataError("No signing key found".to_string()))?;
        let recipient_public_key_spki = signing_key_entry.spki_der.clone();

        // 创建只有原始数据的封装块
        let origin_data = b"Raw binary data without text annotation";
        let (origin_block, _) = SealedBlock::seal(
            origin_data,
            ContentType::Pdf, // 使用PDF作为二进制文档类型
            b"raw_data_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        // 创建没有文字注释的0阶数据胶囊
        let cap0 = Cap0::new(origin_block, None);

        // 验证基本属性
        assert!(!cap0.has_text_version());
        assert!(cap0.get_origin_text().is_none());

        // 验证摘要信息
        let summary = cap0.get_summary();
        assert!(!summary.has_text_version);
        assert!(summary.text_content_type.is_none());
        assert!(summary.text_size.is_none());

        Ok(())
    }

    #[test]
    fn test_cap0_serialization() -> crate::Result<()> {
        // 创建测试用的密钥
        let signing_key = RsaKey::generate_2048()?;
        let recipient_key = RsaKey::generate_2048()?;
        let mut keyring = std::collections::HashMap::new();

        // 获取接收者公钥
        let public_keys = recipient_key.public_keys();
        let signing_key_entry = public_keys
            .signing_key()
            .ok_or_else(|| crate::error::CoreError::DataError("No signing key found".to_string()))?;
        let recipient_public_key_spki = signing_key_entry.spki_der.clone();

        // 创建测试数据
        let origin_data = b"Test medical data";
        let (origin_block, _) = SealedBlock::seal(
            origin_data,
            ContentType::Text, // 使用文本类型
            b"test_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        let cap0 = Cap0::new(origin_block, None);

        // 测试序列化和反序列化
        let json = serde_json::to_string(&cap0).unwrap();
        let deserialized: Cap0 = serde_json::from_str(&json).unwrap();

        // 验证反序列化后的数据
        assert_eq!(cap0.get_origin().content_type, deserialized.get_origin().content_type);
        assert_eq!(cap0.has_text_version(), deserialized.has_text_version());

        Ok(())
    }
}