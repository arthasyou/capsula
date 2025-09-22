use serde::{Deserialize, Serialize};

use crate::block::SealedBlock;

/// 1阶数据胶囊：解释层
/// 
/// 1阶数据胶囊是在0阶数据胶囊基础上的解释层，包含：
/// 1. cap0_id: 关联的0阶数据胶囊ID
/// 2. meta: 元数据的加密密文（6元素向量：采集者、拥有者、摘要、期限等）
/// 3. summary: 数据摘要的加密密文（BNF→JSON结构化摘要）
/// 4. zkp: 零知识证明（暂时可选，未来用于证明摘要片段来自原始数据）
/// 
/// 设计原则：
/// - 不直接暴露0阶原始数据，只通过ID关联
/// - 元数据和摘要都经过加密，保护隐私
/// - 摘要提供结构化信息，便于检索和ZKP证明
/// - 支持独立验证，不依赖解密0阶数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap1 {
    /// 关联的0阶数据胶囊ID
    /// 用于定位对应的原始数据和文字注释
    pub cap0_id: String,

    /// 元数据的加密密文
    /// 包含6元素向量的部分信息：
    /// - 数据采集者信息
    /// - 数据拥有者信息  
    /// - 其他敏感元数据
    /// 注意：使用者、授权向量、期限等可能存储在外层策略中
    pub meta: SealedBlock,

    /// 数据摘要的加密密文
    /// 包含从原始数据提取的结构化摘要：
    /// - BNF解析后的JSON格式数据
    /// - 关键字段和指标
    /// - 标准化的医疗/业务术语
    /// 这部分数据为ZKP证明提供基础
    pub summary: SealedBlock,

    /// 零知识证明（可选，暂未实现）
    /// 用于证明摘要中的特定片段确实来自原始数据
    /// 例如："血糖值 > 7.0 mmol/L" 的证明
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zkp: Option<ZkpProof>,
}

/// 零知识证明结构（占位符定义）
/// 
/// 这是一个占位符结构，实际的ZKP实现需要：
/// 1. 选择合适的ZKP系统（如zk-SNARKs、zk-STARKs）
/// 2. 设计电路来证明摘要片段与原始数据的关系
/// 3. 实现证明生成和验证逻辑
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkpProof {
    /// 证明的类型（如"field_value"、"range_proof"等）
    pub proof_type: String,
    
    /// 被证明的声明（如"blood_glucose > 7.0"）
    pub claim: String,
    
    /// ZKP证明数据（具体格式取决于ZKP系统）
    pub proof_data: String,
    
    /// 验证密钥或公共参数的引用
    pub verification_key: Option<String>,
    
    /// 证明生成时间
    pub generated_at: String,
}

impl Cap1 {
    /// 创建新的1阶数据胶囊
    /// 
    /// # 参数
    /// - `cap0_id`: 关联的0阶数据胶囊ID
    /// - `meta`: 元数据的封装块
    /// - `summary`: 摘要数据的封装块
    /// - `zkp`: 可选的零知识证明
    /// 
    /// # 返回
    /// 新的Cap1实例
    pub fn new(
        cap0_id: String,
        meta: SealedBlock,
        summary: SealedBlock,
        zkp: Option<ZkpProof>,
    ) -> Self {
        Self {
            cap0_id,
            meta,
            summary,
            zkp,
        }
    }

    /// 获取关联的0阶数据胶囊ID
    pub fn get_cap0_id(&self) -> &str {
        &self.cap0_id
    }

    /// 获取元数据封装块的引用
    pub fn get_meta(&self) -> &SealedBlock {
        &self.meta
    }

    /// 获取摘要封装块的引用
    pub fn get_summary(&self) -> &SealedBlock {
        &self.summary
    }

    /// 获取ZKP证明的引用（如果存在）
    pub fn get_zkp(&self) -> Option<&ZkpProof> {
        self.zkp.as_ref()
    }

    /// 检查是否包含ZKP证明
    pub fn has_zkp_proof(&self) -> bool {
        self.zkp.is_some()
    }

    /// 验证1阶胶囊的完整性
    /// 
    /// 检查：
    /// 1. 元数据封装块的完整性
    /// 2. 摘要封装块的完整性
    /// 3. ZKP证明的有效性（如果存在）
    /// 4. cap0_id的有效性（格式检查）
    pub fn verify_integrity(&self) -> crate::Result<bool> {
        // TODO: 实现完整性验证逻辑
        // 1. 验证元数据块的签名和完整性
        // 2. 验证摘要块的签名和完整性
        // 3. 如果有ZKP证明，验证证明的有效性
        // 4. 检查cap0_id的格式和有效性
        // 5. 验证元数据和摘要的一致性（作者、时间戳等）
        
        Ok(true) // 临时返回，待实现具体验证逻辑
    }

    /// 验证与0阶胶囊的关联性
    /// 
    /// 这个方法需要访问对应的0阶胶囊来验证：
    /// 1. cap0_id确实存在且有效
    /// 2. 摘要数据与0阶胶囊的内容一致
    /// 3. 元数据中的信息与0阶胶囊匹配
    pub fn verify_cap0_association(&self, _cap0: &crate::capsule::Cap0) -> crate::Result<bool> {
        // TODO: 实现与0阶胶囊的关联验证
        // 1. 验证cap0_id匹配
        // 2. 检查时间戳的一致性
        // 3. 验证作者信息的一致性
        // 4. 可选：验证摘要确实来源于0阶胶囊的内容
        
        Ok(true) // 临时返回，待实现具体验证逻辑
    }

    /// 获取1阶胶囊的摘要信息
    /// 
    /// 返回用于索引和检索的基本信息，不包含敏感数据
    pub fn get_summary_info(&self) -> Cap1Summary {
        Cap1Summary {
            cap0_id: self.cap0_id.clone(),
            meta_content_type: self.meta.content_type.clone(),
            meta_size: self.meta.ciphertext.len,
            summary_content_type: self.summary.content_type.clone(),
            summary_size: self.summary.ciphertext.len,
            has_zkp_proof: self.has_zkp_proof(),
            zkp_claim: self.zkp.as_ref().map(|z| z.claim.clone()),
            created_at: self.meta.proof.issued_at.clone(),
        }
    }
}

/// 1阶数据胶囊的摘要信息
/// 
/// 用于索引和检索，不包含敏感的密文数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cap1Summary {
    /// 关联的0阶数据胶囊ID
    pub cap0_id: String,
    
    /// 元数据的内容类型
    pub meta_content_type: crate::ContentType,
    
    /// 元数据的大小（字节）
    pub meta_size: u64,
    
    /// 摘要数据的内容类型
    pub summary_content_type: crate::ContentType,
    
    /// 摘要数据的大小（字节）
    pub summary_size: u64,
    
    /// 是否包含ZKP证明
    pub has_zkp_proof: bool,
    
    /// ZKP证明的声明（如果存在）
    pub zkp_claim: Option<String>,
    
    /// 创建时间
    pub created_at: Option<String>,
}

impl ZkpProof {
    /// 创建新的ZKP证明
    pub fn new(
        proof_type: String,
        claim: String,
        proof_data: String,
        verification_key: Option<String>,
    ) -> Self {
        Self {
            proof_type,
            claim,
            proof_data,
            verification_key,
            generated_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        }
    }

    /// 验证ZKP证明的有效性
    pub fn verify(&self) -> crate::Result<bool> {
        // TODO: 实现ZKP验证逻辑
        // 这里需要根据具体的ZKP系统实现验证
        // 1. 解析proof_data
        // 2. 使用verification_key验证证明
        // 3. 检查claim的格式和有效性
        // 4. 验证时间戳
        
        Ok(true) // 临时返回，待实现具体验证逻辑
    }
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
    fn test_cap1_creation() -> crate::Result<()> {
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

        // 创建元数据封装块
        let meta_data = br#"{"collector": "Central Hospital", "owner": "Patient 001", "department": "Radiology"}"#;
        let (meta_block, _) = SealedBlock::seal(
            meta_data,
            ContentType::Json,
            b"meta_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        // 创建摘要封装块
        let summary_data = br#"{"exam_type": "chest_xray", "result": "normal", "findings": [], "abnormalities": false}"#;
        let (summary_block, _) = SealedBlock::seal(
            summary_data,
            ContentType::Json,
            b"summary_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        // 创建ZKP证明（示例）
        let zkp = ZkpProof::new(
            "field_value".to_string(),
            "abnormalities == false".to_string(),
            "zkp_proof_data_placeholder".to_string(),
            Some("verification_key_placeholder".to_string()),
        );

        // 创建1阶数据胶囊
        let cap1 = Cap1::new(
            "cap0_test_id_123".to_string(),
            meta_block,
            summary_block,
            Some(zkp),
        );

        // 验证基本属性
        assert_eq!(cap1.get_cap0_id(), "cap0_test_id_123");
        assert_eq!(cap1.get_meta().content_type, ContentType::Json);
        assert_eq!(cap1.get_summary().content_type, ContentType::Json);
        assert!(cap1.has_zkp_proof());
        assert_eq!(cap1.get_zkp().unwrap().claim, "abnormalities == false");

        // 验证摘要信息
        let summary = cap1.get_summary_info();
        assert_eq!(summary.cap0_id, "cap0_test_id_123");
        assert_eq!(summary.meta_content_type, ContentType::Json);
        assert_eq!(summary.summary_content_type, ContentType::Json);
        assert!(summary.has_zkp_proof);
        assert_eq!(summary.zkp_claim, Some("abnormalities == false".to_string()));

        Ok(())
    }

    #[test]
    fn test_cap1_without_zkp() -> crate::Result<()> {
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

        // 创建简单的元数据和摘要
        let meta_data = b"Basic metadata";
        let (meta_block, _) = SealedBlock::seal(
            meta_data,
            ContentType::Text,
            b"meta_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        let summary_data = b"Basic summary data";
        let (summary_block, _) = SealedBlock::seal(
            summary_data,
            ContentType::Text,
            b"summary_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        // 创建没有ZKP证明的1阶数据胶囊
        let cap1 = Cap1::new(
            "cap0_test_id_456".to_string(),
            meta_block,
            summary_block,
            None,
        );

        // 验证基本属性
        assert!(!cap1.has_zkp_proof());
        assert!(cap1.get_zkp().is_none());

        // 验证摘要信息
        let summary = cap1.get_summary_info();
        assert!(!summary.has_zkp_proof);
        assert!(summary.zkp_claim.is_none());

        Ok(())
    }

    #[test]
    fn test_zkp_proof_creation() {
        let zkp = ZkpProof::new(
            "range_proof".to_string(),
            "age >= 18".to_string(),
            "proof_data_bytes".to_string(),
            Some("vk_ref".to_string()),
        );

        assert_eq!(zkp.proof_type, "range_proof");
        assert_eq!(zkp.claim, "age >= 18");
        assert_eq!(zkp.proof_data, "proof_data_bytes");
        assert_eq!(zkp.verification_key, Some("vk_ref".to_string()));
        assert!(!zkp.generated_at.is_empty());

        // 测试验证（目前只是占位符）
        assert!(zkp.verify().unwrap());
    }

    #[test]
    fn test_cap1_serialization() -> crate::Result<()> {
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
        let meta_data = b"Test metadata";
        let (meta_block, _) = SealedBlock::seal(
            meta_data,
            ContentType::Text,
            b"meta_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        let summary_data = b"Test summary";
        let (summary_block, _) = SealedBlock::seal(
            summary_data,
            ContentType::Text,
            b"summary_aad",
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        let cap1 = Cap1::new(
            "test_cap0_id".to_string(),
            meta_block,
            summary_block,
            None,
        );

        // 测试序列化和反序列化
        let json = serde_json::to_string(&cap1).unwrap();
        let deserialized: Cap1 = serde_json::from_str(&json).unwrap();

        // 验证反序列化后的数据
        assert_eq!(cap1.get_cap0_id(), deserialized.get_cap0_id());
        assert_eq!(cap1.get_meta().content_type, deserialized.get_meta().content_type);
        assert_eq!(cap1.get_summary().content_type, deserialized.get_summary().content_type);
        assert_eq!(cap1.has_zkp_proof(), deserialized.has_zkp_proof());

        Ok(())
    }
}