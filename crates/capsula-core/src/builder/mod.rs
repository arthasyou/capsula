use crate::{
    block::{
        ciphertext::{CipherStorage, Ciphertext},
        SealedBlock,
    },
    capsule::{Cap0, Cap1, Cap2, Capsule, CapsuleHeader, CapsulePayload, PolicyControl},
    integrity::{digest::Digest, signature::Signature},
    keyring::Keyring,
    types::{CapsulaStage, ContentType, EncAlg},
    CoreError, Result,
};

/// 分层封装API - Builder模式
///
/// 实现用户需求："创建分层封装API (Builder模式)"
/// 支持0/1/2阶胶囊的渐进式构建，提供清晰的流式接口

/// 胶囊构建器 - 主要入口点
pub struct CapsuleBuilder {
    header: Option<CapsuleHeader>,
    policy: Option<PolicyControl>,
    keyring: Option<Keyring>,
}

impl CapsuleBuilder {
    /// 创建新的胶囊构建器
    pub fn new() -> Self {
        Self {
            header: None,
            policy: None,
            keyring: None,
        }
    }

    /// 设置胶囊头部信息
    pub fn header(mut self, header: CapsuleHeader) -> Self {
        self.header = Some(header);
        self
    }

    /// 使用ID和内容类型创建头部
    pub fn with_header(mut self, id: String, content_type: String, stage: CapsulaStage) -> Self {
        self.header = Some(CapsuleHeader {
            id,
            version: "1.0".to_string(),
            stage,
            content_type,
            created_at: chrono::Utc::now().to_rfc3339(),
            creator: None,
            metadata: None,
        });
        self
    }

    /// 设置策略控制
    pub fn policy(mut self, policy: PolicyControl) -> Self {
        self.policy = Some(policy);
        self
    }

    /// 使用URI和权限创建策略
    pub fn with_policy(mut self, policy_uri: String, permissions: Vec<String>) -> Self {
        self.policy = Some(PolicyControl::new(policy_uri, permissions));
        self
    }

    /// 设置密钥环
    pub fn keyring(mut self, keyring: Keyring) -> Self {
        self.keyring = Some(keyring);
        self
    }

    /// 创建空密钥环
    pub fn with_empty_keyring(mut self) -> Self {
        self.keyring = Some(Keyring::new());
        self
    }

    /// 构建0阶胶囊
    pub fn build_cap0(self) -> Cap0Builder {
        Cap0Builder {
            base: self,
            origin: None,
            origin_text: None,
        }
    }

    /// 构建1阶胶囊
    pub fn build_cap1(self) -> Cap1Builder {
        Cap1Builder {
            base: self,
            cap0_id: None,
            meta: None,
            bnf_extract: None,
            zkp: None,
        }
    }

    /// 构建2阶胶囊
    pub fn build_cap2(self) -> Cap2Builder {
        Cap2Builder {
            base: self,
            owner_id: None,
            refs: Vec::new(),
        }
    }

    /// 验证必需字段
    fn validate(&self) -> Result<()> {
        if self.header.is_none() {
            return Err(CoreError::DataError("Header is required".to_string()));
        }
        if self.policy.is_none() {
            return Err(CoreError::DataError("Policy is required".to_string()));
        }
        if self.keyring.is_none() {
            return Err(CoreError::DataError("Keyring is required".to_string()));
        }
        Ok(())
    }

    /// 获取已验证的组件
    fn get_components(self) -> Result<(CapsuleHeader, PolicyControl, Keyring)> {
        self.validate()?;
        Ok((
            self.header.unwrap(),
            self.policy.unwrap(),
            self.keyring.unwrap(),
        ))
    }
}

impl Default for CapsuleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 0阶胶囊构建器
pub struct Cap0Builder {
    base: CapsuleBuilder,
    origin: Option<SealedBlock>,
    origin_text: Option<SealedBlock>,
}

impl Cap0Builder {
    /// 设置原始数据
    pub fn origin(mut self, origin: SealedBlock) -> Self {
        self.origin = Some(origin);
        self
    }

    /// 使用原始数据创建SealedBlock
    pub fn with_origin_data(mut self, data: Vec<u8>, content_type: ContentType) -> Result<Self> {
        let sealed_block = SealedBlockBuilder::new()
            .with_inline_data(data, EncAlg::Aes256Gcm)
            .content_type(content_type)
            .author("system")
            .build()?;

        self.origin = Some(sealed_block);
        Ok(self)
    }

    /// 设置文本注释
    pub fn origin_text(mut self, origin_text: SealedBlock) -> Self {
        self.origin_text = Some(origin_text);
        self
    }

    /// 使用文本数据创建文本注释
    pub fn with_text_annotation(mut self, text: String) -> Result<Self> {
        let sealed_block = SealedBlockBuilder::new()
            .with_inline_data(text.into_bytes(), EncAlg::Aes256Gcm)
            .content_type(ContentType::Text)
            .author("system")
            .build()?;

        self.origin_text = Some(sealed_block);
        Ok(self)
    }

    /// 构建最终的胶囊
    pub fn build(self) -> Result<Capsule> {
        if self.origin.is_none() {
            return Err(CoreError::DataError(
                "Origin data is required for Cap0".to_string(),
            ));
        }

        let (header, policy, keyring) = self.base.get_components()?;

        let cap0 = Cap0 {
            origin: self.origin.unwrap(),
            origin_text: self.origin_text,
        };

        let payload = CapsulePayload::Cap0(cap0);
        Capsule::new(header, policy, keyring, payload)
    }
}

/// 1阶胶囊构建器
pub struct Cap1Builder {
    base: CapsuleBuilder,
    cap0_id: Option<String>,
    meta: Option<SealedBlock>,
    bnf_extract: Option<SealedBlock>,
    zkp: Option<crate::capsule::ZkpProof>,
}

impl Cap1Builder {
    /// 设置关联的Cap0 ID
    pub fn cap0_id(mut self, cap0_id: String) -> Self {
        self.cap0_id = Some(cap0_id);
        self
    }

    /// 设置元数据
    pub fn meta(mut self, meta: SealedBlock) -> Self {
        self.meta = Some(meta);
        self
    }

    /// 使用元数据创建SealedBlock
    pub fn with_meta_data(mut self, meta_data: Vec<u8>) -> Result<Self> {
        let sealed_block = SealedBlockBuilder::new()
            .with_inline_data(meta_data, EncAlg::Aes256Gcm)
            .content_type(ContentType::Json)
            .author("system")
            .build()?;

        self.meta = Some(sealed_block);
        Ok(self)
    }

    /// 设置BNF解析提取的结构化内容
    pub fn bnf_extract(mut self, bnf_extract: SealedBlock) -> Self {
        self.bnf_extract = Some(bnf_extract);
        self
    }

    /// 使用JSON数据创建BNF解析提取的结构化内容
    pub fn with_bnf_extract_json(mut self, bnf_extract_json: serde_json::Value) -> Result<Self> {
        let bnf_extract_data = serde_json::to_vec(&bnf_extract_json)
            .map_err(|e| CoreError::DataError(format!("Failed to serialize BNF extract: {}", e)))?;

        let sealed_block = SealedBlockBuilder::new()
            .with_inline_data(bnf_extract_data, EncAlg::Aes256Gcm)
            .content_type(ContentType::Json)
            .author("system")
            .build()?;

        self.bnf_extract = Some(sealed_block);
        Ok(self)
    }

    /// 设置ZKP证明（暂时跳过实现）
    pub fn zkp(mut self, zkp: crate::capsule::ZkpProof) -> Self {
        self.zkp = Some(zkp);
        self
    }

    /// 构建最终的胶囊
    pub fn build(self) -> Result<Capsule> {
        if self.cap0_id.is_none() {
            return Err(CoreError::DataError(
                "Cap0 ID is required for Cap1".to_string(),
            ));
        }
        if self.meta.is_none() {
            return Err(CoreError::DataError(
                "Meta data is required for Cap1".to_string(),
            ));
        }
        if self.bnf_extract.is_none() {
            return Err(CoreError::DataError(
                "BNF extract is required for Cap1".to_string(),
            ));
        }

        let (header, policy, keyring) = self.base.get_components()?;

        let cap1 = Cap1 {
            cap0_id: self.cap0_id.unwrap(),
            meta: self.meta.unwrap(),
            bnf_extract: self.bnf_extract.unwrap(),
            zkp: self.zkp,
        };

        let payload = CapsulePayload::Cap1(cap1);
        Capsule::new(header, policy, keyring, payload)
    }
}

/// 2阶胶囊构建器
pub struct Cap2Builder {
    base: CapsuleBuilder,
    owner_id: Option<String>,
    refs: Vec<crate::capsule::RefEntry>,
}

impl Cap2Builder {
    /// 设置所有者ID
    pub fn owner_id(mut self, owner_id: String) -> Self {
        self.owner_id = Some(owner_id);
        self
    }

    /// 添加引用条目
    pub fn add_ref(mut self, ref_entry: crate::capsule::RefEntry) -> Self {
        self.refs.push(ref_entry);
        self
    }

    /// 添加多个引用条目
    pub fn add_refs(mut self, mut refs: Vec<crate::capsule::RefEntry>) -> Self {
        self.refs.append(&mut refs);
        self
    }

    /// 使用简单参数添加引用
    pub fn add_simple_ref(mut self, report_type: String, ids: Vec<String>) -> Self {
        let count = ids.len() as u32;
        let ref_entry = crate::capsule::RefEntry {
            report_type,
            ids,
            metadata: Some(crate::capsule::RefMetadata {
                count,
                earliest_date: None,
                latest_date: None,
                description: None,
                tags: vec![],
            }),
        };
        self.refs.push(ref_entry);
        self
    }

    /// 构建最终的胶囊
    pub fn build(self) -> Result<Capsule> {
        if self.owner_id.is_none() {
            return Err(CoreError::DataError(
                "Owner ID is required for Cap2".to_string(),
            ));
        }
        if self.refs.is_empty() {
            return Err(CoreError::DataError(
                "At least one reference is required for Cap2".to_string(),
            ));
        }

        let (header, policy, keyring) = self.base.get_components()?;

        // 计算捆绑哈希 (简化实现)
        let bundle_hash = Digest {
            alg: "SHA-256".to_string(),
            hash: "placeholder_bundle_hash".to_string(),
        };

        // 创建捆绑签名 (简化实现)
        let bundle_signature = crate::integrity::signature::Signature {
            alg: "Ed25519".to_string(),
            sig: "placeholder_bundle_signature".to_string(),
            author_hint: self.owner_id.clone().unwrap(),
            cert_hint: None,
        };

        let cap2 = Cap2 {
            owner_id: self.owner_id.unwrap(),
            refs: self.refs,
            bundle_hash,
            bundle_signature,
        };

        let payload = CapsulePayload::Cap2(cap2);
        Capsule::new(header, policy, keyring, payload)
    }
}

/// SealedBlock构建器 - 用于构建加密块
pub struct SealedBlockBuilder {
    data: Option<Vec<u8>>,
    content_type: Option<ContentType>,
    author_hint: Option<String>,
    algorithm: EncAlg,
}

impl SealedBlockBuilder {
    pub fn new() -> Self {
        Self {
            data: None,
            content_type: None,
            author_hint: None,
            algorithm: EncAlg::Aes256Gcm,
        }
    }

    /// 使用内联数据
    pub fn with_inline_data(mut self, data: Vec<u8>, algorithm: EncAlg) -> Self {
        self.data = Some(data);
        self.algorithm = algorithm;
        self
    }

    /// 设置内容类型
    pub fn content_type(mut self, content_type: ContentType) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// 设置作者
    pub fn author(mut self, author_hint: &str) -> Self {
        self.author_hint = Some(author_hint.to_string());
        self
    }

    /// 构建SealedBlock
    pub fn build(self) -> Result<SealedBlock> {
        if self.data.is_none() {
            return Err(CoreError::DataError("Data is required".to_string()));
        }
        if self.content_type.is_none() {
            return Err(CoreError::DataError("Content type is required".to_string()));
        }
        if self.author_hint.is_none() {
            return Err(CoreError::DataError("Author is required".to_string()));
        }

        let data = self.data.unwrap();
        let data_len = data.len() as u64;

        // 创建简化的密文 (实际应该进行真正的加密)
        let ct_b64 = capsula_crypto::base64::encode(&data);
        let ciphertext = Ciphertext {
            aad: "placeholder_aad".to_string(),
            enc: self.algorithm,
            nonce: "placeholder_nonce".to_string(),
            len: data_len,
            dek_id: "placeholder_dek_id".to_string(),
            storage: CipherStorage::Inline {
                ct_b64,
                ciphertext_len: Some(data_len),
                ciphertext_digest: None,
            },
        };

        // 创建主题摘要
        let subject = Digest {
            alg: "SHA-256".to_string(),
            hash: "placeholder_subject_hash".to_string(),
        };

        // 创建作者证明 (简化实现)
        let proof = crate::block::proof::AuthorProof {
            subject,
            schema_hash: None,
            issued_at: Some(chrono::Utc::now().to_rfc3339()),
            signature: Signature {
                alg: "Ed25519".to_string(),
                sig: "placeholder_signature".to_string(),
                author_hint: self.author_hint.unwrap(),
                cert_hint: None,
            },
        };

        Ok(SealedBlock {
            ciphertext,
            proof,
            content_type: self.content_type.unwrap(),
        })
    }
}

impl Default for SealedBlockBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 快速构建辅助函数
pub mod quick {
    use super::*;

    /// 快速创建0阶胶囊
    pub fn create_cap0(
        id: String,
        content_type: String,
        data: Vec<u8>,
        policy_uri: String,
        permissions: Vec<String>,
    ) -> Result<Capsule> {
        CapsuleBuilder::new()
            .with_header(id, content_type.clone(), CapsulaStage::First)
            .with_policy(policy_uri, permissions)
            .with_empty_keyring()
            .build_cap0()
            .with_origin_data(data, ContentType::Json)?
            .build()
    }

    /// 快速创建1阶胶囊
    pub fn create_cap1(
        id: String,
        content_type: String,
        cap0_id: String,
        meta_data: Vec<u8>,
        bnf_extract_json: serde_json::Value,
        policy_uri: String,
        permissions: Vec<String>,
    ) -> Result<Capsule> {
        CapsuleBuilder::new()
            .with_header(id, content_type, CapsulaStage::Second)
            .with_policy(policy_uri, permissions)
            .with_empty_keyring()
            .build_cap1()
            .cap0_id(cap0_id)
            .with_meta_data(meta_data)?
            .with_bnf_extract_json(bnf_extract_json)?
            .build()
    }

    /// 快速创建2阶胶囊
    pub fn create_cap2(
        id: String,
        content_type: String,
        owner_id: String,
        refs: Vec<crate::capsule::RefEntry>,
        policy_uri: String,
        permissions: Vec<String>,
    ) -> Result<Capsule> {
        CapsuleBuilder::new()
            .with_header(id, content_type, CapsulaStage::Third)
            .with_policy(policy_uri, permissions)
            .with_empty_keyring()
            .build_cap2()
            .owner_id(owner_id)
            .add_refs(refs)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ContentType;

    #[test]
    fn test_cap0_builder() {
        let result = CapsuleBuilder::new()
            .with_header(
                "test-id".to_string(),
                "test-type".to_string(),
                CapsulaStage::First,
            )
            .with_policy("policy://test".to_string(), vec!["read".to_string()])
            .with_empty_keyring()
            .build_cap0()
            .with_origin_data(vec![1, 2, 3, 4], ContentType::Json);

        assert!(result.is_ok());

        let cap0_builder = result.unwrap();
        let capsule = cap0_builder.build();
        assert!(capsule.is_ok());
    }

    #[test]
    fn test_cap1_builder() {
        let bnf_extract_json = serde_json::json!({
            "type": "test_bnf_extract",
            "count": 1
        });

        let result = CapsuleBuilder::new()
            .with_header(
                "test-id-1".to_string(),
                "test-type".to_string(),
                CapsulaStage::Second,
            )
            .with_policy("policy://test".to_string(), vec!["read".to_string()])
            .with_empty_keyring()
            .build_cap1()
            .cap0_id("cap0-id".to_string())
            .with_meta_data(vec![5, 6, 7, 8]);

        assert!(result.is_ok());

        let cap1_builder = result.unwrap().with_bnf_extract_json(bnf_extract_json);
        assert!(cap1_builder.is_ok());

        let capsule = cap1_builder.unwrap().build();
        assert!(capsule.is_ok());
    }

    #[test]
    fn test_cap2_builder() {
        let capsule = CapsuleBuilder::new()
            .with_header(
                "test-id-2".to_string(),
                "test-type".to_string(),
                CapsulaStage::Third,
            )
            .with_policy("policy://test".to_string(), vec!["read".to_string()])
            .with_empty_keyring()
            .build_cap2()
            .owner_id("owner-123".to_string())
            .add_simple_ref(
                "血常规报告".to_string(),
                vec!["cap1-id-1".to_string(), "cap1-id-2".to_string()],
            )
            .build();

        assert!(capsule.is_ok());
    }

    #[test]
    fn test_quick_create_cap0() {
        let capsule = quick::create_cap0(
            "quick-cap0".to_string(),
            "application/json".to_string(),
            vec![1, 2, 3, 4],
            "policy://quick".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        assert!(capsule.is_ok());
        let capsule = capsule.unwrap();
        assert_eq!(capsule.header.id, "quick-cap0");
        assert_eq!(capsule.header.stage, CapsulaStage::First);
    }

    #[test]
    fn test_builder_validation() {
        // Test missing header
        let result = CapsuleBuilder::new()
            .with_policy("policy://test".to_string(), vec!["read".to_string()])
            .with_empty_keyring()
            .build_cap0()
            .build();

        assert!(result.is_err());

        // Test missing policy
        let result = CapsuleBuilder::new()
            .with_header(
                "test-id".to_string(),
                "test-type".to_string(),
                CapsulaStage::First,
            )
            .with_empty_keyring()
            .build_cap0()
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_sealed_block_builder() {
        let sealed_block = SealedBlockBuilder::new()
            .with_inline_data(vec![1, 2, 3, 4], EncAlg::Aes256Gcm)
            .content_type(ContentType::Json)
            .author("test-author")
            .build();

        assert!(sealed_block.is_ok());
    }
}
