use std::collections::HashMap;

use capsula_key::key::{Key, KeyEncDec};
use serde::{Deserialize, Serialize};

use crate::{
    aad::{AadBinder, AadBinding},
    integrity::{digest::Digest, signature::Signature, Integrity},
    keyring::Keyring,
    types::CapsulaStage,
    CoreError, Result,
};

pub mod cap0;
pub mod cap1;
pub mod cap2;
pub mod header;
pub mod meta;

// Re-export commonly used types
pub use cap0::{Cap0, Cap0ExternalSeal};
pub use cap1::{Cap1, Cap1Summary, ZkpProof};
pub use cap2::{Cap2, RefEntry, RefMetadata};

/// 统一数据胶囊外壳 (原 Capsule 从 unified.rs)
///
/// 这是一个通用容器，可以封装任何类型的数据胶囊（Cap0/1/2）。
/// 外壳负责提供统一的：
/// 1. 头部信息（版本、类型、时间戳等）
/// 2. AAD绑定（防篡改的额外认证数据）
/// 3. 访问控制策略（指针引用模式）
/// 4. 密钥环管理（对称密钥的安全分发）
/// 5. 载荷容器（Cap0/1/2的具体内容）
/// 6. 完整性保证（整体签名和验证）
///
/// 设计原则：
/// - 统一外壳：一个结构支持所有类型的胶囊
/// - 安全绑定：通过AAD将外壳与内容牢固绑定
/// - 指针引用：策略和审计采用指针模式，减少冗余
/// - 可扩展性：预留字段支持未来功能扩展
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsule {
    /// 胶囊头部信息
    pub header: CapsuleHeader,

    /// AAD绑定机制（Additional Authenticated Data）
    /// 用于防止组件替换攻击，确保外壳和内容的强绑定关系
    /// 包含所有组件的摘要和绑定验证信息
    pub aad_binding: AadBinding,

    /// 访问控制策略（指针引用模式）
    /// 只存储指向外部策略系统的引用，具体权限逻辑在数据库中
    pub policy: PolicyControl,

    /// 密钥环：对称密钥的加密包装
    /// 支持多接收者，每个接收者用自己的公钥解封对应的DEK
    pub keyring: Keyring,

    /// 载荷：具体的胶囊内容
    /// 可以是0/1/2阶胶囊中的任意一种
    pub payload: CapsulePayload,

    /// 完整性保证
    /// 对整个胶囊的签名和摘要，确保不可篡改
    pub integrity: CapsuleIntegrity,

    /// 审计记录引用（可选）
    /// 指向外部审计系统的记录，支持操作追溯
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
}

/// 胶囊头部信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleHeader {
    /// 胶囊唯一标识符
    /// 格式：cid:<base32编码>
    pub id: String,

    /// 胶囊版本
    pub version: String,

    /// 胶囊阶段（对应Cap0/1/2）
    pub stage: CapsulaStage,

    /// 内容类型标识
    /// 例如："medical.blood_test", "legal.contract", "financial.report"
    pub content_type: String,

    /// 创建时间戳（RFC3339格式）
    pub created_at: String,

    /// 创建者信息（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,

    /// 自定义元数据（可选）
    /// 用于索引和检索的额外信息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

/// 访问控制策略（指针引用模式）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyControl {
    /// 策略URI（指向外部策略系统）
    pub policy_uri: String,

    /// 策略权限列表
    pub permissions: Vec<String>,

    /// 策略约束条件
    pub constraints: HashMap<String, String>,
}

/// 胶囊载荷：支持不同阶段的胶囊内容
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum CapsulePayload {
    /// 0阶数据胶囊：原始数据层
    Cap0(Cap0),

    /// 1阶数据胶囊：解释层
    Cap1(Cap1),

    /// 2阶数据胶囊：聚合层
    Cap2(Cap2),
}

/// 胶囊解封后的内容
#[derive(Debug, Clone)]
pub enum CapsuleContent {
    /// Cap1解封内容
    Cap1Content {
        cap0_id: String,
        meta_data: Vec<u8>,
        bnf_extract_data: Vec<u8>,
    },
    /// Cap2内容（明文引用信息）
    Cap2Content {
        owner_id: String,
        refs: Vec<RefEntry>,
    },
}

/// 胶囊完整性保证
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleIntegrity {
    /// 整体签名
    /// 对胶囊规范化摘要的签名，确保整体不可篡改
    pub signature: Signature,

    /// 胶囊摘要
    /// 可以是简单哈希或Merkle根（用于复杂结构）
    pub digest: Digest,

    /// 数字水印（可选）
    /// 用于版权保护或来源追踪
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watermark: Option<Watermark>,
}

/// 数字水印结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watermark {
    /// 水印类型
    pub watermark_type: String,

    /// 水印数据
    pub data: String,

    /// 水印算法
    pub algorithm: String,

    /// 嵌入时间
    pub embedded_at: String,
}

impl Capsule {
    /// 创建新的胶囊
    pub fn new(
        header: CapsuleHeader,
        policy: PolicyControl,
        keyring: Keyring,
        payload: CapsulePayload,
    ) -> Result<Self> {
        // 创建AAD绑定器
        let aad_binder = AadBinder::new();

        // 序列化密钥环用于AAD计算
        let keyring_data = serde_json::to_vec(&keyring)
            .map_err(|e| CoreError::DataError(format!("Failed to serialize keyring: {}", e)))?;

        // 创建AAD绑定
        let aad_binding =
            aad_binder.create_binding(&header, &policy, &payload, Some(&keyring_data))?;

        // 计算完整性摘要（暂时用占位符）
        let digest = Digest {
            alg: "SHA-256".to_string(),
            hash: "placeholder_hash".to_string(),
        };

        // 创建占位符签名（实际使用时需要真实签名）
        let signature = Signature {
            alg: "Ed25519".to_string(),
            sig: "placeholder_signature".to_string(),
            author_hint: "placeholder_author".to_string(),
            cert_hint: None,
        };

        let integrity = CapsuleIntegrity {
            signature,
            digest,
            watermark: None,
        };

        Ok(Self {
            header,
            aad_binding,
            policy,
            keyring,
            payload,
            integrity,
            audit_ref: None,
        })
    }

    /// 快速创建Cap0胶囊
    ///
    /// 简化的构造流程，自动生成头部信息和AAD绑定
    ///
    /// # 参数
    /// - `id`: 胶囊唯一标识符
    /// - `content_type`: 内容类型标识
    /// - `policy_uri`: 策略URI
    /// - `permissions`: 权限列表
    /// - `keyring`: 密钥环
    /// - `cap0`: 已封装的0阶数据胶囊
    /// - `creator`: 可选的创建者信息
    pub fn with_cap0(
        id: String,
        content_type: String,
        policy_uri: String,
        permissions: Vec<String>,
        keyring: Keyring,
        cap0: Cap0,
        creator: Option<String>,
    ) -> Result<Self> {
        let header = CapsuleHeader::new(
            id,
            "1.0".to_string(),
            CapsulaStage::First,
            content_type,
            creator,
        );

        let policy = PolicyControl::new(policy_uri, permissions);
        let payload = CapsulePayload::Cap0(cap0);

        Self::new(header, policy, keyring, payload)
    }

    /// 快速创建Cap1胶囊
    ///
    /// # 参数
    /// - `id`: 胶囊唯一标识符
    /// - `content_type`: 内容类型标识
    /// - `policy_uri`: 策略URI
    /// - `permissions`: 权限列表
    /// - `keyring`: 密钥环
    /// - `cap1`: 已封装的1阶数据胶囊
    /// - `creator`: 可选的创建者信息
    pub fn with_cap1(
        id: String,
        content_type: String,
        policy_uri: String,
        permissions: Vec<String>,
        keyring: Keyring,
        cap1: Cap1,
        creator: Option<String>,
    ) -> Result<Self> {
        let header = CapsuleHeader::new(
            id,
            "1.0".to_string(),
            CapsulaStage::Second,
            content_type,
            creator,
        );

        let policy = PolicyControl::new(policy_uri, permissions);
        let payload = CapsulePayload::Cap1(cap1);

        Self::new(header, policy, keyring, payload)
    }

    /// 快速创建Cap2胶囊
    ///
    /// # 参数
    /// - `id`: 胶囊唯一标识符
    /// - `content_type`: 内容类型标识
    /// - `policy_uri`: 策略URI
    /// - `permissions`: 权限列表
    /// - `keyring`: 密钥环
    /// - `cap2`: 已封装的2阶数据胶囊
    /// - `creator`: 可选的创建者信息
    pub fn with_cap2(
        id: String,
        content_type: String,
        policy_uri: String,
        permissions: Vec<String>,
        keyring: Keyring,
        cap2: Cap2,
        creator: Option<String>,
    ) -> Result<Self> {
        let header = CapsuleHeader::new(
            id,
            "1.0".to_string(),
            CapsulaStage::Third,
            content_type,
            creator,
        );

        let policy = PolicyControl::new(policy_uri, permissions);
        let payload = CapsulePayload::Cap2(cap2);

        Self::new(header, policy, keyring, payload)
    }

    /// 验证AAD绑定的完整性
    ///
    /// 确保胶囊的各个组件未被篡改或替换
    pub fn verify_aad_binding(&self) -> Result<bool> {
        let aad_binder = AadBinder::new();

        // 序列化密钥环用于AAD验证
        let keyring_data = serde_json::to_vec(&self.keyring)
            .map_err(|e| CoreError::DataError(format!("Failed to serialize keyring: {}", e)))?;

        aad_binder.verify_binding(
            &self.aad_binding,
            &self.header,
            &self.policy,
            &self.payload,
            Some(&keyring_data),
        )
    }

    /// 更新胶囊组件并重新绑定AAD
    ///
    /// 当需要修改胶囊组件时，必须重新计算AAD绑定
    pub fn update_with_aad_rebinding(
        &mut self,
        new_header: Option<CapsuleHeader>,
        new_policy: Option<PolicyControl>,
        new_keyring: Option<Keyring>,
        new_payload: Option<CapsulePayload>,
    ) -> Result<()> {
        let aad_binder = AadBinder::new();

        // 更新组件
        if let Some(header) = new_header {
            self.header = header;
        }
        if let Some(policy) = new_policy {
            self.policy = policy;
        }
        if let Some(keyring) = new_keyring {
            self.keyring = keyring;
        }
        if let Some(payload) = new_payload {
            self.payload = payload;
        }

        // 重新计算AAD绑定
        let keyring_data = serde_json::to_vec(&self.keyring)
            .map_err(|e| CoreError::DataError(format!("Failed to serialize keyring: {}", e)))?;

        self.aad_binding = aad_binder.update_binding(
            self.aad_binding.clone(),
            &self.header,
            &self.policy,
            &self.payload,
            Some(&keyring_data),
        )?;

        Ok(())
    }

    /// 获取用于AEAD加密的AAD数据
    pub fn get_aead_aad(&self) -> Vec<u8> {
        let aad_binder = AadBinder::new();
        aad_binder.get_aead_aad(&self.aad_binding)
    }

    /// 计算胶囊的完整性摘要
    pub fn compute_digest(&self) -> crate::Result<Digest> {
        use sha2::{Digest as Sha2Digest, Sha256};

        // 序列化整个胶囊（除了integrity字段）
        let capsule_for_hash = CapsuleForHashing {
            header: &self.header,
            aad_binding: &self.aad_binding,
            policy: &self.policy,
            keyring: &self.keyring,
            payload: &self.payload,
            audit_ref: &self.audit_ref,
        };

        let serialized = serde_json::to_string(&capsule_for_hash)
            .map_err(|e| crate::error::CoreError::JsonError(e))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let hash_bytes = hasher.finalize();
        let hash = capsula_crypto::base64::encode(hash_bytes);

        Ok(Digest {
            alg: "SHA-256".to_string(),
            hash,
        })
    }

    /// 验证胶囊的完整性
    pub fn verify_integrity(&self) -> crate::Result<bool> {
        // 1. 验证AAD
        if !self.verify_aad_binding()? {
            return Ok(false);
        }

        // 2. 验证摘要
        let computed_digest = self.compute_digest()?;
        if computed_digest.hash != self.integrity.digest.hash {
            return Ok(false);
        }

        // 3. TODO: 验证签名（需要公钥）
        // 这里需要根据signature.author_hint获取公钥来验证签名

        Ok(true)
    }

    /// 获取载荷类型
    pub fn get_payload_type(&self) -> &str {
        match &self.payload {
            CapsulePayload::Cap0(_) => "Cap0",
            CapsulePayload::Cap1(_) => "Cap1",
            CapsulePayload::Cap2(_) => "Cap2",
        }
    }

    /// 解封胶囊载荷
    ///
    /// 根据载荷类型提供统一的解封接口
    /// 注意：对于Cap0，需要单独处理外部存储的解封
    pub fn unseal_payload<T>(&self, keyring: &Keyring, decryption_key: &T) -> Result<CapsuleContent>
    where
        T: Key + KeyEncDec,
    {
        match &self.payload {
            CapsulePayload::Cap0(_cap0) => {
                // Cap0使用外部存储，需要单独处理文件下载和解封
                Err(CoreError::DataError(
                    "Cap0 uses external storage. Use cap0.unseal() with file paths instead."
                        .to_string(),
                ))
            }
            CapsulePayload::Cap1(cap1) => {
                let (meta_data, bnf_data) = cap1.unseal(keyring, decryption_key)?;
                Ok(CapsuleContent::Cap1Content {
                    cap0_id: cap1.cap0_id.clone(),
                    meta_data,
                    bnf_extract_data: bnf_data,
                })
            }
            CapsulePayload::Cap2(_cap2) => {
                // Cap2使用明文存储，直接返回引用信息
                Ok(CapsuleContent::Cap2Content {
                    owner_id: _cap2.owner_id.clone(),
                    refs: _cap2.refs.clone(),
                })
            }
        }
    }

    /// 获取载荷中的Cap0引用（如果是Cap0类型）
    pub fn as_cap0(&self) -> Option<&Cap0> {
        match &self.payload {
            CapsulePayload::Cap0(cap0) => Some(cap0),
            _ => None,
        }
    }

    /// 获取载荷中的Cap1引用（如果是Cap1类型）
    pub fn as_cap1(&self) -> Option<&Cap1> {
        match &self.payload {
            CapsulePayload::Cap1(cap1) => Some(cap1),
            _ => None,
        }
    }

    /// 获取载荷中的Cap2引用（如果是Cap2类型）
    pub fn as_cap2(&self) -> Option<&Cap2> {
        match &self.payload {
            CapsulePayload::Cap2(cap2) => Some(cap2),
            _ => None,
        }
    }

    /// 设置审计引用
    pub fn set_audit_ref(&mut self, audit_ref: String) {
        self.audit_ref = Some(audit_ref);
    }

    /// 添加水印
    pub fn add_watermark(&mut self, watermark: Watermark) {
        self.integrity.watermark = Some(watermark);
    }

    /// 获取胶囊摘要信息
    pub fn get_summary(&self) -> CapsuleSummary {
        CapsuleSummary {
            id: self.header.id.clone(),
            version: self.header.version.clone(),
            stage: self.header.stage.clone(),
            content_type: self.header.content_type.clone(),
            created_at: self.header.created_at.clone(),
            creator: self.header.creator.clone(),
            payload_type: self.get_payload_type().to_string(),
            policy_ref: self.policy.policy_uri.clone(),
            policy_type: "general".to_string(), // Default type since we simplified the structure
            has_watermark: self.integrity.watermark.is_some(),
            has_audit_ref: self.audit_ref.is_some(),
        }
    }
}

/// 用于计算哈希的临时结构（排除integrity字段）
#[derive(Serialize)]
struct CapsuleForHashing<'a> {
    header: &'a CapsuleHeader,
    aad_binding: &'a AadBinding,
    policy: &'a PolicyControl,
    keyring: &'a Keyring,
    payload: &'a CapsulePayload,
    audit_ref: &'a Option<String>,
}

/// 胶囊摘要信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleSummary {
    pub id: String,
    pub version: String,
    pub stage: CapsulaStage,
    pub content_type: String,
    pub created_at: String,
    pub creator: Option<String>,
    pub payload_type: String,
    pub policy_ref: String,
    pub policy_type: String,
    pub has_watermark: bool,
    pub has_audit_ref: bool,
}

impl CapsuleHeader {
    /// 创建新的胶囊头部
    pub fn new(
        id: String,
        version: String,
        stage: CapsulaStage,
        content_type: String,
        creator: Option<String>,
    ) -> Self {
        Self {
            id,
            version,
            stage,
            content_type,
            created_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            creator,
            metadata: None,
        }
    }

    /// 添加元数据
    pub fn add_metadata(&mut self, key: String, value: String) {
        if self.metadata.is_none() {
            self.metadata = Some(HashMap::new());
        }
        self.metadata.as_mut().unwrap().insert(key, value);
    }
}

impl PolicyControl {
    /// 创建新的策略控制
    pub fn new(policy_uri: String, permissions: Vec<String>) -> Self {
        Self {
            policy_uri,
            permissions,
            constraints: HashMap::new(),
        }
    }

    /// 添加策略约束
    pub fn add_constraint(&mut self, key: String, value: String) {
        self.constraints.insert(key, value);
    }

    /// 添加权限
    pub fn add_permission(&mut self, permission: String) {
        if !self.permissions.contains(&permission) {
            self.permissions.push(permission);
        }
    }
}

impl Watermark {
    /// 创建新的水印
    pub fn new(watermark_type: String, data: String, algorithm: String) -> Self {
        Self {
            watermark_type,
            data,
            algorithm,
            embedded_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        }
    }
}

/// 原有的简化胶囊结构（保留兼容性）
/// 注意：这个结构现在已被上面的 Capsule 替代
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsula {
    pub header: header::Header, // ← 胶囊头（版本、类型、时间戳等）
    pub meta: meta::Meta,       // ← 元数据（0阶数据的摘要等）

    pub policy: String,       // 指向数据库或 IPFS 的访问策略
    pub integrity: Integrity, // ← 对整个胶囊的签名

    #[serde(default)]
    pub keyring: Keyring, // 传输时的密钥包装
}

/// 使用示例和 API 指南
///
/// # 两步封装设计
///
/// ## 步骤1：创建具体的胶囊 (Cap0/1/2)
/// ```text
/// use std::path::Path;
///
/// use capsula_core::*;
///
/// // Cap0 - 外部存储，两步封装
/// let external_seal = Cap0::seal(
///     Path::new("origin.pdf"),
///     Path::new("origin.enc"),
///     Path::new("text.txt"),
///     Path::new("text.enc"),
///     (ContentType::Pdf, ContentType::Text),
///     b"additional_auth_data",
///     &mut keyring,
///     &spki_der,
///     &signing_key,
/// )?;
///
/// // 用户上传文件后设置URI
/// external_seal.set_origin_uri("s3://bucket/origin.enc".to_string())?;
/// external_seal.set_origin_text_uri("s3://bucket/text.enc".to_string())?;
/// let cap0 = external_seal.into_cap0()?;
///
/// // Cap1 - 内联存储，一步封装
/// let cap1 = Cap1::seal(
///     "cap0_id_123".to_string(),
///     &meta_data,
///     &bnf_data,
///     (ContentType::Json, ContentType::Json),
///     b"additional_auth_data",
///     &mut keyring,
///     &spki_der,
///     &signing_key,
///     None, // 可选的ZKP证明
/// )?;
///
/// // Cap2 - 明文引用，自动hash和签名
/// let cap2 = Cap2::seal("owner_123".to_string(), refs, &signing_key)?;
/// ```
///
/// ## 步骤2：包装成统一胶囊 (Capsule)
/// ```text
/// // 使用便利方法
/// let capsule = Capsule::with_cap0(
///     "capsule_id_123".to_string(),
///     "medical.blood_test".to_string(),
///     "policy://medical".to_string(),
///     vec!["read".to_string(), "decrypt".to_string()],
///     keyring,
///     cap0,
///     Some("医院A".to_string()),
/// )?;
///
/// // 或使用完整方法
/// let header = CapsuleHeader::new(
///     "capsule_id_456".to_string(),
///     "1.0".to_string(),
///     CapsulaStage::Second,
///     "medical.interpretation".to_string(),
///     Some("AI助手".to_string()),
/// );
/// let policy = PolicyControl::new(
///     "policy://ai_analysis".to_string(),
///     vec!["read".to_string(), "analyze".to_string()],
/// );
/// let capsule = Capsule::new(header, policy, keyring, CapsulePayload::Cap1(cap1))?;
/// ```
///
/// ## 使用胶囊
/// ```text
/// // 直接访问字段
/// println!("胶囊ID: {}", capsule.header.id);
/// println!("创建时间: {}", capsule.header.created_at);
/// println!("载荷类型: {}", capsule.get_payload_type());
///
/// // 类型安全的载荷访问
/// if let Some(cap1) = capsule.as_cap1() {
///     println!("关联的Cap0 ID: {}", cap1.cap0_id);
///     let (meta, bnf) = cap1.unseal(&keyring, &decryption_key)?;
/// }
///
/// // 统一解封接口（适用于Cap1和Cap2）
/// match capsule.unseal_payload(&keyring, &decryption_key)? {
///     CapsuleContent::Cap1Content {
///         cap0_id,
///         meta_data,
///         bnf_extract_data,
///     } => {
///         println!("解封了Cap1，关联Cap0: {}", cap0_id);
///     }
///     CapsuleContent::Cap2Content { owner_id, refs } => {
///         println!("Cap2所有者: {}，引用数: {}", owner_id, refs.len());
///     }
/// }
/// ```
///
/// # 设计优势
///
/// - **职责分离**：Cap0/1/2专注数据加密，Capsule专注外壳管理
/// - **类型安全**：编译期确保正确的数据类型
/// - **灵活性**：同一个Cap可以用不同策略包装成多个Capsule
/// - **错误隔离**：可以精确定位是数据层还是外壳层的问题
/// - **可扩展**：易于添加新的胶囊类型而不影响现有代码
pub mod examples {}
