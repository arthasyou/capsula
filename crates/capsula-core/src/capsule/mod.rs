use std::collections::HashMap;

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
pub use cap0::Cap0;
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

    /// 获取胶囊ID
    pub fn get_id(&self) -> &str {
        &self.header.id
    }

    /// 获取胶囊阶段
    pub fn get_stage(&self) -> &CapsulaStage {
        &self.header.stage
    }

    /// 获取载荷类型
    pub fn get_payload_type(&self) -> &str {
        match &self.payload {
            CapsulePayload::Cap0(_) => "Cap0",
            CapsulePayload::Cap1(_) => "Cap1",
            CapsulePayload::Cap2(_) => "Cap2",
        }
    }

    /// 获取载荷的引用
    pub fn get_payload(&self) -> &CapsulePayload {
        &self.payload
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
