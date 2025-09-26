use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

/// 数据胶囊存储记录
/// 简化设计，只保留必要的查询字段
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CapsuleRecord {
    // ===== Header 核心字段（用于查询） =====
    /// 胶囊唯一标识符（主键）
    /// 格式：cid:<base32编码>
    pub capsule_id: String,

    /// 胶囊版本
    pub version: String,

    /// 胶囊阶段：first/second/third
    pub stage: String,

    /// 内容类型
    /// 例如：medical.blood_test, legal.contract, financial.report
    pub content_type: String,

    /// 创建时间（Unix时间戳）
    pub created_at: i64,

    /// 创建者（可选）
    pub creator: Option<String>,

    /// 所有者ID（额外的重要查询字段）
    pub owner_id: String,

    // ===== 完整的胶囊数据（JSON存储） =====
    /// 完整的胶囊数据，包含所有组件
    /// 包括：header, aad_binding, policy, keyring, payload, integrity等
    pub capsule_data: Value,

    /// 自定义元数据（可选）
    /// 用于索引和检索的额外信息
    pub metadata: Option<Value>,
}

impl CapsuleRecord {
    /// 创建新的胶囊记录
    pub fn new(
        capsule_id: String,
        version: String,
        stage: String,
        content_type: String,
        owner_id: String,
        capsule_data: serde_json::Value,
    ) -> Self {
        let now = chrono::Utc::now().timestamp();

        Self {
            capsule_id,
            version,
            stage,
            content_type,
            created_at: now,
            creator: None,
            owner_id,
            capsule_data,
            metadata: None,
        }
    }

    /// 设置创建者
    pub fn with_creator(mut self, creator: String) -> Self {
        self.creator = Some(creator);
        self
    }

    /// 添加元数据
    pub fn add_metadata(mut self, key: String, value: String) -> Self {
        if self.metadata.is_none() {
            self.metadata = Some(serde_json::json!({}));
        }
        if let Some(metadata) = self.metadata.as_mut() {
            if let Some(obj) = metadata.as_object_mut() {
                obj.insert(key, serde_json::json!(value));
            }
        }
        self
    }

    /// 从 capsula-core 的 Capsule 转换（将来使用）
    /// ```
    /// let capsule_record = CapsuleRecord::from_core_capsule(
    ///     capsule, // capsula_core::Capsule
    ///     owner_id,
    /// );
    /// ```
    pub fn from_json(capsule_json: serde_json::Value, owner_id: String) -> Option<Self> {
        // 从 JSON 中提取 header 字段
        let header = capsule_json.get("header")?;
        let capsule_id = header.get("id")?.as_str()?.to_string();
        let version = header.get("version")?.as_str()?.to_string();
        let stage = header.get("stage")?.as_str()?.to_string();
        let content_type = header.get("content_type")?.as_str()?.to_string();
        let created_at = header
            .get("created_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.timestamp())
            .unwrap_or_else(|| chrono::Utc::now().timestamp());
        let creator = header
            .get("creator")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let metadata = header.get("metadata").cloned();

        Some(Self {
            capsule_id,
            version,
            stage,
            content_type,
            created_at,
            creator,
            owner_id,
            capsule_data: capsule_json,
            metadata,
        })
    }
}
