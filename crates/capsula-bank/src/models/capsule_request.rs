//! 胶囊创建请求模型

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// 加密信息
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EncryptionInfo {
    /// 加密算法（如 "AES-256-GCM"）
    pub algorithm: String,

    /// 加密的 DEK（Data Encryption Key），Base64 编码
    /// 使用 PKI 证书的公钥通过 RSA-OAEP 加密
    pub encrypted_dek: String,

    /// AES-GCM Nonce，Base64 编码（12 字节）
    pub nonce: String,

    /// AES-GCM 认证标签，Base64 编码（16 字节）
    pub tag: String,

    /// 密钥所有者 ID（用于 PKI 查找证书）
    pub key_owner: String,

    /// RSA 填充方案（如 "RSA-OAEP-SHA256"）
    #[serde(default = "default_rsa_padding")]
    pub rsa_padding: String,
}

fn default_rsa_padding() -> String {
    "RSA-OAEP-SHA256".to_string()
}

/// Cap0 数据（外部存储）
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Cap0Data {
    /// 外部文件 URL（S3 或其他对象存储）
    pub external_url: String,

    /// 原始文本 URL（可选，如果已提取）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_text_url: Option<String>,

    /// 加密信息（可选，如果文件已加密）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionInfo>,
}

/// Cap1 元数据
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Cap1Metadata {
    /// 文件名
    pub filename: String,

    /// 文件大小（字节）
    pub size: u64,

    /// MIME 类型
    pub mime_type: String,

    /// 文件哈希（SHA-256，可选，Bank 会验证）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,

    /// 创建时间（Unix 时间戳，可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,

    /// 修改时间（Unix 时间戳，可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<i64>,

    /// 额外的键值对
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

/// Cap1 数据（内联存储）
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Cap1Data {
    /// 元数据
    pub metadata: Cap1Metadata,

    /// 结构化数据（BNF 提取或 LLM 生成）
    pub structured_data: serde_json::Value,
}

/// 创建胶囊请求（外部化方案）
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateCapsuleRequest {
    /// Cap0 数据（外部存储引用）
    pub cap0: Cap0Data,

    /// Cap1 数据（元数据 + 结构化数据）
    pub cap1: Cap1Data,

    /// 所有者 ID
    pub owner_id: String,

    /// 内容类型（如 "medical.blood_test"）
    pub content_type: String,

    /// 策略 URI
    pub policy_uri: String,

    /// 权限列表
    pub permissions: Vec<String>,

    /// 创建者（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
}

/// 创建胶囊响应
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateCapsuleResponse {
    /// 是否成功
    pub success: bool,

    /// Cap0 胶囊 ID
    pub cap0_id: String,

    /// Cap1 胶囊 ID
    pub cap1_id: String,

    /// 外部存储 URL
    pub storage_url: String,

    /// 创建时间（Unix 时间戳）
    pub created_at: i64,

    /// 消息（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// 预签名 URL 请求
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PresignedUrlRequest {
    /// 文件名
    pub filename: String,

    /// 内容类型
    pub content_type: String,

    /// 文件大小（字节）
    pub size: u64,

    /// 过期时间（秒，默认 3600）
    #[serde(default = "default_expires_in")]
    pub expires_in: u64,
}

fn default_expires_in() -> u64 {
    3600 // 1 小时
}

/// 预签名 URL 响应
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PresignedUrlResponse {
    /// 上传 URL
    pub upload_url: String,

    /// 对象键（S3 key）
    pub object_key: String,

    /// 过期时间（Unix 时间戳）
    pub expires_at: i64,

    /// 最大文件大小（字节）
    pub max_size: u64,
}

/// 验证胶囊请求
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VerifyCapsuleRequest {
    /// Cap0 胶囊 ID
    pub cap0_id: String,

    /// 期望的哈希值（SHA-256）
    pub expected_hash: String,
}

/// 验证胶囊响应
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VerifyCapsuleResponse {
    /// 是否有效
    pub valid: bool,

    /// 实际哈希值
    pub actual_hash: String,

    /// 验证时间（Unix 时间戳）
    pub verified_at: i64,

    /// 消息（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
