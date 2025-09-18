use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    protocol::types::{CapsulaGranted, CapsulaStage},
    Keyring,
};

/// 1阶数据胶囊 - 对原始报告的安全封装
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsula1 {
    pub header: Header,       // ← 胶囊头（版本、类型、时间戳等）
    pub meta: Meta,           // ← 元数据（0阶数据的摘要等）
    pub payload: Payload,     // ← 原始报告（0阶数据）加密后放在这里
    pub policy: Policy,       // ← 使用策略（X.509要求、OPA策略等）
    pub integrity: Integrity, // ← 对整个胶囊的签名
    #[serde(default)]
    pub audit: Vec<AuditEvent>, // 审计日志（考虑放在外部不要封装在胶囊里面）
    #[serde(default)]
    pub keyring: Keyring, // 传输时的密钥包装
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub ver: String,         // "1.0"
    pub stage: CapsulaStage, // 1
    #[serde(rename = "type")]
    pub type_: String, // 如 "medical.blood_test"
    pub id: String,          // "cid:...base32"
    pub created_at: String,  // RFC3339 字符串
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub producer: String, // 数据采集者（医院）
    pub owner: String,    // 数据拥有者（患者）
    #[serde(default)]
    pub user: Option<String>, // 数据使用者（可空）
    #[serde(default)]
    pub grants: Vec<CapsulaGranted>, // 使用授权向量
    pub digest: Digest,   // 原始报告的摘要
    #[serde(default)]
    pub expires_at: Option<String>, // 使用期限
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest {
    pub alg: String,  // "SHA-256"
    pub hash: String, // 原始报告的哈希值
    #[serde(default)]
    pub summary: Value, // ZKP用的关键内容概要，如 {"blood_wbc":"normal", "blood_rbc":"normal"}
}

/// 载荷 - 加密的原始报告数据
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub ct: String,  // base64(encrypted_original_report) ← 0阶报告加密后的内容
    pub aad: String, // base64(additional_authenticated_data) - 绑定header/meta/policy
    pub enc: String, // "AES-256-GCM" / "ChaCha20-Poly1305"
    pub len: u64,    // 原始报告明文长度
    #[serde(default)]
    pub external: Option<String>, // 大文件外链（如影像文件的存储位置）
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Policy {
    #[serde(default)]
    pub x509_req: Option<X509Req>, // 证书要求
    #[serde(default)]
    pub rego: Option<String>, // OPA策略
    #[serde(default)]
    pub simple_rules: Vec<String>, // 简单规则
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509Req {
    #[serde(default)]
    pub eku: Vec<String>, // 扩展密钥用法要求
}

/// 密钥包装 - 用于传输
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyWrap {
    pub kid: String,         // 接收方公钥标识
    pub alg: String,         // "X25519+HKDF"
    pub cek_wrapped: String, // base64(用接收方公钥包装的内容加密密钥)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrity {
    pub signature: Signature, // 发送方签名
    #[serde(default)]
    pub watermark: Option<Watermark>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub alg: String,    // "Ed25519"
    pub sig: String,    // base64(签名) - 对整个胶囊的签名
    pub signer: String, // 签名者（医疗机构）
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watermark {
    #[serde(rename = "type")]
    pub type_: String, // "fragile" / "robust"
    pub data: String, // 水印数据
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: String,     // 时间戳
    pub actor: String,  // 执行者
    pub action: String, // "create" / "access" / "decrypt"
    #[serde(default)]
    pub target: Option<String>,
    pub result: String, // "ok" / "deny"
    #[serde(default)]
    pub sig: Option<String>,
}
