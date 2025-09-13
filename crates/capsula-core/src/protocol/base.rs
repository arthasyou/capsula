use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocol::types::{CapsulaGranted, CapsulaStage};

/// 1阶数据胶囊
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capsule {
    pub header: Header,
    pub meta: Meta,
    pub policy: Policy,
    pub payload: Payload,
    pub keyring: Vec<KeyWrap>,
    pub integrity: Integrity,
    #[serde(default)]
    pub audit: Vec<AuditEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub ver: String,         // "1.0"
    pub stage: CapsulaStage, // 1
    #[serde(rename = "type")]
    pub type_: String, // 如 "medical.report"
    pub id: String,          // "cid:...base32"
    pub created_at: String,  // RFC3339 字符串
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub producer: String, // 数据采集者
    pub owner: String,    // 数据拥有者
    #[serde(default)]
    pub user: Option<String>, // 数据使用者（可空）
    #[serde(default)]
    pub grants: Vec<CapsulaGranted>, // 授权向量，如 ["read","use"]
    pub digest: Digest,   // 数据摘要（ZKP用）
    #[serde(default)]
    pub expires_at: Option<String>, // 过期时间（可空）
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digest {
    pub alg: String,  // "SHA-256"
    pub hash: String, // 哈希（十六进制/BASE64 视你的实现）
    #[serde(default)]
    pub summary: Value, // 任意结构的概要标签，如 {"heme":"normal"}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub x509_req: Option<X509Req>, // 证书/属性要求（可选）
    #[serde(default)]
    pub rego: Option<String>, // OPA Rego 策略（可选）
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509Req {
    #[serde(default)]
    pub eku: Vec<String>, // 扩展密钥用法 OID 列表
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub ct: String,  // base64(ciphertext)
    pub aad: String, // base64(aad) —— 绑定 header/meta/policy
    pub enc: String, // "AES-256-GCM" / "ChaCha20-Poly1305"
    pub len: u64,    // 明文长度
    #[serde(default)]
    pub external: Option<String>, // 大文件外链（可空）
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyWrap {
    pub kid: String,         // 接收方公钥标识
    pub alg: String,         // 包裹算法，如 "X25519+HKDF"
    pub cek_wrapped: String, // base64(...)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrity {
    pub signature: Signature, // 发送方签名
    #[serde(default)]
    pub watermark: Option<Watermark>, // 可选水印
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub alg: String,    // "Ed25519"
    pub sig: String,    // base64(...)
    pub signer: String, // 标识（如机构/证书主体）
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watermark {
    #[serde(rename = "type")]
    pub type_: String, // "fragile" / "robust" 等
    pub data: String, // 水印数据（编码形式自定）
}

/// 审计事件（结构可按你后续规范扩展）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: String,     // 时间戳
    pub actor: String,  // 执行者
    pub action: String, // "open" / "grant" / "revoke" 等
    #[serde(default)]
    pub target: Option<String>, // 目标对象（可空）
    pub result: String, // "ok" / "deny" / 错误码
    #[serde(default)]
    pub sig: Option<String>, // 事件签名（可空）
}
