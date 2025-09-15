use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ContentType, EncAlg};

/// 密文块 - 通用结构，用于封装加密数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextBlock {
    pub ct: String,        // base64(ciphertext)
    pub aad: String,       // base64(aad) —— 绑定 header/meta/policy
    pub enc: EncAlg,       // "AES-256-GCM" / "ChaCha20-Poly1305"
    pub nonce: String,     // base64(nonce) - 用于解密
    pub len: u64,          // 明文长度
    pub mime: ContentType, // "application/json" / "text/plain" / "application/pdf" / "image/png"
    pub dek_id: String,    // 关联到 keyring 里对应的 DEK 包裹
}

/// original (encrypted, non-distributable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginalBlock {
    pub enc_blob: CiphertextBlock, // reuse existing Payload as encrypted blob
    pub provenance: ProvenanceBundle,
    #[serde(default)]
    pub custody_hint: Option<String>, // "sealed-hsm" / "m-of-n" / "owner-only"
}

/// 来源证明
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceBundle {
    pub digest: Digest,      // 明文摘要
    pub schema_hash: String, // schema hash
    pub issued_at: String,   // RFC3339
    pub signature: String,   // detached signature (base64)
    #[serde(default)]
    pub producer_cert_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    pub alg: String,  // "SHA-256"
    pub hash: String, // 哈希（十六进制/BASE64 视你的实现）
    #[serde(default)]
    pub summary: Value, // 任意结构的概要标签，如 {"heme":"normal"}
}
