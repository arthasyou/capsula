use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{ContentType, EncAlg};

// --- 密文块：加解密所需最小信息 ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub ct: String,     // base64(ciphertext || tag)
    pub aad: String,    // base64(aad) —— 由外层计算并传入（绑定上下文）
    pub enc: EncAlg,    // AES-256-GCM / ChaCha20-Poly1305
    pub nonce: String,  // base64(12 bytes)
    pub len: u64,       // 明文长度（字节）
    pub dek_id: String, // 对应的 DEK ID（外层用 KeyWrap 关联）
}

// --- 明文指纹（被签名的“承诺值”）---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    pub alg: String,  // 例: "SHA-256" / "Merkle-SHA256"
    pub hash: String, // hex 或 base64
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<Value>, // 任意结构的概要标签，如 {"heme":"normal"}
}

// --- 作者签名（对 AuthorProof 的签名值/身份线索）---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub alg: String,         // "Ed25519" / "ECDSA-P256-SHA256"
    pub sig: String,         // base64(signature)
    pub author_hint: String, // 作者标识线索（证书主体/DID/公钥指纹）
    #[serde(default)]
    pub cert_hint: Option<String>, // 可选：证书链/目录定位线索
}

// --- 作者证明：明确“签了什么” ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorProof {
    pub subject: Digest, // 明文指纹（或 Merkle 根）
    #[serde(default)]
    pub schema_hash: Option<String>, // 可选：明文结构/规范哈希
    #[serde(default)]
    pub issued_at: Option<String>, // 可选：RFC3339 出具时间
    pub signature: Signature, // 作者对 {subject, schema_hash?, issued_at?} 的脱离式签名
}

// --- 最小可验证封装单元：密文 + 单一作者证明 ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlock {
    pub block: Ciphertext,         // 密文主体（机密性/完整性 by AEAD）
    pub proof: AuthorProof,        // 唯一作者的来源/不可抵赖证明
    pub content_type: ContentType, // 明文内容类型（MIME）
}
