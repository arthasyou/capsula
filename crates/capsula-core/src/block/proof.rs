use serde::{Deserialize, Serialize};

use crate::integrity::{digest::Digest, signature::Signature};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorProof {
    pub subject: Digest, // 明文指纹（或 Merkle 根）
    #[serde(default)]
    pub schema_hash: Option<String>, // 可选：明文结构/规范哈希
    #[serde(default)]
    pub issued_at: Option<String>, // 可选：RFC3339 出具时间
    pub signature: Signature, // 作者对 {subject, schema_hash?, issued_at?} 的脱离式签名
}
