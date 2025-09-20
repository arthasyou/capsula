use serde::{Deserialize, Serialize};

use crate::{integrity::digest::Digest, EncAlg};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub aad: String,    // base64(aad) —— 由外层计算并传入（绑定上下文）
    pub enc: EncAlg,    // AES-256-GCM / ChaCha20-Poly1305
    pub nonce: String,  // base64(12 bytes)
    pub len: u64,       // 明文长度（字节）
    pub dek_id: String, // 对应的 DEK ID（外层用 KeyWrap 关联）
    pub storage: CipherStorage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CipherStorage {
    Inline {
        ct_b64: String, // base64(ciphertext||tag)
        ciphertext_len: Option<u64>,
        ciphertext_digest: Option<Digest>, // 传输校验可选
    },
    External {
        uri: String, // s3://... 或 https://...
        ciphertext_len: Option<u64>,
        ciphertext_digest: Option<Digest>,
    },
}

impl Ciphertext {
    /// Get the ciphertext as base64 string for decryption
    pub fn get_ciphertext_b64(&self) -> Result<&str, String> {
        match &self.storage {
            CipherStorage::Inline { ct_b64, .. } => Ok(ct_b64),
            CipherStorage::External { .. } => {
                Err("External storage not yet supported for direct access".to_string())
            }
        }
    }

    /// Get the ciphertext bytes for decryption (decodes base64)
    pub fn get_ciphertext_bytes(&self) -> Result<Vec<u8>, String> {
        match &self.storage {
            CipherStorage::Inline { ct_b64, .. } => capsula_crypto::base64::decode(ct_b64)
                .map_err(|e| format!("Failed to decode ciphertext: {}", e)),
            CipherStorage::External { .. } => {
                Err("External storage not yet supported for direct access".to_string())
            }
        }
    }
}
