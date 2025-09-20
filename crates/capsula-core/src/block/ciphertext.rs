use serde::{Deserialize, Serialize};

use crate::EncAlg;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub ct: String,     // base64(ciphertext || tag)
    pub aad: String,    // base64(aad) —— 由外层计算并传入（绑定上下文）
    pub enc: EncAlg,    // AES-256-GCM / ChaCha20-Poly1305
    pub nonce: String,  // base64(12 bytes)
    pub len: u64,       // 明文长度（字节）
    pub dek_id: String, // 对应的 DEK ID（外层用 KeyWrap 关联）
}
