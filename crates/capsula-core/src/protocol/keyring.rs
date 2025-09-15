use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyWrap {
    pub kid: String,         // 接收方公钥标识
    pub alg: String,         // 包裹算法，如 "X25519+HKDF"
    pub cek_wrapped: String, // base64(...)
}
