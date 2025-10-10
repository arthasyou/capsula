use serde::{Deserialize, Serialize};

/// 私钥存储模型（极简版）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    /// 私钥唯一标识符
    pub key_id: String,

    /// 密钥所有者ID（用户ID）
    pub owner_id: String,

    /// 私钥数据（PEM格式）
    pub private_key_pem: String,
}

impl PrivateKey {
    /// 创建新的私钥记录
    pub fn new(key_id: String, owner_id: String, private_key_pem: String) -> Self {
        Self {
            key_id,
            owner_id,
            private_key_pem,
        }
    }
}
