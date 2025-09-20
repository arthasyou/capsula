use serde::{Deserialize, Serialize};

use crate::{
    capsule::{header::Header, meta::Meta},
    integrity::Integrity,
    Keyring,
};

pub mod header;
pub mod meta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsula {
    pub header: Header, // ← 胶囊头（版本、类型、时间戳等）
    pub meta: Meta,     // ← 元数据（0阶数据的摘要等）

    pub policy: String,       // 指向数据库或 IPFS 的访问策略
    pub integrity: Integrity, // ← 对整个胶囊的签名

    #[serde(default)]
    pub keyring: Keyring, // 传输时的密钥包装
}
