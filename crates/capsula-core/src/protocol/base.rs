use serde::{Deserialize, Serialize};

use crate::{
    protocol::{block::OriginalBlock, policy::Policy},
    Header, KeyWrap, Meta,
};

/// First-order capsule with optional co-existence of B1 (original) and multiple B3 (views); B2
/// (grants) is external.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsule {
    pub header: Header,
    pub meta: Meta,
    pub policy: Policy,

    #[serde(default)]
    pub original: Option<OriginalBlock>,

    #[serde(default)]
    pub keyring: Vec<KeyWrap>,
    // pub integrity: Integrity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    pub signature: Signature, // 发送方签名
    #[serde(default)]
    pub watermark: Option<Watermark>, // 可选水印
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub alg: String,    // "Ed25519"
    pub sig: String,    // base64(...)
    pub signer: String, // 标识（如机构/证书主体）
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watermark {
    #[serde(rename = "type")]
    pub type_: String, // "fragile" / "robust" 等
    pub data: String, // 水印数据（编码形式自定）
}
