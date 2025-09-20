pub mod digest;
pub mod signature;
pub mod watermark;

use serde::{Deserialize, Serialize};

use crate::integrity::{digest::Digest, signature::Signature, watermark::Watermark};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integrity {
    pub digest: Digest,
    pub signature: Signature,         // 整体指纹（对整个胶囊的摘要）
    pub watermark: Option<Watermark>, // 数字水印
}
