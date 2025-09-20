use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub alg: String,         // "Ed25519" / "ECDSA-P256-SHA256"
    pub sig: String,         // base64(signature)
    pub author_hint: String, // 作者标识线索（证书主体/DID/公钥指纹）
    #[serde(default)]
    pub cert_hint: Option<String>, // 可选：证书链/目录定位线索
}
