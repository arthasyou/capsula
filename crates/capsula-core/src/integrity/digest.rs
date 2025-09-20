use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    pub alg: String,  // 例: "SHA-256" / "Merkle-SHA256"
    pub hash: String, // hex 或 base64
}
