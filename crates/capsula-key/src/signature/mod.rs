use capsula_crypto::{asymmetric::der_to_pem, verify_signature, Algorithm};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// 完整的数字签名结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    pub alg: Algorithm,
    pub signature: Vec<u8>,
    pub spki_der: Vec<u8>,
}

impl DigitalSignature {
    /// 获取签名的十六进制表示
    pub fn signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }

    /// 获取公钥的十六进制表示
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.spki_der)
    }

    pub fn public_key_pem(&self) -> String {
        der_to_pem("PUBLIC KEY", &self.spki_der)
    }

    pub fn algorithm(&self) -> &Algorithm {
        &self.alg
    }

    /// 序列化为JSON字符串
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// 从JSON字符串反序列化
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::EncodingError(e.to_string()))
    }

    pub fn verify_signature(&self, data: &[u8]) -> Result<bool> {
        let r = verify_signature(&self.spki_der, data, &self.signature)?;
        Ok(r)
    }
}
