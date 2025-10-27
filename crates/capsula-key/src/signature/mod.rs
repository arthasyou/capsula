use capsula_crypto::Algorithm;
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// 完整的数字签名结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    pub alg: Algorithm,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl DigitalSignature {
    /// 获取签名的十六进制表示
    pub fn signature_hex(&self) -> String {
        hex::encode(&self.signature)
    }

    /// 获取公钥的十六进制表示
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    /// 序列化为JSON字符串
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// 从JSON字符串反序列化
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|e| Error::EncodingError(e.to_string()))
    }
}

// /// 独立的签名验证函数（不需要密钥对实例）
// pub fn verify_signature_standalone(
//     data: &[u8],
//     digital_signature: &DigitalSignature,
// ) -> Result<bool, Error> {
//     // 计算数据哈希
//     use sha2::{Digest, Sha256};
//     let mut hasher = Sha256::new();
//     hasher.update(data);
//     let computed_hash = hasher.finalize().to_vec();

//     // 检查哈希是否匹配
//     if computed_hash != digital_signature.extended_info.data_hash {
//         return Ok(false);
//     }

//     // 重新序列化扩展信息
//     let extended_info_bytes = serde_json::to_vec(&digital_signature.extended_info)
//         .map_err(|e| Error::EncodingError(format!("Failed to serialize extended info: {e}")))?;

//     // 重建待验证数据
//     let mut verify_data = Vec::new();
//     verify_data.extend_from_slice(&computed_hash);
//     verify_data.extend_from_slice(&extended_info_bytes);

//     // 从字节重建 Ed25519 签名
//     let signature = Signature::from_bytes(
//         digital_signature
//             .signature
//             .as_slice()
//             .try_into()
//             .map_err(|_| Error::SignatureError("Invalid signature length".to_string()))?,
//     );

//     // 从数字签名中获取公钥
//     // 如果公钥是 SPKI DER 格式，需要解析出原始公钥
//     let public_key_bytes = if digital_signature.public_key.len() == 32 {
//         // 原始 32 字节公钥
//         digital_signature.public_key.as_slice()
//     } else {
//         // SPKI DER 格式，需要提取公钥部分
//         // Ed25519 SPKI 格式：前 12 字节是 OID 和元数据，后 32 字节是公钥
//         if digital_signature.public_key.len() >= 44 {
//             &digital_signature.public_key[12 ..]
//         } else {
//             return Err(Error::KeyError("Invalid public key format".to_string()));
//         }
//     };

//     let public_key = VerifyingKey::from_bytes(
//         public_key_bytes
//             .try_into()
//             .map_err(|_| Error::KeyError("Invalid public key length".to_string()))?,
//     )
//     .map_err(|e| Error::KeyError(format!("Invalid public key: {e}")))?;

//     // 执行 Ed25519 验证
//     Ok(public_key.verify(&verify_data, &signature).is_ok())
// }
