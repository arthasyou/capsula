use std::time::SystemTime;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use signature::Verifier;

use crate::error::Error;

/// 位置信息结构体
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LocationInfo {
    /// 纬度
    pub latitude: Option<f64>,
    /// 经度
    pub longitude: Option<f64>,
    /// 地址描述
    pub address: Option<String>,
    /// 医疗机构ID
    pub institution_id: Option<String>,
    /// 科室信息
    pub department: Option<String>,
}

/// 扩展签名信息结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedSignatureInfo {
    /// 原始数据的哈希
    pub data_hash: Vec<u8>,
    /// 时间戳 (Unix timestamp)
    pub timestamp: u64,
    /// 位置信息
    pub location: LocationInfo,
    /// 签名者信息
    pub signer_info: Option<String>,
    /// 签名用途/类型
    pub signature_type: Option<String>,
}

/// 完整的数字签名结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    /// Ed25519 签名
    pub signature: Vec<u8>,
    /// 扩展签名信息
    pub extended_info: ExtendedSignatureInfo,
    /// 公钥 (用于验证)
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

    /// 获取时间戳的可读格式
    pub fn timestamp_readable(&self) -> String {
        let datetime =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(self.extended_info.timestamp);
        format!("{datetime:?}")
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


/// 独立的签名验证函数（不需要密钥对实例）
pub fn verify_signature_standalone(
    data: &[u8],
    digital_signature: &DigitalSignature,
) -> Result<bool, Error> {
    // 计算数据哈希
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let computed_hash = hasher.finalize().to_vec();

    // 检查哈希是否匹配
    if computed_hash != digital_signature.extended_info.data_hash {
        return Ok(false);
    }

    // 重新序列化扩展信息
    let extended_info_bytes = serde_json::to_vec(&digital_signature.extended_info)
        .map_err(|e| Error::EncodingError(format!("Failed to serialize extended info: {e}")))?;

    // 重建待验证数据
    let mut verify_data = Vec::new();
    verify_data.extend_from_slice(&computed_hash);
    verify_data.extend_from_slice(&extended_info_bytes);

    // 从字节重建 Ed25519 签名
    let signature = Signature::from_bytes(
        digital_signature
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::SignatureError("Invalid signature length".to_string()))?,
    );

    // 从数字签名中获取公钥
    // 如果公钥是 SPKI DER 格式，需要解析出原始公钥
    let public_key_bytes = if digital_signature.public_key.len() == 32 {
        // 原始 32 字节公钥
        digital_signature.public_key.as_slice()
    } else {
        // SPKI DER 格式，需要提取公钥部分
        // Ed25519 SPKI 格式：前 12 字节是 OID 和元数据，后 32 字节是公钥
        if digital_signature.public_key.len() >= 44 {
            &digital_signature.public_key[12..]
        } else {
            return Err(Error::KeyError("Invalid public key format".to_string()));
        }
    };
    
    let public_key = VerifyingKey::from_bytes(
        public_key_bytes
            .try_into()
            .map_err(|_| Error::KeyError("Invalid public key length".to_string()))?,
    )
    .map_err(|e| Error::KeyError(format!("Invalid public key: {e}")))?;

    // 执行 Ed25519 验证
    Ok(public_key.verify(&verify_data, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::impls::ed25519::Ed25519Provider;
    use crate::provider::KeyProvider;
    use std::time::UNIX_EPOCH;

    #[test]
    fn test_sign_and_verify_with_location() {
        let provider = Ed25519Provider::new().unwrap();
        let handle = provider.generate().unwrap();
        
        let location = LocationInfo {
            latitude: Some(31.2304),
            longitude: Some(121.4737),
            address: Some("上海市第一人民医院".to_string()),
            institution_id: Some("HOSPITAL_001".to_string()),
            department: Some("心内科".to_string()),
        };

        let medical_data =
            "患者：张三，年龄：45岁，诊断：高血压二级，处方：氨氯地平片 5mg 每日一次".as_bytes();

        // 创建扩展签名信息
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(medical_data);
        let data_hash = hasher.finalize().to_vec();

        let extended_info = ExtendedSignatureInfo {
            data_hash: data_hash.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            location: location.clone(),
            signer_info: Some("Dr. 李医生 (医师证号: 123456789)".to_string()),
            signature_type: Some("诊断处方".to_string()),
        };

        // 序列化扩展信息
        let extended_info_bytes = serde_json::to_vec(&extended_info).unwrap();

        // 构建待签名数据
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&data_hash);
        sign_data.extend_from_slice(&extended_info_bytes);

        // 签名
        let signature_bytes = provider.sign(handle, &sign_data).unwrap();
        let public_key = provider.public_spki_der(handle).unwrap();

        // 创建数字签名
        let digital_signature = DigitalSignature {
            signature: signature_bytes,
            extended_info,
            public_key,
        };

        // 独立验证
        let is_valid_standalone = verify_signature_standalone(medical_data, &digital_signature).unwrap();
        assert!(is_valid_standalone);

        // 验证位置信息
        assert_eq!(digital_signature.extended_info.location, location);
        assert!(digital_signature.extended_info.signer_info.is_some());
        assert!(digital_signature.extended_info.signature_type.is_some());
    }

    #[test]
    fn test_signature_serialization() {
        let provider = Ed25519Provider::new().unwrap();
        let handle = provider.generate().unwrap();

        let location = LocationInfo {
            latitude: Some(31.2304),
            longitude: Some(121.4737),
            address: Some("测试医院".to_string()),
            institution_id: Some("TEST_001".to_string()),
            department: Some("测试科".to_string()),
        };

        let data = "测试医疗数据".as_bytes();
        
        // 创建扩展签名信息
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash = hasher.finalize().to_vec();

        let extended_info = ExtendedSignatureInfo {
            data_hash: data_hash.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            location,
            signer_info: Some("测试医生".to_string()),
            signature_type: Some("测试签名".to_string()),
        };

        let extended_info_bytes = serde_json::to_vec(&extended_info).unwrap();
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&data_hash);
        sign_data.extend_from_slice(&extended_info_bytes);

        let signature_bytes = provider.sign(handle, &sign_data).unwrap();
        let public_key = provider.public_spki_der(handle).unwrap();

        let signature = DigitalSignature {
            signature: signature_bytes,
            extended_info,
            public_key,
        };

        // 序列化为JSON
        let json = signature.to_json().unwrap();
        println!("签名JSON: {json}");

        // 从JSON反序列化
        let deserialized_signature = DigitalSignature::from_json(&json).unwrap();

        // 验证反序列化的签名
        let is_valid = verify_signature_standalone(data, &deserialized_signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let provider = Ed25519Provider::new().unwrap();
        let handle = provider.generate().unwrap();
        
        let data = b"original data";
        let tampered_data = "篡改数据".as_bytes();

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash = hasher.finalize().to_vec();

        let extended_info = ExtendedSignatureInfo {
            data_hash: data_hash.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            location: LocationInfo::default(),
            signer_info: None,
            signature_type: None,
        };

        let extended_info_bytes = serde_json::to_vec(&extended_info).unwrap();
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&data_hash);
        sign_data.extend_from_slice(&extended_info_bytes);

        let signature_bytes = provider.sign(handle, &sign_data).unwrap();
        let public_key = provider.public_spki_der(handle).unwrap();

        let signature = DigitalSignature {
            signature: signature_bytes,
            extended_info,
            public_key,
        };

        // 用篡改的数据验证应该失败
        let is_valid = verify_signature_standalone(tampered_data, &signature).unwrap();
        assert!(!is_valid);
    }
}