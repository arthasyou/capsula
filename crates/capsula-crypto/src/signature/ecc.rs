use std::time::SystemTime;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use signature::Verifier;

use crate::Error;

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
        serde_json::to_string_pretty(self).map_err(|e| Error::SignatureError(e.to_string()))
    }

    /// 从JSON字符串反序列化
    pub fn from_json(json: &str) -> Result<Self, Error> {
        serde_json::from_str(json).map_err(|e| Error::SignatureError(e.to_string()))
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
        .map_err(|e| Error::SignatureError(format!("Failed to serialize extended info: {e}")))?;

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
    let public_key = VerifyingKey::from_bytes(
        digital_signature
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::SignatureError("Invalid public key length".to_string()))?,
    )
    .map_err(|e| Error::SignatureError(format!("Invalid public key: {e}")))?;

    // 执行 Ed25519 验证
    Ok(public_key.verify(&verify_data, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EccKeyPair;
    use std::time::UNIX_EPOCH;

    #[test]
    fn test_sign_and_verify_with_location() {
        let keypair = EccKeyPair::generate_keypair().unwrap();

        let location = LocationInfo {
            latitude: Some(31.2304),
            longitude: Some(121.4737),
            address: Some("上海市第一人民医院".to_string()),
            institution_id: Some("HOSPITAL_001".to_string()),
            department: Some("心内科".to_string()),
        };

        let medical_data =
            "患者：张三，年龄：45岁，诊断：高血压二级，处方：氨氯地平片 5mg 每日一次".as_bytes();

        // 签名
        let signature = keypair
            .sign_data(
                medical_data,
                location.clone(),
                Some("Dr. 李医生 (医师证号: 123456789)".to_string()),
                Some("诊断处方".to_string()),
            )
            .unwrap();

        // 验证
        let is_valid = keypair.verify_signature(medical_data, &signature).unwrap();
        assert!(is_valid);

        // 独立验证
        let is_valid_standalone = verify_signature_standalone(medical_data, &signature).unwrap();
        assert!(is_valid_standalone);

        // 验证位置信息
        assert_eq!(signature.extended_info.location, location);
        assert!(signature.extended_info.signer_info.is_some());
        assert!(signature.extended_info.signature_type.is_some());
    }

    #[test]
    fn test_sign_with_timestamp() {
        let keypair = EccKeyPair::generate_keypair().unwrap();
        let data = "紧急医疗记录".as_bytes();

        let signature = keypair
            .sign_with_timestamp(data, Some("Dr. 急诊医生".to_string()))
            .unwrap();

        let is_valid = keypair.verify_signature(data, &signature).unwrap();
        assert!(is_valid);

        // 检查时间戳
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(signature.extended_info.timestamp <= current_time);
        assert!(signature.extended_info.timestamp > current_time - 10); // 应该在10秒内
    }

    #[test]
    fn test_add_location_info() {
        let keypair = EccKeyPair::generate_keypair().unwrap();
        let data = "转院医疗记录".as_bytes();

        // 原始签名（无位置信息）
        let original_signature = keypair
            .sign_with_timestamp(data, Some("Dr. 原医院医生".to_string()))
            .unwrap();

        // 添加新位置信息
        let new_location = LocationInfo {
            latitude: Some(39.9042),
            longitude: Some(116.4074),
            address: Some("北京协和医院".to_string()),
            institution_id: Some("HOSPITAL_002".to_string()),
            department: Some("急诊科".to_string()),
        };

        let updated_signature = keypair
            .add_location_info(data, &original_signature, new_location.clone())
            .unwrap();

        // 验证更新后的签名
        let is_valid = keypair.verify_signature(data, &updated_signature).unwrap();
        assert!(is_valid);

        // 检查位置信息已更新
        assert_eq!(updated_signature.extended_info.location, new_location);
        assert!(
            updated_signature.extended_info.timestamp >= original_signature.extended_info.timestamp
        );
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = EccKeyPair::generate_keypair().unwrap();

        let location = LocationInfo {
            latitude: Some(31.2304),
            longitude: Some(121.4737),
            address: Some("测试医院".to_string()),
            institution_id: Some("TEST_001".to_string()),
            department: Some("测试科".to_string()),
        };

        let data = "测试医疗数据".as_bytes();
        let signature = keypair
            .sign_data(
                data,
                location,
                Some("测试医生".to_string()),
                Some("测试签名".to_string()),
            )
            .unwrap();

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
        let keypair = EccKeyPair::generate_keypair().unwrap();
        let data = b"original data";
        let tampered_data = "篡改数据".as_bytes();

        let signature = keypair.sign_with_timestamp(data, None).unwrap();

        // 用篡改的数据验证应该失败
        let is_valid = keypair.verify_signature(tampered_data, &signature).unwrap();
        assert!(!is_valid);
    }
}
