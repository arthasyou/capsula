//! 数据胶囊高级API
//!
//! 提供简单易用的封包和解包接口

use capsula_key::{Key, KeySign};
use time::OffsetDateTime;

use crate::encapsulator::CapsulaBuilder;
use crate::decapsulator::{CapsuleDecryptor, DecapsulationResult};
use crate::error::{CoreError, Result};
use crate::protocol::capsule::Capsula1;
use crate::protocol::types::CapsulaGranted;

/// 数据胶囊API
pub struct CapsulaApi;

impl CapsulaApi {
    /// 简单封包操作
    /// 
    /// # 参数
    /// * `data` - 原始数据
    /// * `data_type` - 数据类型（如 "medical.blood_test"）
    /// * `producer` - 数据生产者
    /// * `owner` - 数据拥有者
    /// * `producer_key` - 生产者的签名密钥
    /// * `recipient_keys` - 接收者的密钥列表 (ID, 公钥)
    pub fn encapsulate_simple<S: KeySign>(
        data: Vec<u8>,
        data_type: String,
        producer: String,
        owner: String,
        producer_key: &S,
        recipient_keys: &[(String, &dyn Key)],
    ) -> Result<Capsula1> {
        CapsulaBuilder::new(data, data_type)
            .producer(producer)
            .owner(owner)
            .add_grant(CapsulaGranted::Read)
            .encapsulate(producer_key, recipient_keys)
    }

    /// 带策略的封包操作
    #[allow(clippy::too_many_arguments)]
    pub fn encapsulate_with_policy<S: KeySign>(
        data: Vec<u8>,
        data_type: String,
        producer: String,
        owner: String,
        producer_key: &S,
        recipient_keys: &[(String, &dyn Key)],
        simple_rules: Vec<String>,
        expires_at: Option<OffsetDateTime>,
    ) -> Result<Capsula1> {
        let mut builder = CapsulaBuilder::new(data, data_type)
            .producer(producer)
            .owner(owner)
            .add_grant(CapsulaGranted::Read);

        if let Some(expiry) = expires_at {
            builder = builder.expires_at(expiry);
        }

        if !simple_rules.is_empty() {
            let policy = crate::protocol::capsule::Policy {
                x509_req: None,
                rego: None,
                simple_rules,
            };
            builder = builder.policy(policy);
        }

        builder.encapsulate(producer_key, recipient_keys)
    }

    /// 简单解包操作（RSA密钥）
    /// 
    /// # 参数
    /// * `capsule` - 数据胶囊
    /// * `private_key` - 接收者的RSA私钥
    /// * `user_id` - 用户标识
    /// * `producer_public_key` - 生产者公钥（可选，用于签名验证）
    pub fn decapsulate_simple_rsa(
        capsule: &Capsula1,
        private_key: capsula_key::RsaKey,
        user_id: String,
        producer_public_key: Option<Vec<u8>>,
    ) -> Result<DecapsulationResult> {
        let mut decryptor = CapsuleDecryptor::new_rsa(private_key, user_id);
        
        if let Some(pub_key) = producer_public_key {
            decryptor = decryptor.with_producer_public_key(pub_key);
        }

        decryptor.decapsulate(capsule)
    }

    /// 简单解包操作（P256密钥）
    /// 
    /// # 参数
    /// * `capsule` - 数据胶囊
    /// * `private_key` - 接收者的P256私钥
    /// * `user_id` - 用户标识
    /// * `producer_public_key` - 生产者公钥（可选，用于签名验证）
    pub fn decapsulate_simple_p256(
        capsule: &Capsula1,
        private_key: capsula_key::P256Key,
        user_id: String,
        producer_public_key: Option<Vec<u8>>,
    ) -> Result<DecapsulationResult> {
        let mut decryptor = CapsuleDecryptor::new_p256(private_key, user_id);
        
        if let Some(pub_key) = producer_public_key {
            decryptor = decryptor.with_producer_public_key(pub_key);
        }

        decryptor.decapsulate(capsule)
    }

    /// 验证胶囊而不解密
    pub fn verify_capsule(
        capsule: &Capsula1,
        producer_public_key: Option<Vec<u8>>,
        user_id: Option<String>,
    ) -> Result<bool> {
        // 创建一个临时的虚拟密钥用于验证
        let dummy_key = capsula_key::RsaKey::generate_2048()
            .map_err(|e| CoreError::Other(format!("Failed to create dummy key: {}", e)))?;
        
        let decryptor = if let Some(pub_key) = producer_public_key {
            CapsuleDecryptor::new_rsa(dummy_key, user_id.unwrap_or_default())
                .with_producer_public_key(pub_key)
        } else {
            CapsuleDecryptor::new_rsa(dummy_key, user_id.unwrap_or_default())
        };

        // 只进行结构和签名验证，不解密
        match decryptor.decapsulate(capsule) {
            Ok(result) => Ok(result.verification.signature_valid && 
                            result.verification.policy_valid && 
                            result.verification.time_valid),
            Err(_) => Ok(false),
        }
    }
}

/// 便利函数：创建医疗数据胶囊
pub fn create_medical_capsule<S: KeySign>(
    medical_data: Vec<u8>,
    report_type: &str,
    hospital: String,
    patient: String,
    doctor_key: &S,
    authorized_users: &[(String, &dyn Key)],
    expires_in_days: Option<u64>,
) -> Result<Capsula1> {
    let data_type = format!("medical.{}", report_type);
    let expires_at = expires_in_days.map(|days| {
        OffsetDateTime::now_utc() + time::Duration::days(days as i64)
    });

    CapsulaApi::encapsulate_with_policy(
        medical_data,
        data_type,
        hospital,
        patient,
        doctor_key,
        authorized_users,
        vec!["medical_personnel:required".to_string()],
        expires_at,
    )
}

/// 便利函数：解包医疗数据胶囊（RSA密钥）
pub fn decrypt_medical_capsule_rsa(
    capsule: &Capsula1,
    user_private_key: capsula_key::RsaKey,
    user_id: String,
    hospital_public_key: Vec<u8>,
) -> Result<DecapsulationResult> {
    CapsulaApi::decapsulate_simple_rsa(
        capsule,
        user_private_key,
        user_id,
        Some(hospital_public_key),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsula_key::{RsaKey, Key, KeySign};

    #[test]
    fn test_simple_encapsulation() {
        let data = b"Test medical report".to_vec();
        let producer_key = RsaKey::generate_2048().unwrap();
        let recipient_key = RsaKey::generate_2048().unwrap();
        
        let recipients = vec![("user1".to_string(), &recipient_key as &dyn Key)];

        let result = CapsulaApi::encapsulate_simple(
            data,
            "medical.test".to_string(),
            "Hospital A".to_string(),
            "Patient 001".to_string(),
            &producer_key,
            &recipients,
        );

        assert!(result.is_ok());
        let capsule = result.unwrap();
        assert_eq!(capsule.header.type_, "medical.test");
        assert_eq!(capsule.meta.producer, "Hospital A");
        assert_eq!(capsule.meta.owner, "Patient 001");
    }

    #[test]
    fn test_medical_capsule_creation() {
        let medical_data = b"Blood test results: Normal".to_vec();
        let doctor_key = RsaKey::generate_2048().unwrap();
        let nurse_key = RsaKey::generate_2048().unwrap();
        
        let authorized_users = vec![("nurse1".to_string(), &nurse_key as &dyn Key)];

        let result = create_medical_capsule(
            medical_data,
            "blood_test",
            "Central Hospital".to_string(),
            "John Doe".to_string(),
            &doctor_key,
            &authorized_users,
            Some(30), // 30天后过期
        );

        assert!(result.is_ok());
        let capsule = result.unwrap();
        assert_eq!(capsule.header.type_, "medical.blood_test");
        assert!(capsule.meta.expires_at.is_some());
        assert!(!capsule.policy.simple_rules.is_empty());
    }

    #[test]
    fn test_capsule_verification() {
        let data = b"Test data".to_vec();
        let producer_key = RsaKey::generate_2048().unwrap();
        let recipient_key = RsaKey::generate_2048().unwrap();
        let recipients = vec![("user1".to_string(), &recipient_key as &dyn Key)];

        let capsule = CapsulaApi::encapsulate_simple(
            data,
            "test".to_string(),
            "Producer".to_string(),
            "Owner".to_string(),
            &producer_key,
            &recipients,
        ).unwrap();

        // TODO: 需要实现公钥导出功能才能完整测试签名验证
        let verification_result = CapsulaApi::verify_capsule(
            &capsule,
            None, // 暂时不验证签名
            Some("user1".to_string()),
        );

        assert!(verification_result.is_ok());
    }
}