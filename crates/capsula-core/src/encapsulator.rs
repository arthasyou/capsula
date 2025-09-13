//! 数据胶囊封包器
//!
//! 实现1阶数据胶囊的封包功能，包括数据格式化、加密、签名等操作

use base64::{engine::general_purpose, Engine as _};
use capsula_crypto::{asymmetric::rsa, sha256, symmetric::aes::Aes};
use capsula_key::{Key, KeySign};
use rand::RngCore;
use serde_json::Value;
use time::OffsetDateTime;

use crate::{
    error::{CoreError, Result},
    protocol::{
        capsule::*,
        types::{CapsulaGranted, CapsulaStage},
    },
};

/// 数据胶囊封包器
pub struct CapsulaBuilder {
    /// 原始数据
    raw_data: Vec<u8>,
    /// 数据类型
    data_type: String,
    /// 生产者信息
    producer: String,
    /// 数据拥有者
    owner: String,
    /// 授权信息
    grants: Vec<CapsulaGranted>,
    /// 过期时间
    expires_at: Option<OffsetDateTime>,
    /// 访问策略
    policy: Policy,
}

impl CapsulaBuilder {
    /// 创建新的封包器
    pub fn new(raw_data: Vec<u8>, data_type: String) -> Self {
        Self {
            raw_data,
            data_type,
            producer: String::new(),
            owner: String::new(),
            grants: Vec::new(),
            expires_at: None,
            policy: Policy::default(),
        }
    }

    /// 设置生产者
    pub fn producer(mut self, producer: String) -> Self {
        self.producer = producer;
        self
    }

    /// 设置数据拥有者
    pub fn owner(mut self, owner: String) -> Self {
        self.owner = owner;
        self
    }

    /// 添加授权
    pub fn add_grant(mut self, grant: CapsulaGranted) -> Self {
        self.grants.push(grant);
        self
    }

    /// 设置过期时间
    pub fn expires_at(mut self, expires_at: OffsetDateTime) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// 设置策略
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// 执行封包操作
    pub fn encapsulate<S: KeySign>(
        self,
        producer_key: &S,
        recipient_keys: &[(String, &dyn Key)],
    ) -> Result<Capsula1> {
        // 1. 生成胶囊ID和时间戳
        let capsule_id = self.generate_capsule_id()?;
        let created_at = OffsetDateTime::now_utc();

        // Clone values that will be moved
        let producer_clone = self.producer.clone();

        // 2. 计算数据摘要
        let digest = self.compute_digest(&self.raw_data)?;

        // 3. 生成CEK并加密数据
        let cek = self.generate_cek()?;
        let (ciphertext, aad) = self.encrypt_data(&self.raw_data, &cek, &capsule_id)?;

        // 4. 创建密钥环
        let keyring = self.create_keyring(&cek, recipient_keys)?;

        // 5. 构建胶囊结构
        let mut capsule = Capsula1 {
            header: Header {
                ver: "1.0".to_string(),
                stage: CapsulaStage::First,
                type_: self.data_type.clone(),
                id: capsule_id.clone(),
                created_at: created_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| CoreError::Other(format!("Time format error: {}", e)))?,
            },
            meta: Meta {
                producer: producer_clone,
                owner: self.owner.clone(),
                user: None,
                grants: self.grants.clone(),
                digest,
                expires_at: self
                    .expires_at
                    .map(|t| {
                        t.format(&time::format_description::well_known::Rfc3339)
                            .map_err(|e| CoreError::Other(format!("Time format error: {}", e)))
                    })
                    .transpose()?,
            },
            payload: Payload {
                ct: general_purpose::STANDARD.encode(&ciphertext),
                aad: general_purpose::STANDARD.encode(&aad),
                enc: "AES-256-GCM".to_string(),
                len: self.raw_data.len() as u64,
                external: None,
            },
            policy: self.policy.clone(),
            integrity: Integrity {
                signature: Signature {
                    alg: "Ed25519".to_string(),
                    sig: String::new(), // 临时占位
                    signer: self.producer.clone(),
                },
                watermark: None,
            },
            audit: vec![AuditEvent {
                ts: created_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| CoreError::Other(format!("Time format error: {}", e)))?,
                actor: self.producer.clone(),
                action: "create".to_string(),
                target: Some(capsule_id),
                result: "ok".to_string(),
                sig: None,
            }],
            keyring,
        };

        // 6. 签名胶囊
        capsule.integrity.signature = self.sign_capsule(&capsule, producer_key)?;

        Ok(capsule)
    }

    /// 生成胶囊ID
    fn generate_capsule_id(&self) -> Result<String> {
        let mut rng = rand::thread_rng();
        let mut id_bytes = [0u8; 16];
        rng.fill_bytes(&mut id_bytes);
        Ok(format!(
            "cid:{}",
            general_purpose::STANDARD.encode(id_bytes)
        ))
    }

    /// 计算数据摘要
    fn compute_digest(&self, data: &[u8]) -> Result<Digest> {
        let hash = sha256(data);
        let hash_str = general_purpose::STANDARD.encode(hash);

        Ok(Digest {
            alg: "SHA-256".to_string(),
            hash: hash_str,
            summary: Value::Null, // TODO: 实现ZKP摘要
        })
    }

    /// 生成内容加密密钥
    fn generate_cek(&self) -> Result<[u8; 32]> {
        let mut cek = [0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut cek);
        Ok(cek)
    }

    /// 加密数据
    fn encrypt_data(
        &self,
        data: &[u8],
        cek: &[u8; 32],
        capsule_id: &str,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // 使用胶囊ID作为AAD的一部分
        let aad = capsule_id.as_bytes().to_vec();

        // 使用AES-GCM加密
        let aes = Aes::new(cek)?;
        let ciphertext = aes.encrypt(data)?;

        Ok((ciphertext, aad))
    }

    /// 创建密钥环
    fn create_keyring(
        &self,
        cek: &[u8; 32],
        recipient_keys: &[(String, &dyn Key)],
    ) -> Result<Vec<KeyWrap>> {
        let mut keyring = Vec::new();

        for (kid, key) in recipient_keys {
            // 获取接收者的公钥
            let public_keys = key.public_keys();
            if let Some(key_agreement_key) = public_keys.key_agreement_key() {
                // TODO: 实现密钥协商和包装
                // 这里需要使用ECDH或RSA加密CEK
                let wrapped_cek = self.wrap_cek_for_key(cek, &key_agreement_key.spki_der)?;

                keyring.push(KeyWrap {
                    kid: kid.clone(),
                    alg: "RSA-OAEP".to_string(), // 或根据密钥类型选择算法
                    cek_wrapped: general_purpose::STANDARD.encode(&wrapped_cek),
                });
            }
        }

        Ok(keyring)
    }

    /// 为特定密钥包装CEK
    fn wrap_cek_for_key(&self, cek: &[u8; 32], public_key_der: &[u8]) -> Result<Vec<u8>> {
        // 使用RSA加密CEK
        let public_key = rsa::public_key_from_spki_der(public_key_der)?;
        let encrypted_cek = rsa::encrypt(&public_key, cek)?;
        Ok(encrypted_cek)
    }

    /// 签名胶囊
    fn sign_capsule<S: KeySign>(&self, capsule: &Capsula1, signer_key: &S) -> Result<Signature> {
        // 创建签名数据
        let sign_data = self.create_signature_data(capsule)?;

        // 使用私钥签名
        let signature_bytes = signer_key
            .sign(&sign_data)
            .map_err(|e| CoreError::SignatureError(format!("Signing failed: {}", e)))?;

        Ok(Signature {
            alg: "Ed25519".to_string(), // TODO: 根据密钥类型动态选择
            sig: general_purpose::STANDARD.encode(&signature_bytes),
            signer: capsule.meta.producer.clone(),
        })
    }

    /// 创建签名数据
    fn create_signature_data(&self, capsule: &Capsula1) -> Result<Vec<u8>> {
        // 按照固定顺序组织需要签名的数据
        let sign_structure = serde_json::json!({
            "header": capsule.header,
            "meta": capsule.meta,
            "payload": {
                "ct": capsule.payload.ct,
                "aad": capsule.payload.aad,
                "enc": capsule.payload.enc,
                "len": capsule.payload.len
            },
            "policy": capsule.policy
        });

        serde_json::to_vec(&sign_structure).map_err(|e| {
            CoreError::EncapsulationError(format!("Signature data creation failed: {}", e))
        })
    }
}

// Default implementation moved to protocol/capsule.rs

#[cfg(test)]
mod tests {
    use capsula_key::{Curve25519, P256Key, RsaKey};

    use super::*;

    #[test]
    fn test_capsule_builder() {
        let raw_data = b"Test medical report data".to_vec();

        let builder = CapsulaBuilder::new(raw_data, "medical.blood_test".to_string())
            .producer("Hospital A".to_string())
            .owner("Patient 001".to_string())
            .add_grant(CapsulaGranted::Read);

        // 测试基本构建功能
        assert_eq!(builder.data_type, "medical.blood_test");
        assert_eq!(builder.producer, "Hospital A");
        assert_eq!(builder.owner, "Patient 001");
        assert_eq!(builder.grants.len(), 1);
    }

    #[test]
    fn test_digest_computation() {
        let data = b"test data";
        let builder = CapsulaBuilder::new(data.to_vec(), "test".to_string());

        let digest = builder.compute_digest(data).unwrap();
        assert_eq!(digest.alg, "SHA-256");
        assert!(!digest.hash.is_empty());
    }
}
