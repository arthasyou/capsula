//! 数据胶囊解包器
//!
//! 实现1阶数据胶囊的解包功能，包括验证、解密、完整性检查等操作

use base64::{engine::general_purpose, Engine as _};
use capsula_crypto::{sha256, symmetric::aes::Aes, verify_signature, asymmetric::rsa};
use capsula_key::{Curve25519, P256Key, RsaKey};
use time::OffsetDateTime;

use crate::{
    error::{CoreError, Result},
    protocol::capsule::*,
};

/// 解包结果
pub struct DecapsulationResult {
    /// 解密后的原始数据
    pub data: Vec<u8>,
    /// 验证信息
    pub verification: VerificationInfo,
    /// 审计事件
    pub audit_event: AuditEvent,
}

/// 验证信息
#[derive(Debug)]
pub struct VerificationInfo {
    /// 签名验证结果
    pub signature_valid: bool,
    /// 完整性验证结果
    pub integrity_valid: bool,
    /// 策略验证结果
    pub policy_valid: bool,
    /// 时间验证结果
    pub time_valid: bool,
}

/// 私钥包装器，用于处理不同类型的私钥
pub enum PrivateKeyWrapper {
    Rsa(RsaKey),
    P256(P256Key),
    Curve25519(Curve25519),
}

impl PrivateKeyWrapper {
    fn decrypt_cek(&self, wrapped_cek: &[u8], algorithm: &str) -> Result<Vec<u8>> {
        match (self, algorithm) {
            (PrivateKeyWrapper::Rsa(key), "RSA-OAEP") => {
                // 使用capsula-crypto的RSA解密功能
                use capsula_key::ExportablePrivateKey;
                let private_key_der = key.to_pkcs8_der()
                    .map_err(|e| CoreError::DecapsulationError(format!("Failed to export RSA private key: {}", e)))?;
                let crypto_key = rsa::Rsa::from_pkcs8_der(&private_key_der)
                    .map_err(|e| CoreError::DecapsulationError(format!("Failed to import RSA key for decryption: {}", e)))?;
                let plaintext = crypto_key.decrypt(wrapped_cek)
                    .map_err(|e| CoreError::DecapsulationError(format!("RSA decryption failed: {}", e)))?;
                Ok(plaintext)
            }
            _ => Err(CoreError::DecapsulationError(format!(
                "Unsupported key type or algorithm: {:?}/{}",
                self.key_type(),
                algorithm
            ))),
        }
    }

    fn key_type(&self) -> &'static str {
        match self {
            PrivateKeyWrapper::Rsa(_) => "RSA",
            PrivateKeyWrapper::P256(_) => "P256",
            PrivateKeyWrapper::Curve25519(_) => "Curve25519",
        }
    }
}

/// 数据胶囊解包器
pub struct CapsuleDecryptor {
    /// 私钥用于解密CEK
    private_key: PrivateKeyWrapper,
    /// 用户身份标识
    user_id: String,
    /// 验证用的公钥 (Producer的公钥)
    producer_public_key: Option<Vec<u8>>,
}

impl CapsuleDecryptor {
    /// 创建新的解包器
    pub fn new_rsa(private_key: RsaKey, user_id: String) -> Self {
        Self {
            private_key: PrivateKeyWrapper::Rsa(private_key),
            user_id,
            producer_public_key: None,
        }
    }

    /// 创建新的解包器（P256）
    pub fn new_p256(private_key: P256Key, user_id: String) -> Self {
        Self {
            private_key: PrivateKeyWrapper::P256(private_key),
            user_id,
            producer_public_key: None,
        }
    }

    /// 创建新的解包器（Curve25519）
    pub fn new_curve25519(private_key: Curve25519, user_id: String) -> Self {
        Self {
            private_key: PrivateKeyWrapper::Curve25519(private_key),
            user_id,
            producer_public_key: None,
        }
    }

    /// 设置生产者公钥用于验证签名
    pub fn with_producer_public_key(mut self, public_key: Vec<u8>) -> Self {
        self.producer_public_key = Some(public_key);
        self
    }

    /// 执行解包操作
    pub fn decapsulate(&self, capsule: &Capsula1) -> Result<DecapsulationResult> {
        // 1. 结构校验
        self.validate_structure(capsule)?;

        // 2. 验证签名
        let signature_valid = self.verify_signature(capsule)?;

        // 3. 策略检查
        let policy_valid = self.check_policy(capsule)?;

        // 4. 时间验证
        let time_valid = self.validate_time(capsule)?;

        // 5. 解密CEK
        let cek = self.decrypt_cek(capsule)?;

        // 6. 解密数据
        let decrypted_data = self.decrypt_payload(capsule, &cek)?;

        // 7. 完整性验证
        let integrity_valid = self.verify_integrity(capsule, &decrypted_data)?;

        // 8. 生成审计事件
        let audit_event = self.create_audit_event(capsule)?;

        Ok(DecapsulationResult {
            data: decrypted_data,
            verification: VerificationInfo {
                signature_valid,
                integrity_valid,
                policy_valid,
                time_valid,
            },
            audit_event,
        })
    }

    /// 验证胶囊结构
    fn validate_structure(&self, capsule: &Capsula1) -> Result<()> {
        // 检查版本
        if capsule.header.ver != "1.0" {
            return Err(CoreError::FormatError("Unsupported version".to_string()));
        }

        // 检查必要字段
        if capsule.header.id.is_empty() || capsule.meta.producer.is_empty() {
            return Err(CoreError::FormatError(
                "Missing required fields".to_string(),
            ));
        }

        // 检查载荷
        if capsule.payload.ct.is_empty() || capsule.payload.enc != "AES-256-GCM" {
            return Err(CoreError::FormatError("Invalid payload format".to_string()));
        }

        Ok(())
    }

    /// 验证数字签名
    fn verify_signature(&self, capsule: &Capsula1) -> Result<bool> {
        if let Some(producer_pub_key) = &self.producer_public_key {
            // 重构签名数据
            let sign_data = self.create_signature_data(capsule)?;

            // 解码签名
            let signature_bytes =
                general_purpose::STANDARD.decode(&capsule.integrity.signature.sig)?;

            // 验证签名
            let valid = verify_signature(producer_pub_key, &sign_data, &signature_bytes)?;
            Ok(valid)
        } else {
            // 如果没有提供公钥，跳过签名验证
            Ok(true)
        }
    }

    /// 检查访问策略
    fn check_policy(&self, capsule: &Capsula1) -> Result<bool> {
        // 简单规则检查
        for rule in &capsule.policy.simple_rules {
            if !self.evaluate_simple_rule(rule, capsule)? {
                return Ok(false);
            }
        }

        // TODO: X509证书检查
        // TODO: OPA/Rego策略评估

        Ok(true)
    }

    /// 评估简单规则
    fn evaluate_simple_rule(&self, rule: &str, _capsule: &Capsula1) -> Result<bool> {
        // 简单实现，支持基本的字符串匹配
        if let Some(required_user) = rule.strip_prefix("user:") {
            Ok(self.user_id == required_user)
        } else if rule == "allow_all" {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 验证时间限制
    fn validate_time(&self, capsule: &Capsula1) -> Result<bool> {
        if let Some(expires_at_str) = &capsule.meta.expires_at {
            let expires_at = OffsetDateTime::parse(
                expires_at_str,
                &time::format_description::well_known::Rfc3339,
            )?;
            let now = OffsetDateTime::now_utc();
            Ok(now <= expires_at)
        } else {
            Ok(true)
        }
    }

    /// 解密CEK
    fn decrypt_cek(&self, capsule: &Capsula1) -> Result<Vec<u8>> {
        // 在keyring中查找适合的密钥
        for keywrap in &capsule.keyring {
            if keywrap.kid == self.user_id {
                // 解码包装的CEK
                let wrapped_cek = general_purpose::STANDARD.decode(&keywrap.cek_wrapped)?;

                // 使用私钥解密CEK
                let cek = self.unwrap_cek(&wrapped_cek, &keywrap.alg)?;
                return Ok(cek);
            }
        }

        Err(CoreError::DecapsulationError(
            format!("No suitable key found in keyring for user_id '{}'", self.user_id),
        ))
    }

    /// 解包CEK
    fn unwrap_cek(&self, wrapped_cek: &[u8], algorithm: &str) -> Result<Vec<u8>> {
        self.private_key.decrypt_cek(wrapped_cek, algorithm)
    }

    /// 解密载荷
    fn decrypt_payload(&self, capsule: &Capsula1, cek: &[u8]) -> Result<Vec<u8>> {
        // 解码密文
        let ciphertext = general_purpose::STANDARD.decode(&capsule.payload.ct)?;

        // 使用CEK解密
        if cek.len() == 32 {
            let mut cek_array = [0u8; 32];
            cek_array.copy_from_slice(cek);

            let aes = Aes::new(&cek_array)?;
            let plaintext = aes.decrypt(&ciphertext)?;
            Ok(plaintext)
        } else {
            Err(CoreError::DecapsulationError(
                "Invalid CEK length".to_string(),
            ))
        }
    }

    /// 验证数据完整性
    fn verify_integrity(&self, capsule: &Capsula1, decrypted_data: &[u8]) -> Result<bool> {
        // 重新计算摘要
        let computed_hash = sha256(decrypted_data);
        let computed_hash_str = general_purpose::STANDARD.encode(computed_hash);

        // 与存储的摘要比较
        Ok(computed_hash_str == capsule.meta.digest.hash)
    }

    /// 创建审计事件
    fn create_audit_event(&self, capsule: &Capsula1) -> Result<AuditEvent> {
        let now = OffsetDateTime::now_utc();

        Ok(AuditEvent {
            ts: now
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| CoreError::Other(format!("Time format error: {}", e)))?,
            actor: self.user_id.clone(),
            action: "decrypt".to_string(),
            target: Some(capsule.header.id.clone()),
            result: "ok".to_string(),
            sig: None,
        })
    }

    /// 创建签名数据 (与封包器中的实现相同)
    fn create_signature_data(&self, capsule: &Capsula1) -> Result<Vec<u8>> {
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
            CoreError::DecapsulationError(format!("Signature data creation failed: {}", e))
        })
    }
}

#[cfg(test)]
mod tests {
    use capsula_key::RsaKey;

    use super::*;

    #[test]
    fn test_structure_validation() {
        let rsa_key = RsaKey::generate_2048().unwrap();
        let decryptor = CapsuleDecryptor::new_rsa(rsa_key, "test_user".to_string());

        // 创建一个基本的胶囊用于测试
        let capsule = create_test_capsule();

        assert!(decryptor.validate_structure(&capsule).is_ok());
    }

    #[test]
    fn test_time_validation() {
        let rsa_key = RsaKey::generate_2048().unwrap();
        let decryptor = CapsuleDecryptor::new_rsa(rsa_key, "test_user".to_string());

        let mut capsule = create_test_capsule();

        // 设置未来的过期时间
        let future_time = OffsetDateTime::now_utc() + time::Duration::hours(1);
        capsule.meta.expires_at = Some(
            future_time
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        );

        assert!(decryptor.validate_time(&capsule).unwrap());

        // 设置过去的过期时间
        let past_time = OffsetDateTime::now_utc() - time::Duration::hours(1);
        capsule.meta.expires_at = Some(
            past_time
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        );

        assert!(!decryptor.validate_time(&capsule).unwrap());
    }

    fn create_test_capsule() -> Capsula1 {
        use crate::protocol::types::{CapsulaGranted, CapsulaStage};

        Capsula1 {
            header: Header {
                ver: "1.0".to_string(),
                stage: CapsulaStage::First,
                type_: "test".to_string(),
                id: "cid:test123".to_string(),
                created_at: OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap(),
            },
            meta: Meta {
                producer: "test_producer".to_string(),
                owner: "test_owner".to_string(),
                user: None,
                grants: vec![CapsulaGranted::Read],
                digest: Digest {
                    alg: "SHA-256".to_string(),
                    hash: "test_hash".to_string(),
                    summary: serde_json::Value::Null,
                },
                expires_at: None,
            },
            payload: Payload {
                ct: "test_ct".to_string(),
                aad: "test_aad".to_string(),
                enc: "AES-256-GCM".to_string(),
                len: 100,
                external: None,
            },
            policy: Policy::default(),
            integrity: Integrity {
                signature: Signature {
                    alg: "Ed25519".to_string(),
                    sig: "test_sig".to_string(),
                    signer: "test_producer".to_string(),
                },
                watermark: None,
            },
            audit: Vec::new(),
            keyring: Vec::new(),
        }
    }
}
