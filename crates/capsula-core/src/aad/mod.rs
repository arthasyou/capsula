use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    capsule::{CapsuleHeader, CapsulePayload, PolicyControl},
    integrity::digest::Digest as CapsulaDigest,
    CoreError, Result,
};

/// AAD (Additional Authenticated Data) binding mechanism
///
/// This module implements the core security requirement from the whitepaper:
/// "AAD绑定机制用于防止组件替换攻击"
///
/// AAD binds together all capsule components to ensure integrity and
/// prevent malicious substitution of individual parts.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AadContext {
    /// 胶囊头部摘要
    pub header_digest: CapsulaDigest,
    /// 策略控制摘要
    pub policy_digest: CapsulaDigest,
    /// 载荷摘要
    pub payload_digest: CapsulaDigest,
    /// 密钥环摘要 (可选)
    pub keyring_digest: Option<CapsulaDigest>,
    /// 绑定时间戳
    pub binding_timestamp: String,
    /// 绑定版本
    pub binding_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AadBinding {
    /// AAD上下文
    pub context: AadContext,
    /// 组合摘要 (所有组件的哈希)
    pub composite_digest: CapsulaDigest,
    /// AAD字符串 (用于AEAD加密)
    pub aad_string: String,
}

/// AAD绑定器 - 负责生成和验证AAD绑定
pub struct AadBinder {
    binding_version: String,
}

impl Default for AadBinder {
    fn default() -> Self {
        Self::new()
    }
}

impl AadBinder {
    pub fn new() -> Self {
        Self {
            binding_version: "1.0".to_string(),
        }
    }

    /// 为胶囊组件创建AAD绑定
    ///
    /// 这是防止组件替换攻击的核心机制
    pub fn create_binding(
        &self,
        header: &CapsuleHeader,
        policy: &PolicyControl,
        payload: &CapsulePayload,
        keyring_data: Option<&[u8]>,
    ) -> Result<AadBinding> {
        // 计算各组件的摘要
        let header_digest = self.compute_header_digest(header)?;
        let policy_digest = self.compute_policy_digest(policy)?;
        let payload_digest = self.compute_payload_digest(payload)?;
        let keyring_digest = if let Some(data) = keyring_data {
            Some(self.compute_data_digest(data)?)
        } else {
            None
        };

        // 创建AAD上下文
        let context = AadContext {
            header_digest,
            policy_digest,
            payload_digest,
            keyring_digest,
            binding_timestamp: chrono::Utc::now().to_rfc3339(),
            binding_version: self.binding_version.clone(),
        };

        // 计算组合摘要
        let composite_digest = self.compute_composite_digest(&context)?;

        // 生成AAD字符串
        let aad_string = self.generate_aad_string(&context, &composite_digest)?;

        Ok(AadBinding {
            context,
            composite_digest,
            aad_string,
        })
    }

    /// 验证AAD绑定的完整性
    ///
    /// 确保胶囊组件未被篡改或替换
    pub fn verify_binding(
        &self,
        binding: &AadBinding,
        header: &CapsuleHeader,
        policy: &PolicyControl,
        payload: &CapsulePayload,
        keyring_data: Option<&[u8]>,
    ) -> Result<bool> {
        // 重新计算各组件摘要
        let header_digest = self.compute_header_digest(header)?;
        let policy_digest = self.compute_policy_digest(policy)?;
        let payload_digest = self.compute_payload_digest(payload)?;
        let keyring_digest = if let Some(data) = keyring_data {
            Some(self.compute_data_digest(data)?)
        } else {
            None
        };

        // 验证各组件摘要
        if binding.context.header_digest.hash != header_digest.hash {
            return Ok(false);
        }
        if binding.context.policy_digest.hash != policy_digest.hash {
            return Ok(false);
        }
        if binding.context.payload_digest.hash != payload_digest.hash {
            return Ok(false);
        }
        if binding.context.keyring_digest.as_ref().map(|d| &d.hash)
            != keyring_digest.as_ref().map(|d| &d.hash)
        {
            return Ok(false);
        }

        // 验证组合摘要
        let expected_composite = self.compute_composite_digest(&binding.context)?;
        if binding.composite_digest.hash != expected_composite.hash {
            return Ok(false);
        }

        // 验证AAD字符串
        let expected_aad = self.generate_aad_string(&binding.context, &expected_composite)?;
        if binding.aad_string != expected_aad {
            return Ok(false);
        }

        Ok(true)
    }

    /// 从AAD绑定更新胶囊组件
    ///
    /// 当组件发生变化时，需要重新绑定
    pub fn update_binding(
        &self,
        mut binding: AadBinding,
        header: &CapsuleHeader,
        policy: &PolicyControl,
        payload: &CapsulePayload,
        keyring_data: Option<&[u8]>,
    ) -> Result<AadBinding> {
        // 重新计算所有组件摘要
        binding.context.header_digest = self.compute_header_digest(header)?;
        binding.context.policy_digest = self.compute_policy_digest(policy)?;
        binding.context.payload_digest = self.compute_payload_digest(payload)?;
        binding.context.keyring_digest = if let Some(data) = keyring_data {
            Some(self.compute_data_digest(data)?)
        } else {
            None
        };

        // 更新时间戳
        binding.context.binding_timestamp = chrono::Utc::now().to_rfc3339();

        // 重新计算组合摘要和AAD字符串
        binding.composite_digest = self.compute_composite_digest(&binding.context)?;
        binding.aad_string =
            self.generate_aad_string(&binding.context, &binding.composite_digest)?;

        Ok(binding)
    }

    /// 获取用于AEAD加密的AAD数据
    pub fn get_aead_aad(&self, binding: &AadBinding) -> Vec<u8> {
        binding.aad_string.as_bytes().to_vec()
    }

    // 私有辅助方法

    fn compute_header_digest(&self, header: &CapsuleHeader) -> Result<CapsulaDigest> {
        let serialized = serde_json::to_vec(header)
            .map_err(|e| CoreError::DataError(format!("Failed to serialize header: {}", e)))?;
        self.compute_data_digest(&serialized)
    }

    fn compute_policy_digest(&self, policy: &PolicyControl) -> Result<CapsulaDigest> {
        let serialized = serde_json::to_vec(policy)
            .map_err(|e| CoreError::DataError(format!("Failed to serialize policy: {}", e)))?;
        self.compute_data_digest(&serialized)
    }

    fn compute_payload_digest(&self, payload: &CapsulePayload) -> Result<CapsulaDigest> {
        let serialized = serde_json::to_vec(payload)
            .map_err(|e| CoreError::DataError(format!("Failed to serialize payload: {}", e)))?;
        self.compute_data_digest(&serialized)
    }

    fn compute_data_digest(&self, data: &[u8]) -> Result<CapsulaDigest> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        Ok(CapsulaDigest {
            alg: "SHA-256".to_string(),
            hash: hex::encode(hash),
        })
    }

    fn compute_composite_digest(&self, context: &AadContext) -> Result<CapsulaDigest> {
        let mut hasher = Sha256::new();

        // 按固定顺序添加所有摘要
        hasher.update(context.header_digest.hash.as_bytes());
        hasher.update(context.policy_digest.hash.as_bytes());
        hasher.update(context.payload_digest.hash.as_bytes());

        if let Some(ref keyring_digest) = context.keyring_digest {
            hasher.update(keyring_digest.hash.as_bytes());
        }

        // 添加元数据
        hasher.update(context.binding_timestamp.as_bytes());
        hasher.update(context.binding_version.as_bytes());

        let hash = hasher.finalize();

        Ok(CapsulaDigest {
            alg: "SHA-256".to_string(),
            hash: hex::encode(hash),
        })
    }

    fn generate_aad_string(
        &self,
        context: &AadContext,
        composite: &CapsulaDigest,
    ) -> Result<String> {
        // 创建结构化的AAD字符串，用于AEAD加密
        let aad_data = serde_json::json!({
            "binding_version": context.binding_version,
            "timestamp": context.binding_timestamp,
            "header_hash": context.header_digest.hash,
            "policy_hash": context.policy_digest.hash,
            "payload_hash": context.payload_digest.hash,
            "keyring_hash": context.keyring_digest.as_ref().map(|d| &d.hash),
            "composite_hash": composite.hash
        });

        serde_json::to_string(&aad_data)
            .map_err(|e| CoreError::DataError(format!("Failed to generate AAD string: {}", e)))
    }
}

/// AAD绑定验证器 - 用于批量验证和审计
pub struct AadValidator {
    binder: AadBinder,
}

impl AadValidator {
    pub fn new() -> Self {
        Self {
            binder: AadBinder::new(),
        }
    }

    /// 验证胶囊的完整AAD绑定
    pub fn validate_capsule_aad(
        &self,
        aad_string: &str,
        header: &CapsuleHeader,
        policy: &PolicyControl,
        payload: &CapsulePayload,
        keyring_data: Option<&[u8]>,
    ) -> Result<AadValidationResult> {
        // 解析AAD绑定
        let binding: AadBinding = serde_json::from_str(aad_string)
            .map_err(|e| CoreError::DataError(format!("Invalid AAD format: {}", e)))?;

        // 验证绑定
        let is_valid =
            self.binder
                .verify_binding(&binding, header, policy, payload, keyring_data)?;

        let result = AadValidationResult {
            is_valid,
            binding_version: binding.context.binding_version.clone(),
            binding_timestamp: binding.context.binding_timestamp.clone(),
            composite_hash: binding.composite_digest.hash.clone(),
            validation_timestamp: chrono::Utc::now().to_rfc3339(),
            details: if is_valid {
                "All components verified successfully".to_string()
            } else {
                "Component verification failed - possible tampering detected".to_string()
            },
        };

        Ok(result)
    }

    /// 批量验证多个胶囊的AAD绑定
    pub fn batch_validate(
        &self,
        validations: Vec<BatchValidationItem>,
    ) -> Vec<AadValidationResult> {
        validations
            .into_iter()
            .map(|item| {
                self.validate_capsule_aad(
                    &item.aad_string,
                    &item.header,
                    &item.policy,
                    &item.payload,
                    item.keyring_data.as_deref(),
                )
                .unwrap_or_else(|e| AadValidationResult {
                    is_valid: false,
                    binding_version: "unknown".to_string(),
                    binding_timestamp: "unknown".to_string(),
                    composite_hash: "unknown".to_string(),
                    validation_timestamp: chrono::Utc::now().to_rfc3339(),
                    details: format!("Validation error: {}", e),
                })
            })
            .collect()
    }
}

impl Default for AadValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AadValidationResult {
    pub is_valid: bool,
    pub binding_version: String,
    pub binding_timestamp: String,
    pub composite_hash: String,
    pub validation_timestamp: String,
    pub details: String,
}

#[derive(Debug)]
pub struct BatchValidationItem {
    pub aad_string: String,
    pub header: CapsuleHeader,
    pub policy: PolicyControl,
    pub payload: CapsulePayload,
    pub keyring_data: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        capsule::{Cap0, CapsuleHeader, CapsulePayload, PolicyControl},
        types::{CapsulaStage, EncAlg},
    };

    fn create_test_header() -> CapsuleHeader {
        CapsuleHeader {
            id: "cid:test123".to_string(),
            version: "1.0".to_string(),
            stage: CapsulaStage::First,
            content_type: "medical.test".to_string(),
            created_at: "2023-10-01T00:00:00Z".to_string(),
            creator: Some("test-author".to_string()),
            metadata: Some(HashMap::new()),
        }
    }

    fn create_test_policy() -> PolicyControl {
        PolicyControl {
            policy_uri: "policy://test".to_string(),
            permissions: vec!["read".to_string()],
            constraints: std::collections::HashMap::new(),
        }
    }

    fn create_test_payload() -> CapsulePayload {
        use crate::integrity::digest::Digest;

        CapsulePayload::Cap0(Cap0 {
            origin: crate::block::SealedBlock {
                ciphertext: crate::block::ciphertext::Ciphertext {
                    aad: "dGVzdA==".to_string(), // base64("test")
                    enc: EncAlg::Aes256Gcm,
                    nonce: "MTIzNDU2Nzg5MA==".to_string(), // base64("1234567890")
                    len: 4,
                    dek_id: "dek:test123".to_string(),
                    storage: crate::block::ciphertext::CipherStorage::Inline {
                        ct_b64: "dGVzdGRhdGE=".to_string(), // base64("testdata")
                        ciphertext_len: Some(4),
                        ciphertext_digest: Some(Digest {
                            alg: "SHA-256".to_string(),
                            hash: "test-hash".to_string(),
                        }),
                    },
                },
                proof: crate::block::proof::AuthorProof {
                    subject: Digest {
                        alg: "SHA-256".to_string(),
                        hash: "subject-hash".to_string(),
                    },
                    schema_hash: Some("schema-hash".to_string()),
                    issued_at: Some("2023-10-01T00:00:00Z".to_string()),
                    signature: crate::integrity::signature::Signature {
                        alg: "Ed25519".to_string(),
                        sig: "c2lnbmF0dXJl".to_string(), // base64("signature")
                        author_hint: "test-author".to_string(),
                        cert_hint: Some("cert-hint".to_string()),
                    },
                },
                content_type: crate::types::ContentType::Json,
            },
            origin_text: None,
        })
    }

    #[test]
    fn test_aad_binding_creation() {
        let binder = AadBinder::new();
        let header = create_test_header();
        let policy = create_test_policy();
        let payload = create_test_payload();

        let binding = binder
            .create_binding(&header, &policy, &payload, None)
            .unwrap();

        assert_eq!(binding.context.binding_version, "1.0");
        assert!(!binding.aad_string.is_empty());
        assert!(!binding.composite_digest.hash.is_empty());
    }

    #[test]
    fn test_aad_binding_verification() {
        let binder = AadBinder::new();
        let header = create_test_header();
        let policy = create_test_policy();
        let payload = create_test_payload();

        let binding = binder
            .create_binding(&header, &policy, &payload, None)
            .unwrap();
        let is_valid = binder
            .verify_binding(&binding, &header, &policy, &payload, None)
            .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_aad_binding_tamper_detection() {
        let binder = AadBinder::new();
        let header = create_test_header();
        let policy = create_test_policy();
        let payload = create_test_payload();

        let binding = binder
            .create_binding(&header, &policy, &payload, None)
            .unwrap();

        // Tamper with header
        let mut tampered_header = header.clone();
        tampered_header.version = "2.0".to_string();

        let is_valid = binder
            .verify_binding(&binding, &tampered_header, &policy, &payload, None)
            .unwrap();

        assert!(!is_valid);
    }

    #[test]
    fn test_aad_binding_update() {
        let binder = AadBinder::new();
        let header = create_test_header();
        let policy = create_test_policy();
        let payload = create_test_payload();

        let binding = binder
            .create_binding(&header, &policy, &payload, None)
            .unwrap();
        let original_hash = binding.composite_digest.hash.clone();

        // Update with modified header
        let mut new_header = header.clone();
        new_header.version = "2.0".to_string();

        let updated_binding = binder
            .update_binding(binding, &new_header, &policy, &payload, None)
            .unwrap();

        // Hash should change
        assert_ne!(original_hash, updated_binding.composite_digest.hash);

        // New binding should be valid
        let is_valid = binder
            .verify_binding(&updated_binding, &new_header, &policy, &payload, None)
            .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_aad_validator() {
        let validator = AadValidator::new();
        let header = create_test_header();
        let policy = create_test_policy();
        let payload = create_test_payload();

        let binder = AadBinder::new();
        let binding = binder
            .create_binding(&header, &policy, &payload, None)
            .unwrap();
        let aad_string = serde_json::to_string(&binding).unwrap();

        let result = validator
            .validate_capsule_aad(&aad_string, &header, &policy, &payload, None)
            .unwrap();

        assert!(result.is_valid);
        assert_eq!(result.binding_version, "1.0");
    }

    #[test]
    fn test_aead_aad_generation() {
        let binder = AadBinder::new();
        let header = create_test_header();
        let policy = create_test_policy();
        let payload = create_test_payload();

        let binding = binder
            .create_binding(&header, &policy, &payload, None)
            .unwrap();
        let aead_aad = binder.get_aead_aad(&binding);

        assert!(!aead_aad.is_empty());
        assert_eq!(aead_aad, binding.aad_string.as_bytes());
    }
}
