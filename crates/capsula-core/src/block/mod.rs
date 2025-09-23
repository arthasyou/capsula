pub mod ciphertext;
pub mod proof;

use capsula_crypto::{
    base64, decrypt_aead, encrypt_aead, encrypt_dek_with_algorithm, generate_id, generate_key,
    generate_nonce, parse_algorithm_from_spki, sha256_hex,
};
use capsula_key::key::SigningKey;
use pkcs8::{der::Decode, spki::SubjectPublicKeyInfoRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use time::OffsetDateTime;

use crate::{
    block::{
        ciphertext::{CipherStorage, Ciphertext},
        proof::AuthorProof,
    },
    error::{CoreError as Error, Result},
    integrity::{digest::Digest, signature::Signature},
    keyring::{KeyWrap, Keyring},
    state::{CapsuleState, StateTransitionError, UploadMeta},
    ContentType, EncAlg,
};

// --- 最小可验证封装单元：密文 + 单一作者证明 + 状态管理 ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlock {
    pub ciphertext: Ciphertext,    // 密文主体（机密性/完整性 by AEAD）
    pub proof: AuthorProof,        // 唯一作者的来源/不可抵赖证明
    pub content_type: ContentType, // 明文内容类型（MIME）
    pub state: CapsuleState,       // 胶囊状态（支持异步封装）
}

impl SealedBlock {
    /// 封装数据：把明文加密并签名，生成一个 SealedBlock
    pub fn seal<S: SigningKey>(
        plaintext: &[u8],            // 明文字节
        content_type: ContentType,   // 明文类型 (MIME)
        aad: &[u8],                  // 额外认证数据（外层上下文）
        keyring: &mut Keyring,       // 密钥环用于存储加密的DEK
        recipient_public_key: &[u8], // 所有者公钥（SPKI DER格式）
        signing_key: &S,             // 作者私钥（用于签名）
    ) -> Result<(Self, String)> {
        // 1. 生成 DEK 和 DEK ID
        let dek = generate_key();
        let dek_id = generate_id("dek");

        // 2. 解析SPKI DER获取算法和公钥
        let spki = SubjectPublicKeyInfoRef::from_der(recipient_public_key)
            .map_err(|e| Error::DataError(format!("Invalid SPKI DER: {}", e)))?;

        let algorithm = parse_algorithm_from_spki(&spki.algorithm)
            .map_err(|e| Error::DataError(format!("Algorithm parsing failed: {}", e)))?;

        // 3. 根据算法加密DEK
        let (encrypted_dek, algorithm_name) =
            encrypt_dek_with_algorithm(&dek, algorithm, recipient_public_key)
                .map_err(|e| Error::DataError(format!("DEK encryption failed: {}", e)))?;

        let cek_wrapped = base64::encode(encrypted_dek);

        // 4. 计算接收者密钥ID（使用公钥的SHA-256哈希）
        let recipient_key_id = Self::compute_public_key_id(recipient_public_key)?;

        // 5. 创建KeyWrap并添加到keyring
        let key_wrap = KeyWrap::new(recipient_key_id, algorithm_name, cek_wrapped);
        keyring.insert(dek_id.clone(), key_wrap);

        // 4. 生成随机 nonce (12 bytes for AES-256-GCM)
        let nonce_bytes = generate_nonce();
        let nonce = base64::encode(nonce_bytes);

        // 3. 使用 DEK 进行 AEAD 加密
        let ciphertext_b64 = encrypt_aead(plaintext, &dek, &nonce_bytes, aad)
            .map_err(|e| Error::DataError(format!("Encryption failed: {}", e)))?;

        // 3. 计算明文摘要
        let digest = Self::compute_digest(plaintext)?;

        // 4. 创建待签名的数据结构
        let signing_data = Self::prepare_signing_data(&digest)?;

        // 5. 使用签名密钥进行签名
        let signature_bytes = signing_key.sign(&signing_data)?;
        let signature_b64 = base64::encode(signature_bytes);

        // 6. 获取签名者信息
        let author_hint = signing_key.key_id_hex();

        // 7. 组装结构
        let block = Ciphertext {
            aad: base64::encode(aad),
            enc: EncAlg::Aes256Gcm,
            nonce,
            len: plaintext.len() as u64,
            dek_id: dek_id.clone(),
            storage: CipherStorage::Inline {
                ct_b64: ciphertext_b64.clone(),
                ciphertext_len: Some(ciphertext_b64.len() as u64),
                ciphertext_digest: None,
            },
        };

        let signature = Signature {
            alg: "Ed25519".to_string(), // 假设使用 Ed25519
            sig: signature_b64,
            author_hint,
            cert_hint: None,
        };

        let proof = AuthorProof {
            subject: digest,
            schema_hash: None,
            issued_at: Some(
                OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap(),
            ),
            signature,
        };

        // 传统的同步封装，直接标记为Completed状态
        let state = CapsuleState::Completed {
            final_uri: match &block.storage {
                CipherStorage::Inline { .. } => "inline://encrypted-data".to_string(),
                CipherStorage::External { uri, .. } => uri.clone(),
            },
            uploaded_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            verification: None,
        };

        Ok((
            SealedBlock {
                ciphertext: block,
                proof,
                content_type,
                state,
            },
            dek_id,
        ))
    }

    /// 解封数据：从keyring解密DEK，然后解密数据，返回明文
    pub fn unseal<T: capsula_key::key::KeyEncDec>(
        &self,
        keyring: &Keyring,
        decryption_key: &T,
    ) -> Result<Vec<u8>> {
        // 1. 从keyring获取加密的DEK
        let key_wrap = keyring.get(&self.ciphertext.dek_id).ok_or_else(|| {
            Error::DataError(format!(
                "DEK not found in keyring: {}",
                self.ciphertext.dek_id
            ))
        })?;

        // 2. 解码base64编码的加密DEK
        let encrypted_dek = base64::decode(&key_wrap.cek_wrapped)
            .map_err(|e| Error::DataError(format!("Failed to decode encrypted DEK: {}", e)))?;

        // 3. 使用私钥解密DEK
        let dek = decryption_key.decrypt(&encrypted_dek)?;

        // 4. 解码 nonce 和 AAD
        let nonce_vec = base64::decode(&self.ciphertext.nonce)
            .map_err(|e| Error::DataError(format!("Base64 decode error: {}", e)))?;
        let aad = base64::decode(&self.ciphertext.aad)
            .map_err(|e| Error::DataError(format!("Base64 decode error: {}", e)))?;

        if nonce_vec.len() != 12 {
            return Err(Error::DataError("Invalid nonce length".to_string()));
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce_vec);

        // 5. 解密数据
        let plaintext = match &self.state {
            // 如果是Pending状态，直接使用状态中存储的密文数据
            CapsuleState::Pending {
                ciphertext_data, ..
            } => {
                // 将字节数据转换为base64，然后使用现有的decrypt_aead函数
                let ciphertext_b64 = base64::encode(ciphertext_data);
                decrypt_aead(&ciphertext_b64, &dek, &nonce_bytes, &aad)
                    .map_err(|e| Error::DataError(format!("Decryption failed: {}", e)))?
            }
            // 其他状态，尝试从ciphertext获取
            _ => {
                // 首先尝试从ciphertext直接获取（适用于Inline存储）
                match self.ciphertext.get_ciphertext_b64() {
                    Ok(ciphertext_b64) => decrypt_aead(ciphertext_b64, &dek, &nonce_bytes, &aad)
                        .map_err(|e| Error::DataError(format!("Decryption failed: {}", e)))?,
                    Err(_) => {
                        // 对于External存储，在没有真实存储后端的情况下，
                        // 我们需要特殊处理。目前这是一个测试限制。
                        //
                        // 在生产环境中，这里应该：
                        // 1. 从URI解析存储后端类型
                        // 2. 使用相应的存储客户端下载密文
                        // 3. 解密并返回明文
                        //
                        // 现在我们返回一个更友好的错误信息
                        return Err(Error::DataError(format!(
                            "Cannot decrypt: External storage at '{}' requires a storage backend \
                             implementation. This is expected for current testing without real S3 \
                             backend.",
                            match &self.ciphertext.storage {
                                CipherStorage::External { uri, .. } => uri,
                                _ => "unknown",
                            }
                        )));
                    }
                }
            }
        };

        // 6. 验证长度
        if plaintext.len() != self.ciphertext.len as usize {
            return Err(Error::DataError("Decrypted length mismatch".to_string()));
        }

        // 7. 验证摘要
        let computed_digest = Self::compute_digest(&plaintext)?;
        if computed_digest.hash != self.proof.subject.hash {
            return Err(Error::IntegrityError(
                "Digest verification failed".to_string(),
            ));
        }

        // 8. TODO: 验证签名 - 需要获取签名者的公钥
        // 这里暂时跳过签名验证，在实际应用中需要从证书存储或PKI中获取公钥

        Ok(plaintext)
    }

    /// 计算公钥ID（使用公钥的SHA-256哈希）
    fn compute_public_key_id(public_key: &[u8]) -> Result<String> {
        Ok(sha256_hex(public_key))
    }

    /// 计算明文的SHA-256摘要
    fn compute_digest(plaintext: &[u8]) -> Result<Digest> {
        let mut hasher = Sha256::new();
        hasher.update(plaintext);
        let hash_bytes = hasher.finalize();
        let hash = base64::encode(hash_bytes);

        Ok(Digest {
            alg: "SHA-256".to_string(),
            hash,
        })
    }

    /// 准备用于签名的数据
    fn prepare_signing_data(digest: &Digest) -> Result<Vec<u8>> {
        let json = serde_json::to_string(digest).map_err(|e| Error::JsonError(e))?;
        Ok(json.into_bytes())
    }

    /// 异步封装：创建Pending状态的胶囊，准备上传
    pub fn seal_pending<S: SigningKey>(
        plaintext: &[u8],
        content_type: ContentType,
        placeholder_uri: String, // 占位符URI模板，如 "s3://bucket/data-{hash}"
        aad: &[u8],
        keyring: &mut Keyring,
        recipient_public_key: &[u8],
        signing_key: &S,
    ) -> Result<(Self, String)> {
        // 1. 执行加密和签名（与seal方法相同的流程）
        let dek = generate_key();
        let dek_id = generate_id("dek");

        let spki = SubjectPublicKeyInfoRef::from_der(recipient_public_key)
            .map_err(|e| Error::DataError(format!("Invalid SPKI DER: {}", e)))?;

        let algorithm = parse_algorithm_from_spki(&spki.algorithm)
            .map_err(|e| Error::DataError(format!("Algorithm parsing failed: {}", e)))?;

        let (encrypted_dek, algorithm_name) =
            encrypt_dek_with_algorithm(&dek, algorithm, recipient_public_key)
                .map_err(|e| Error::DataError(format!("DEK encryption failed: {}", e)))?;

        let cek_wrapped = base64::encode(encrypted_dek);
        let recipient_key_id = Self::compute_public_key_id(recipient_public_key)?;
        let key_wrap = KeyWrap::new(recipient_key_id, algorithm_name, cek_wrapped);
        keyring.insert(dek_id.clone(), key_wrap);

        let nonce_bytes = generate_nonce();
        let nonce = base64::encode(nonce_bytes);

        let ciphertext_b64 = encrypt_aead(plaintext, &dek, &nonce_bytes, aad)
            .map_err(|e| Error::DataError(format!("Encryption failed: {}", e)))?;

        let digest = Self::compute_digest(plaintext)?;
        let signing_data = Self::prepare_signing_data(&digest)?;
        let signature_bytes = signing_key.sign(&signing_data)?;
        let signature_b64 = base64::encode(signature_bytes);
        let author_hint = signing_key.key_id_hex();

        // 2. 准备密文数据用于上传
        let ciphertext_bytes = base64::decode(&ciphertext_b64).map_err(|e| {
            Error::DataError(format!("Failed to decode ciphertext for upload: {}", e))
        })?;

        // 3. 计算内容哈希（用于生成最终URI）
        let content_hash = sha256_hex(&ciphertext_bytes);

        // 4. 创建Ciphertext结构（使用Inline存储，直到实际上传）
        let ciphertext_b64 = base64::encode(&ciphertext_bytes);
        let block = Ciphertext {
            aad: base64::encode(aad),
            enc: EncAlg::Aes256Gcm,
            nonce,
            len: plaintext.len() as u64,
            dek_id: dek_id.clone(),
            storage: CipherStorage::Inline {
                ct_b64: ciphertext_b64,
                ciphertext_len: Some(ciphertext_bytes.len() as u64),
                ciphertext_digest: Some(Self::compute_digest(&ciphertext_bytes)?),
            },
        };

        let signature = Signature {
            alg: "Ed25519".to_string(),
            sig: signature_b64,
            author_hint,
            cert_hint: None,
        };

        let proof = AuthorProof {
            subject: digest,
            schema_hash: None,
            issued_at: Some(
                OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap(),
            ),
            signature,
        };

        // 5. 创建Pending状态
        let state = CapsuleState::new_pending(placeholder_uri, ciphertext_bytes, content_hash);

        Ok((
            SealedBlock {
                ciphertext: block,
                proof,
                content_type,
                state,
            },
            dek_id,
        ))
    }

    /// 开始上传流程，将状态从Pending转换为Uploading
    pub fn start_upload(
        &mut self,
        upload_id: String,
        target_uri: String,
        upload_meta: Option<UploadMeta>,
    ) -> std::result::Result<(), StateTransitionError> {
        self.state = self
            .state
            .clone()
            .start_upload(upload_id, target_uri.clone(), upload_meta)?;

        // 在上传阶段，我们保持Inline存储，只有在上传完成时才转换为External
        // 这样在上传过程中，数据仍然可以直接访问
        // 如果已经是External存储，则更新URI
        if let CipherStorage::External { uri, .. } = &mut self.ciphertext.storage {
            *uri = target_uri;
        }

        Ok(())
    }

    /// 更新上传进度
    pub fn update_upload_progress(
        &mut self,
        progress: f64,
    ) -> std::result::Result<(), StateTransitionError> {
        self.state.update_progress(progress)
    }

    /// 标记上传完成
    pub fn mark_upload_completed(
        &mut self,
        final_uri: String,
        verification: Option<crate::state::UploadVerification>,
    ) -> std::result::Result<(), StateTransitionError> {
        self.state = self
            .state
            .clone()
            .mark_completed(final_uri.clone(), verification)?;

        // 转换存储方式：从Inline转换为External（表示数据已上传）
        match &self.ciphertext.storage {
            CipherStorage::Inline {
                ciphertext_len,
                ciphertext_digest,
                ..
            } => {
                // 转换为External存储，表示数据已经上传到外部存储
                self.ciphertext.storage = CipherStorage::External {
                    uri: final_uri,
                    ciphertext_len: *ciphertext_len,
                    ciphertext_digest: ciphertext_digest.clone(),
                };
            }
            CipherStorage::External { .. } => {
                // 如果已经是External存储，只更新URI
                if let CipherStorage::External {
                    uri: existing_uri, ..
                } = &mut self.ciphertext.storage
                {
                    *existing_uri = final_uri;
                }
            }
        }

        Ok(())
    }

    /// 标记上传失败
    pub fn mark_upload_failed(
        &mut self,
        error: String,
        error_code: Option<String>,
        retryable: bool,
    ) -> std::result::Result<(), StateTransitionError> {
        self.state = self
            .state
            .clone()
            .mark_failed(error, error_code, retryable)?;
        Ok(())
    }

    /// 获取当前状态
    pub fn get_state(&self) -> &CapsuleState {
        &self.state
    }

    /// 检查是否可以开始上传
    pub fn can_upload(&self) -> bool {
        self.state.can_upload()
    }

    /// 检查是否已完成
    pub fn is_completed(&self) -> bool {
        matches!(self.state, CapsuleState::Completed { .. })
    }

    /// 获取上传进度
    pub fn get_upload_progress(&self) -> Option<f64> {
        self.state.get_progress()
    }

    /// 获取待上传的密文数据（仅在Pending状态时有效）
    pub fn get_pending_ciphertext(&self) -> Option<&Vec<u8>> {
        match &self.state {
            CapsuleState::Pending {
                ciphertext_data, ..
            } => Some(ciphertext_data),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use capsula_key::{Key, RsaKey};

    use super::*;
    use crate::ContentType;

    #[test]
    fn test_sealed_block_round_trip() -> Result<()> {
        // Test data
        let plaintext = b"Hello, World! This is a test message.";
        let content_type = ContentType::Json;
        let aad = b"additional_authenticated_data";

        // Create signing key and recipient key
        let signing_key = RsaKey::generate_2048()?;
        let recipient_key = RsaKey::generate_2048()?;
        let mut keyring = std::collections::HashMap::new();

        // Get recipient public key in SPKI DER format
        let public_keys = recipient_key.public_keys();
        let signing_key_entry = public_keys
            .signing_key()
            .ok_or_else(|| Error::DataError("No signing key found".to_string()))?;
        let recipient_public_key_spki = signing_key_entry.spki_der.clone();

        // Seal the block using RSA
        let (sealed_block, dek_id) = SealedBlock::seal(
            plaintext,
            content_type,
            aad,
            &mut keyring,
            &recipient_public_key_spki, // 使用SPKI DER格式
            &signing_key,
        )?;

        // Verify structure
        assert_eq!(sealed_block.content_type, ContentType::Json);
        assert_eq!(sealed_block.ciphertext.dek_id, dek_id);
        assert_eq!(sealed_block.ciphertext.len, plaintext.len() as u64);
        assert_eq!(sealed_block.ciphertext.enc, EncAlg::Aes256Gcm);

        // Verify keyring has the DEK
        assert!(keyring.contains_key(&dek_id));
        assert_eq!(keyring.len(), 1);

        // Unseal the block using the recipient's private key and keyring
        let decrypted = sealed_block.unseal(&keyring, &recipient_key)?;

        // Verify round trip
        assert_eq!(decrypted, plaintext);

        // Verify state is Completed for traditional seal
        assert!(sealed_block.is_completed());

        Ok(())
    }

    #[test]
    fn test_sealed_block_pending_state() -> Result<()> {
        // Test data
        let plaintext = b"Hello, World! This is a test message for pending state.";
        let content_type = ContentType::Json;
        let aad = b"additional_authenticated_data";
        let placeholder_uri = "s3://test-bucket/data-{hash}".to_string();

        // Create signing key and recipient key
        let signing_key = RsaKey::generate_2048()?;
        let recipient_key = RsaKey::generate_2048()?;
        let mut keyring = std::collections::HashMap::new();

        // Get recipient public key in SPKI DER format
        let public_keys = recipient_key.public_keys();
        let signing_key_entry = public_keys
            .signing_key()
            .ok_or_else(|| Error::DataError("No signing key found".to_string()))?;
        let recipient_public_key_spki = signing_key_entry.spki_der.clone();

        // Seal the block in pending state
        let (mut sealed_block, _dek_id) = SealedBlock::seal_pending(
            plaintext,
            content_type,
            placeholder_uri,
            aad,
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        // Verify initial state
        assert!(sealed_block.can_upload());
        assert!(!sealed_block.is_completed());
        assert_eq!(sealed_block.get_upload_progress(), Some(0.0));

        // Verify we can get the pending ciphertext
        assert!(sealed_block.get_pending_ciphertext().is_some());

        // Start upload
        sealed_block
            .start_upload(
                "upload-123".to_string(),
                "s3://test-bucket/data-abc123".to_string(),
                None,
            )
            .unwrap();

        // Verify uploading state
        assert!(!sealed_block.can_upload());
        assert_eq!(sealed_block.get_upload_progress(), Some(0.0));

        // Update progress
        sealed_block.update_upload_progress(0.5).unwrap();
        assert_eq!(sealed_block.get_upload_progress(), Some(0.5));

        // Verify we can still unseal during upload (Inline storage)
        println!(
            "Storage during upload: {:?}",
            match &sealed_block.ciphertext.storage {
                CipherStorage::Inline { .. } => "Inline".to_string(),
                CipherStorage::External { uri, .. } => format!("External({})", uri),
            }
        );
        let decrypted_during_upload = sealed_block.unseal(&keyring, &recipient_key).unwrap();
        assert_eq!(decrypted_during_upload, plaintext);

        // Mark completed
        sealed_block
            .mark_upload_completed("s3://test-bucket/data-abc123".to_string(), None)
            .unwrap();

        // Verify completed state
        assert!(sealed_block.is_completed());
        assert_eq!(sealed_block.get_upload_progress(), Some(1.0));
        assert!(sealed_block.get_pending_ciphertext().is_none());

        // Verify storage conversion after completion
        println!("Current state: {:?}", sealed_block.get_state().state_name());
        println!(
            "Storage after completion: {:?}",
            match &sealed_block.ciphertext.storage {
                CipherStorage::Inline { .. } => "Inline".to_string(),
                CipherStorage::External { uri, .. } => format!("External({})", uri),
            }
        );

        // After conversion to External storage, unsealing requires a storage backend
        // In a real application, this would fetch from S3 and then unseal
        // For this test, we expect an appropriate error message
        match sealed_block.unseal(&keyring, &recipient_key) {
            Err(Error::DataError(msg)) if msg.contains("External storage") => {
                println!("Expected error for External storage: {}", msg);
                // This is the expected behavior without a storage backend
            }
            other => panic!("Expected External storage error, got: {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn test_dek_generation() {
        let dek1 = generate_key();
        let dek2 = generate_key();

        // DEKs should be 32 bytes (256 bits)
        assert_eq!(dek1.len(), 32);
        assert_eq!(dek2.len(), 32);

        // DEKs should be different
        assert_ne!(dek1, dek2);
    }

    #[test]
    fn test_dek_id_generation() {
        let id1 = generate_id("dek");
        let id2 = generate_id("dek");

        // IDs should start with "dek_"
        assert!(id1.starts_with("dek_"));
        assert!(id2.starts_with("dek_"));

        // IDs should be different
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_sealed_block_with_wrong_dek() -> Result<()> {
        let plaintext = b"Hello, World!";
        let content_type = ContentType::Json;
        let aad = b"aad";

        let signing_key = RsaKey::generate_2048()?;
        let recipient_key = RsaKey::generate_2048()?;
        let mut keyring = std::collections::HashMap::new();

        // Get recipient public key in SPKI DER format
        let public_keys = recipient_key.public_keys();
        let signing_key_entry = public_keys
            .signing_key()
            .ok_or_else(|| Error::DataError("No signing key found".to_string()))?;
        let recipient_public_key_spki = signing_key_entry.spki_der.clone();

        // Seal with generated DEK
        let (sealed_block, _dek_id) = SealedBlock::seal(
            plaintext,
            content_type,
            aad,
            &mut keyring,
            &recipient_public_key_spki,
            &signing_key,
        )?;

        // Try to unseal with a different key (this should fail when the wrong key tries to decrypt)
        let wrong_key = RsaKey::generate_2048()?;
        let result = sealed_block.unseal(&keyring, &wrong_key);

        // Should fail
        assert!(result.is_err());

        Ok(())
    }
}
