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
    ContentType, EncAlg,
};

// --- 最小可验证封装单元：密文 + 单一作者证明 ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlock {
    pub ciphertext: Ciphertext,    // 密文主体（机密性/完整性 by AEAD）
    pub proof: AuthorProof,        // 唯一作者的来源/不可抵赖证明
    pub content_type: ContentType, // 明文内容类型（MIME）
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

        Ok((
            SealedBlock {
                ciphertext: block,
                proof,
                content_type,
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
        let ciphertext_b64 = self
            .ciphertext
            .get_ciphertext_b64()
            .map_err(|e| Error::DataError(e))?;
        let plaintext = decrypt_aead(ciphertext_b64, &dek, &nonce_bytes, &aad)
            .map_err(|e| Error::DataError(format!("Decryption failed: {}", e)))?;

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
