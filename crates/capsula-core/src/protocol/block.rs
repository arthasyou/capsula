use capsula_crypto::{base64, encrypt_aead, decrypt_aead, generate_key, generate_nonce, generate_id};
use capsula_key::key::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as Sha2Digest, Sha256};
use time::OffsetDateTime;

use crate::{
    error::{CoreError as Error, Result},
    keyring::Keyring,
    ContentType, EncAlg,
};

// --- 密文块：加解密所需最小信息 ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub ct: String,     // base64(ciphertext || tag)
    pub aad: String,    // base64(aad) —— 由外层计算并传入（绑定上下文）
    pub enc: EncAlg,    // AES-256-GCM / ChaCha20-Poly1305
    pub nonce: String,  // base64(12 bytes)
    pub len: u64,       // 明文长度（字节）
    pub dek_id: String, // 对应的 DEK ID（外层用 KeyWrap 关联）
}

// --- 明文指纹（被签名的“承诺值”）---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Digest {
    pub alg: String,  // 例: "SHA-256" / "Merkle-SHA256"
    pub hash: String, // hex 或 base64
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<Value>, // 任意结构的概要标签，如 {"heme":"normal"}
}

// --- 作者签名（对 AuthorProof 的签名值/身份线索）---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub alg: String,         // "Ed25519" / "ECDSA-P256-SHA256"
    pub sig: String,         // base64(signature)
    pub author_hint: String, // 作者标识线索（证书主体/DID/公钥指纹）
    #[serde(default)]
    pub cert_hint: Option<String>, // 可选：证书链/目录定位线索
}

// --- 作者证明：明确“签了什么” ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorProof {
    pub subject: Digest, // 明文指纹（或 Merkle 根）
    #[serde(default)]
    pub schema_hash: Option<String>, // 可选：明文结构/规范哈希
    #[serde(default)]
    pub issued_at: Option<String>, // 可选：RFC3339 出具时间
    pub signature: Signature, // 作者对 {subject, schema_hash?, issued_at?} 的脱离式签名
}

// --- 最小可验证封装单元：密文 + 单一作者证明 ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlock {
    pub block: Ciphertext,         // 密文主体（机密性/完整性 by AEAD）
    pub proof: AuthorProof,        // 唯一作者的来源/不可抵赖证明
    pub content_type: ContentType, // 明文内容类型（MIME）
}

impl SealedBlock {
    /// 封装数据：把明文加密并签名，生成一个 SealedBlock
    pub fn seal(
        plaintext: &[u8],             // 明文字节
        content_type: ContentType,    // 明文类型 (MIME)
        aad: &[u8],                   // 额外认证数据（外层上下文）
        _keyring: &Keyring,           // 密钥环用于查找DEK (暂未使用)
        signing_key: &dyn SigningKey, // 外部提供的签名私钥
    ) -> Result<(Self, Vec<u8>, String)> {
        // 1. 生成 DEK 和 DEK ID
        let dek = generate_key();
        let dek_id = generate_id("dek");

        // 2. 生成随机 nonce (12 bytes for AES-256-GCM)
        let nonce_bytes = generate_nonce();
        let nonce = base64::encode(nonce_bytes);

        // 3. 使用 DEK 进行 AEAD 加密
        let ciphertext = encrypt_aead(plaintext, &dek, &nonce_bytes, aad)
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
            ct: ciphertext,
            aad: base64::encode(aad),
            enc: EncAlg::Aes256Gcm,
            nonce,
            len: plaintext.len() as u64,
            dek_id: dek_id.clone(),
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
                block,
                proof,
                content_type,
            },
            dek.to_vec(),
            dek_id,
        ))
    }

    /// 解封数据：解密并验证签名，返回明文
    pub fn unseal(
        &self,
        dek: &[u8], // 已经解包的数据加密密钥
    ) -> Result<Vec<u8>> {
        // 1. 解码 nonce 和 AAD
        let nonce_vec = base64::decode(&self.block.nonce).map_err(|e| Error::DataError(format!("Base64 decode error: {}", e)))?;
        let aad = base64::decode(&self.block.aad).map_err(|e| Error::DataError(format!("Base64 decode error: {}", e)))?;

        if nonce_vec.len() != 12 {
            return Err(Error::DataError("Invalid nonce length".to_string()));
        }
        
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce_vec);

        // 2. 解密数据
        let plaintext = decrypt_aead(&self.block.ct, dek, &nonce_bytes, &aad)
            .map_err(|e| Error::DataError(format!("Decryption failed: {}", e)))?;

        // 3. 验证长度
        if plaintext.len() != self.block.len as usize {
            return Err(Error::DataError("Decrypted length mismatch".to_string()));
        }

        // 4. 验证摘要
        let computed_digest = Self::compute_digest(&plaintext)?;
        if computed_digest.hash != self.proof.subject.hash {
            return Err(Error::IntegrityError(
                "Digest verification failed".to_string(),
            ));
        }

        // 5. TODO: 验证签名 - 需要获取签名者的公钥
        // 这里暂时跳过签名验证，在实际应用中需要从证书存储或PKI中获取公钥

        Ok(plaintext)
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
            summary: None,
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
    use capsula_key::Curve25519;

    use super::*;
    use crate::ContentType;

    #[test]
    fn test_sealed_block_round_trip() -> Result<()> {
        // Test data
        let plaintext = b"Hello, World! This is a test message.";
        let content_type = ContentType::Json;
        let aad = b"additional_authenticated_data";

        // Create signing key and keyring
        let signing_key = Curve25519::generate()?;
        let keyring = std::collections::HashMap::new();

        // Seal the block
        let (sealed_block, dek, dek_id) =
            SealedBlock::seal(plaintext, content_type, aad, &keyring, &signing_key)?;

        // Verify structure
        assert_eq!(sealed_block.content_type, ContentType::Json);
        assert_eq!(sealed_block.block.dek_id, dek_id);
        assert_eq!(sealed_block.block.len, plaintext.len() as u64);
        assert_eq!(sealed_block.block.enc, EncAlg::Aes256Gcm);

        // Unseal the block
        let decrypted = sealed_block.unseal(&dek)?;

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

        let signing_key = Curve25519::generate()?;
        let keyring = std::collections::HashMap::new();

        // Seal with generated DEK
        let (sealed_block, _dek, _dek_id) =
            SealedBlock::seal(plaintext, content_type, aad, &keyring, &signing_key)?;

        // Try to unseal with a different DEK
        let wrong_dek = generate_key();
        let result = sealed_block.unseal(&wrong_dek);

        // Should fail
        assert!(result.is_err());

        Ok(())
    }
}
