use capsula_crypto::{
    base64, decrypt_aead, encrypt_aead, encrypt_dek_with_algorithm, generate_id, generate_key,
    generate_nonce, parse_algorithm_from_spki, sha256_hex,
};
use capsula_key::key::{Key, SigningKey};
use pkcs8::{der::Decode, spki::SubjectPublicKeyInfoRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as Sha2Digest, Sha256};
use time::OffsetDateTime;

use crate::{
    error::{CoreError as Error, Result},
    keyring::{KeyWrap, Keyring},
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
        keyring: &mut Keyring,        // 密钥环用于存储加密的DEK
        recipient_public_key: &[u8],  // 所有者公钥（SPKI DER格式）
        signing_key: &dyn SigningKey, // 作者私钥（用于签名）
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
            dek_id,
        ))
    }

    /// 解封数据：解密并验证签名，返回明文
    pub fn unseal(
        &self,
        dek: &[u8], // 已经解包的数据加密密钥
    ) -> Result<Vec<u8>> {
        // 1. 解码 nonce 和 AAD
        let nonce_vec = base64::decode(&self.block.nonce)
            .map_err(|e| Error::DataError(format!("Base64 decode error: {}", e)))?;
        let aad = base64::decode(&self.block.aad)
            .map_err(|e| Error::DataError(format!("Base64 decode error: {}", e)))?;

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
    use capsula_key::{Key, KeyEncDec, RsaKey};

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
        assert_eq!(sealed_block.block.dek_id, dek_id);
        assert_eq!(sealed_block.block.len, plaintext.len() as u64);
        assert_eq!(sealed_block.block.enc, EncAlg::Aes256Gcm);

        // Verify keyring has the DEK
        assert!(keyring.contains_key(&dek_id));
        assert_eq!(keyring.len(), 1);

        // Decrypt DEK from keyring using recipient's private key
        let key_wrap = keyring.get(&dek_id).unwrap();
        let encrypted_dek_bytes = base64::decode(&key_wrap.cek_wrapped)
            .map_err(|e| Error::DataError(format!("Base64 decode failed: {}", e)))?;

        // Decrypt the DEK using RSA private key
        let dek = recipient_key.decrypt(&encrypted_dek_bytes)?;

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

        // Try to unseal with a different DEK
        let wrong_dek = generate_key();
        let result = sealed_block.unseal(&wrong_dek);

        // Should fail
        assert!(result.is_err());

        Ok(())
    }
}
