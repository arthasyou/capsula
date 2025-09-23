//! # SealedBlock 模块：数据加密封装
//!
//! 本模块提供了两种数据加密存储模式：**内联存储 (Inline)** 和 **外部存储 (External)**
//!
//! ## 存储模式说明
//!
//! ### 内联存储 (Inline)
//! 适用于小型数据，密文直接存储在 SealedBlock 结构中
//!
//! **使用流程**：
//! ```rust
//! // 1. 封装数据
//! let sealed_block =
//!     SealedBlock::seal_inline(plaintext, content_type, aad, keyring, spki_der, signing_key)?;
//!
//! // 2. 解封数据
//! let decrypted = sealed_block.unseal_inline(keyring, decryption_key)?;
//! ```
//!
//! ### 外部存储 (External)
//! 适用于大型文件，密文存储在外部系统（S3、IPFS、HTTP等）
//!
//! **封装流程**：
//! ```rust
//! // 1. 预备封装：加密文件并生成元数据
//! let metadata = SealedBlock::pre_seal(
//!     input_file_path,
//!     output_file_path,
//!     content_type,
//!     aad,
//!     keyring,
//!     spki_der,
//!     signing_key,
//! )?;
//!
//! // 2. 用户负责：将 output_file_path 的加密文件上传到外部存储
//! let storage_uri = upload_to_external_storage(output_file_path)?; // 用户实现
//!
//! // 3. 设置URI并创建最终封装
//! let sealed_block = SealedBlock::set_uri(metadata, storage_uri)?;
//! ```
//!
//! **解封流程**：
//! ```rust
//! // 1. 获取外部存储URI
//! let uri = sealed_block.get_external_uri()?;
//!
//! // 2. 用户负责：从外部存储下载加密文件
//! let downloaded_file = download_from_external_storage(uri)?; // 用户实现
//!
//! // 3. 解封数据
//! sealed_block.unseal_external(&downloaded_file, &output_file, keyring, decryption_key)?;
//! ```
//!
//! ## 重要说明
//!
//! - **职责分离**：本模块只负责加密/解密，外部存储的上传/下载由用户实现
//! - **灵活性**：支持任何外部存储协议（S3、HTTP、IPFS、自定义等）
//! - **安全性**：密文完整性通过摘要验证，作者身份通过数字签名验证

pub mod ciphertext;
pub mod proof;

use capsula_crypto::base64;
use capsula_key::key::{Key, KeyEncDec, KeySign};
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    block::{ciphertext::Ciphertext, proof::AuthorProof},
    error::{CoreError as Error, Result},
    integrity::digest::Digest,
    keyring::Keyring,
    types::EncAlg,
    ContentType,
};

// --- 最小可验证封装单元：密文 + 单一作者证明 ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlock {
    pub ciphertext: Ciphertext,    // 密文主体（机密性/完整性 by AEAD）
    pub proof: AuthorProof,        // 唯一作者的来源/不可抵赖证明
    pub content_type: ContentType, // 明文内容类型（MIME）
}

// --- 存储类型枚举 ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageType {
    Inline,   // 内联存储
    External, // 外部存储
}

impl SealedBlock {
    /// 封装数据：默认使用内联存储，向后兼容旧代码
    pub fn seal<S>(
        plaintext: &[u8],          // 明文字节
        content_type: ContentType, // 明文类型 (MIME)
        aad: &[u8],                // 额外认证数据（外层上下文）
        keyring: &mut Keyring,     // 密钥环用于存储加密的DEK
        spki_der: &[u8],           // 所有者公钥（SPKI DER格式）
        signing_key: &S,           // 作者签名密钥
    ) -> Result<Self>
    where
        S: Key + KeySign,
    {
        Self::seal_inline(plaintext, content_type, aad, keyring, spki_der, signing_key)
    }

    /// 封装数据到内联存储：把明文加密并签名，生成一个 SealedBlock
    pub fn seal_inline<S>(
        plaintext: &[u8],          // 明文字节
        content_type: ContentType, // 明文类型 (MIME)
        aad: &[u8],                // 额外认证数据（外层上下文）
        keyring: &mut Keyring,     // 密钥环用于存储加密的DEK
        spki_der: &[u8],           // 所有者公钥（SPKI DER格式）
        signing_key: &S,           // 作者签名密钥
    ) -> Result<Self>
    where
        S: Key + KeySign,
    {
        // 1. Create ciphertext using inline storage
        let ciphertext = Ciphertext::new_inline_aes(plaintext, aad, keyring, spki_der)?;

        // 2. Create proof using the AuthorProof module
        let proof = AuthorProof::create(plaintext, signing_key, None)?;

        Ok(SealedBlock {
            ciphertext,
            proof,
            content_type,
        })
    }

    /// 预备封装：加密文件并生成SealedBlock（URI为占位符）
    /// 直接调用 Ciphertext::new_external 进行文件加密
    pub fn pre_seal<S>(
        input_file_path: &std::path::Path,  // 输入文件路径
        output_file_path: &std::path::Path, // 输出加密文件路径
        content_type: ContentType,          // 明文类型 (MIME)
        aad: &[u8],                         // 额外认证数据（外层上下文）
        keyring: &mut Keyring,              // 密钥环用于存储加密的DEK
        spki_der: &[u8],                    // 所有者公钥（SPKI DER格式）
        signing_key: &S,                    // 作者签名密钥
    ) -> Result<Self>
    where
        S: Key + KeySign,
    {
        // 1. 读取明文以创建作者证明
        let plaintext = std::fs::read(input_file_path)
            .map_err(|e| Error::DataError(format!("Failed to read input file: {}", e)))?;

        // 2. 创建作者证明
        let proof = AuthorProof::create(&plaintext, signing_key, None)?;

        // 3. 创建外部密文（使用默认 AES-256-GCM）
        let ciphertext = Ciphertext::new_external(
            input_file_path,
            output_file_path,
            aad,
            EncAlg::Aes256Gcm,
            keyring,
            spki_der,
        )?;

        // 4. 创建SealedBlock（URI为占位符，等待后续设置）
        Ok(SealedBlock {
            ciphertext,
            proof,
            content_type,
        })
    }

    /// 设置外部存储URI
    ///
    /// 用户上传加密文件后调用此方法设置存储URI，完成封装过程
    pub fn set_uri(&mut self, storage_uri: String) -> Result<()> {
        // 检查存储类型必须是外部存储
        match &self.ciphertext.storage {
            crate::block::ciphertext::CipherStorage::External {
                ciphertext_len,
                ciphertext_digest,
                ..
            } => {
                // 更新存储URI
                self.ciphertext.storage = crate::block::ciphertext::CipherStorage::External {
                    uri: storage_uri,
                    ciphertext_len: *ciphertext_len,
                    ciphertext_digest: ciphertext_digest.clone(),
                };
                Ok(())
            }
            crate::block::ciphertext::CipherStorage::Inline { .. } => Err(Error::DataError(
                "Cannot set URI: block uses inline storage, not external storage".to_string(),
            )),
        }
    }

    /// 检查存储类型
    pub fn storage_type(&self) -> StorageType {
        match &self.ciphertext.storage {
            crate::block::ciphertext::CipherStorage::Inline { .. } => StorageType::Inline,
            crate::block::ciphertext::CipherStorage::External { .. } => StorageType::External,
        }
    }

    /// 解封内联存储的数据：直接从内联数据解密
    pub fn unseal_inline<T>(&self, keyring: &Keyring, decryption_key: &T) -> Result<Vec<u8>>
    where
        T: Key + KeyEncDec,
    {
        // 检查存储类型
        if !matches!(
            self.ciphertext.storage,
            crate::block::ciphertext::CipherStorage::Inline { .. }
        ) {
            return Err(Error::DataError(
                "Block uses external storage, use unseal_external instead".to_string(),
            ));
        }

        // 使用 Ciphertext 模块的 decrypt_inline 方法进行解密
        let plaintext = self.ciphertext.decrypt_inline(keyring, decryption_key)?;

        // 验证摘要
        self.verify_plaintext(&plaintext)?;

        Ok(plaintext)
    }

    /// 解封外部存储的数据：需要提供下载的密文文件路径和输出文件路径
    pub fn unseal_external<T>(
        &self,
        encrypted_file_path: &std::path::Path,
        output_file_path: &std::path::Path,
        keyring: &Keyring,
        decryption_key: &T,
    ) -> Result<()>
    where
        T: Key + KeyEncDec,
    {
        // 检查存储类型
        if !matches!(
            self.ciphertext.storage,
            crate::block::ciphertext::CipherStorage::External { .. }
        ) {
            return Err(Error::DataError(
                "Block uses inline storage, use unseal_inline instead".to_string(),
            ));
        }

        // 使用 Ciphertext 模块的 decrypt_external 方法进行解密
        self.ciphertext.decrypt_external(
            encrypted_file_path,
            output_file_path,
            keyring,
            decryption_key,
        )?;

        // 验证摘要（需要读取输出文件）
        let plaintext = std::fs::read(output_file_path)
            .map_err(|e| Error::DataError(format!("Failed to read decrypted output: {}", e)))?;
        self.verify_plaintext(&plaintext)?;

        Ok(())
    }

    /// 获取外部存储的 URI（仅对外部存储有效）
    pub fn get_external_uri(&self) -> Result<&str> {
        match &self.ciphertext.storage {
            crate::block::ciphertext::CipherStorage::External { uri, .. } => Ok(uri),
            crate::block::ciphertext::CipherStorage::Inline { .. } => Err(Error::DataError(
                "Block uses inline storage, no external URI available".to_string(),
            )),
        }
    }

    /// 验证明文摘要
    fn verify_plaintext(&self, plaintext: &[u8]) -> Result<()> {
        let computed_digest = Self::compute_digest(plaintext)?;
        if computed_digest.hash != self.proof.subject.hash {
            return Err(Error::IntegrityError(
                "Digest verification failed".to_string(),
            ));
        }

        // TODO: 验证签名 - 需要获取签名者的公钥
        // 这里暂时跳过签名验证，在实际应用中需要从证书存储或PKI中获取公钥

        Ok(())
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
}
