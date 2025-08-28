use ed25519_dalek::{SigningKey, VerifyingKey};
use ed25519_dalek::pkcs8::{EncodePrivateKey, DecodePrivateKey, spki::der::pem::LineEnding};
use signature::Signer;

pub type Result<T> = std::result::Result<T, crate::error::PkiError>;
use capsula_key::{DigitalSignature, ExtendedSignatureInfo, LocationInfo};

/// PKI 专用的密钥对结构体
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key: SigningKey,
    pub public_key: VerifyingKey,
}

impl KeyPair {
    /// 生成新的密钥对
    pub fn generate() -> Result<Self> {
        // 使用操作系统的安全随机数生成器
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf)
            .map_err(|e| crate::error::PkiError::KeyError(format!("Random generation failed: {e}")))?;

        // 生成Ed25519私钥
        let private_key = SigningKey::from_bytes(&buf);

        // 从私钥派生公钥
        let public_key = private_key.verifying_key();

        Ok(KeyPair {
            private_key,
            public_key,
        })
    }

    /// 从字节数组创建密钥对
    pub fn from_bytes(private_key_bytes: &[u8]) -> Result<Self> {
        // 验证私钥长度
        if private_key_bytes.len() != 32 {
            return Err(crate::error::PkiError::KeyError(format!(
                "Ed25519 private key must be 32 bytes, got {} bytes",
                private_key_bytes.len()
            )));
        }

        // 将字节数组转换为固定长度数组
        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(private_key_bytes);

        // 从字节数组创建私钥
        let private_key = SigningKey::from_bytes(&private_key_array);

        // 从私钥派生公钥
        let public_key = private_key.verifying_key();

        Ok(KeyPair {
            private_key,
            public_key,
        })
    }

    /// 获取私钥字节
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }

    /// 获取公钥字节
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// 导出私钥为 PKCS#8 PEM 格式
    pub fn export_private_key(&self) -> Result<String> {
        let key = self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| crate::error::PkiError::KeyError(format!("Failed to export private key to PEM: {e}")))?;
        Ok(key.to_string())
    }

    /// 签名数据（带位置信息）
    pub fn sign_data(
        &self,
        data: &[u8],
        location: LocationInfo,
        signer_info: Option<String>,
        signature_type: Option<String>,
    ) -> Result<DigitalSignature> {
        use sha2::{Digest, Sha256};
        use std::time::{SystemTime, UNIX_EPOCH};
        
        // 计算数据哈希
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash = hasher.finalize().to_vec();

        // 创建扩展签名信息
        let extended_info = ExtendedSignatureInfo {
            data_hash: data_hash.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            location,
            signer_info,
            signature_type,
        };

        // 序列化扩展信息
        let extended_info_bytes = serde_json::to_vec(&extended_info)
            .map_err(|e| crate::error::PkiError::SignatureError(format!("Failed to serialize extended info: {e}")))?;

        // 构建待签名数据
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&data_hash);
        sign_data.extend_from_slice(&extended_info_bytes);

        // 签名
        let signature = self.private_key.sign(&sign_data);
        let signature_bytes = signature.to_bytes().to_vec();

        // 创建数字签名
        Ok(DigitalSignature {
            signature: signature_bytes,
            extended_info,
            public_key: self.public_key.to_bytes().to_vec(),
        })
    }

    /// 从字节数组创建公钥
    pub fn public_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey> {
        if bytes.len() != 32 {
            return Err(crate::error::PkiError::KeyError(format!(
                "Ed25519 public key must be 32 bytes, got {} bytes",
                bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(bytes);
        
        VerifyingKey::from_bytes(&key_array)
            .map_err(|e| crate::error::PkiError::KeyError(format!("Invalid public key: {e}")))
    }

    /// 从 PEM 格式导入私钥
    pub fn import_private_key(pem_str: &str) -> Result<Self> {
        // 验证输入格式
        if !pem_str.contains("-----BEGIN PRIVATE KEY-----") {
            return Err(crate::error::PkiError::KeyError(
                "Invalid PEM format: missing PEM header".to_string()
            ));
        }

        // 从PEM字符串解析私钥
        let private_key = SigningKey::from_pkcs8_pem(pem_str)
            .map_err(|e| crate::error::PkiError::KeyError(format!("Failed to import private key from PEM: {e}")))?;

        // 从私钥派生公钥
        let public_key = private_key.verifying_key();

        Ok(KeyPair {
            private_key,
            public_key,
        })
    }
}