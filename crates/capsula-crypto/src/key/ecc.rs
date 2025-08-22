use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{
    pkcs8::{
        spki::der::pem::LineEnding, DecodePrivateKey, DecodePublicKey, EncodePrivateKey,
        EncodePublicKey,
    },
    Signature, SigningKey, VerifyingKey,
};
use serde_json;
use signature::{Signer, Verifier};

use crate::{
    error::{Error, Result},
    signature::ecc::{DigitalSignature, ExtendedSignatureInfo, LocationInfo},
};

/// Ed25519密钥对结构体 (使用 ed25519-dalek 实现，兼容 RustCrypto trait)
#[derive(Debug, Clone)]
pub struct EccKeyPair {
    pub private_key: SigningKey,
    pub public_key: VerifyingKey,
}

impl EccKeyPair {
    /// 生成新的Ed25519密钥对
    /// 使用 ed25519-dalek 实现，兼容 RustCrypto signature trait
    ///
    /// # Returns
    /// * `Result<EccKeyPair, EccError>` - 成功返回密钥对，失败返回错误
    ///
    /// # Example
    /// ```rust
    /// use capsula_crypto::key::ecc::EccKeyPair;
    ///
    /// let keypair = EccKeyPair::generate_keypair().unwrap();
    /// println!("Ed25519密钥对生成成功");
    // ```
    pub fn generate_keypair() -> Result<Self> {
        // 使用操作系统的安全随机数生成器
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf)
            .map_err(|e| Error::KeyError(format!("Random generation failed: {e}")))?;

        // 生成Ed25519私钥
        let private_key = SigningKey::from_bytes(&buf);

        // 从私钥派生公钥
        let public_key = private_key.verifying_key();

        Ok(EccKeyPair {
            private_key,
            public_key,
        })
    }

    /// 导出私钥为 PKCS#8 PEM 格式
    /// 使用标准的 PKCS#8 格式，便于与其他系统互操作
    ///
    /// # Returns
    /// * `Result<String, EccError>` - 成功返回PEM格式的私钥字符串
    ///
    /// # Example
    /// ```rust
    /// use capsula_crypto::key::ecc::EccKeyPair;
    /// let keypair = EccKeyPair::generate_keypair().unwrap();
    /// let private_key_pem = keypair.export_private_key().unwrap();
    /// println!("私钥PEM格式:\n{}", private_key_pem);
    /// ```
    pub fn export_private_key(&self) -> Result<String> {
        let key = self
            .private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| Error::KeyError(format!("Failed to export private key to PEM: {e}")))?;
        Ok(key.to_string())
    }

    /// 导出私钥为 PKCS#8 DER 格式
    /// DER格式是二进制格式，占用空间更小
    ///
    /// # Returns
    /// * `Result<Vec<u8>, EccError>` - 成功返回DER格式的私钥字节数组
    pub fn export_private_key_der(&self) -> Result<Vec<u8>> {
        let der = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| Error::KeyError(format!("Failed to export private key to DER: {e}")))?;
        Ok(der.as_bytes().to_vec())
    }

    /// 导出私钥原始字节
    /// Ed25519私钥是32字节的固定长度
    ///
    /// # Returns
    /// * `Vec<u8>` - 私钥的32字节数组
    pub fn export_private_key_bytes(&self) -> Vec<u8> {
        self.private_key.to_bytes().to_vec()
    }

    /// 导出私钥为十六进制字符串
    /// 便于存储和传输
    ///
    /// # Returns
    /// * `String` - 十六进制格式的私钥字符串
    pub fn export_private_key_hex(&self) -> String {
        hex::encode(self.private_key.to_bytes())
    }

    /// 导出公钥为 SPKI PEM 格式
    /// SPKI (Subject Public Key Info) 是公钥的标准格式
    ///
    /// # Returns
    /// * `Result<String, EccError>` - 成功返回PEM格式的公钥字符串
    pub fn export_public_key_pem(&self) -> Result<String> {
        let pem = self
            .public_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::KeyError(format!("Failed to export public key to PEM: {e}")))?;
        Ok(pem.to_string())
    }

    /// 从 PKCS#8 PEM 格式导入私钥
    /// 支持标准的 PKCS#8 PEM 格式
    ///
    /// # Arguments
    /// * `pem_str` - PEM格式的私钥字符串
    ///
    /// # Returns
    /// * `Result<EccKeyPair, Error>` - 成功返回密钥对，失败返回错误
    ///
    /// # Example
    /// ```rust
    /// use capsula_crypto::key::ecc::EccKeyPair;
    /// let pem_key = "-----BEGIN PRIVATE KEY-----\n...";
    /// let keypair = EccKeyPair::import_private_key(pem_key);
    /// println!("私钥导入成功");
    /// ```
    pub fn import_private_key(pem_str: &str) -> Result<Self> {
        // 验证输入格式
        if !pem_str.contains("-----BEGIN PRIVATE KEY-----") {
            let err = Error::KeyError("Invalid PEM format: missing PEM header".to_string());
            return Err(err);
        }

        // 从PEM字符串解析私钥
        let private_key = SigningKey::from_pkcs8_pem(pem_str)
            .map_err(|e| Error::KeyError(format!("Failed to import private key from PEM: {e}")))?;

        // 从私钥派生公钥
        let public_key = private_key.verifying_key();

        Ok(EccKeyPair {
            private_key,
            public_key,
        })
    }

    /// 从 PKCS#8 DER 格式导入私钥
    ///
    /// # Arguments
    /// * `der_bytes` - DER格式的私钥字节数组
    ///
    /// # Returns
    /// * `Result<EccKeyPair, EccError>` - 成功返回密钥对，失败返回错误
    pub fn import_private_key_der(der_bytes: &[u8]) -> Result<Self> {
        // 从DER字节数组解析私钥
        let private_key = SigningKey::from_pkcs8_der(der_bytes)
            .map_err(|e| Error::KeyError(format!("Failed to import private key from DER: {e}")))?;

        // 从私钥派生公钥
        let public_key = private_key.verifying_key();

        Ok(EccKeyPair {
            private_key,
            public_key,
        })
    }

    /// 从原始字节数组导入私钥
    ///
    /// # Arguments
    /// * `key_bytes` - 32字节的私钥数据
    ///
    /// # Returns
    /// * `Result<EccKeyPair, EccError>` - 成功返回密钥对，失败返回错误
    pub fn import_private_key_bytes(key_bytes: &[u8]) -> Result<Self> {
        // 验证私钥长度
        if key_bytes.len() != 32 {
            let err = Error::KeyError(format!(
                "Ed25519 private key must be 32 bytes, got {} bytes",
                key_bytes.len()
            ));
            return Err(err);
        }

        // 将字节数组转换为固定长度数组
        let mut private_key_array = [0u8; 32];
        private_key_array.copy_from_slice(key_bytes);

        // 从字节数组创建私钥
        let private_key = SigningKey::from_bytes(&private_key_array);

        // 从私钥派生公钥
        let public_key = private_key.verifying_key();

        Ok(EccKeyPair {
            private_key,
            public_key,
        })
    }

    /// 从十六进制字符串导入私钥
    ///
    /// # Arguments
    /// * `hex_str` - 十六进制格式的私钥字符串
    ///
    /// # Returns
    /// * `Result<EccKeyPair, EccError>` - 成功返回密钥对，失败返回错误
    pub fn import_private_key_hex(hex_str: &str) -> Result<Self> {
        // 去除可能的前缀和空白字符
        let cleaned_hex = hex_str.trim().trim_start_matches("0x");

        // 解码十六进制字符串
        let key_bytes = hex::decode(cleaned_hex)
            .map_err(|e| Error::KeyError(format!("Invalid hex format: {e}")))?;

        Self::import_private_key_bytes(&key_bytes)
    }

    /// 从 SPKI PEM 格式导入公钥
    ///
    /// # Arguments
    /// * `pem_str` - PEM格式的公钥字符串
    ///
    /// # Returns
    /// * `Result<VerifyingKey, EccError>` - 成功返回验证密钥
    pub fn import_public_key_pem(pem_str: &str) -> Result<VerifyingKey> {
        let key = VerifyingKey::from_public_key_pem(pem_str)
            .map_err(|e| Error::KeyError(format!("Failed to import public key from PEM: {e}")))?;
        Ok(key)
    }

    /// 获取公钥字节数组
    /// Ed25519公钥是32字节的固定长度
    ///
    /// # Returns
    /// * `Vec<u8>` - 公钥的字节数组
    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    /// 获取公钥十六进制字符串
    ///
    /// # Returns
    /// * `String` - 公钥的十六进制字符串
    pub fn get_public_key_hex(&self) -> String {
        hex::encode(self.public_key.to_bytes())
    }

    /// 从公钥字节数组创建 VerifyingKey
    /// 用于验证签名时导入公钥
    ///
    /// # Arguments
    /// * `public_key_bytes` - 32字节的公钥数据
    ///
    /// # Returns
    /// * `Result<VerifyingKey, EccError>` - 成功返回验证密钥
    pub fn public_key_from_bytes(public_key_bytes: &[u8]) -> Result<VerifyingKey> {
        if public_key_bytes.len() != 32 {
            let err = Error::KeyError(format!(
                "Ed25519 public key must be 32 bytes, got {} bytes",
                public_key_bytes.len()
            ));
            return Err(err);
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(public_key_bytes);

        let key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| Error::KeyError(format!("Invalid public key: {e}")))?;
        Ok(key)
    }

    /// 从十六进制字符串创建 VerifyingKey
    ///
    /// # Arguments
    /// * `hex_str` - 十六进制格式的公钥字符串
    ///
    /// # Returns
    /// * `Result<VerifyingKey, EccError>` - 成功返回验证密钥
    pub fn public_key_from_hex(hex_str: &str) -> Result<VerifyingKey> {
        let cleaned_hex = hex_str.trim().trim_start_matches("0x");
        let key_bytes = hex::decode(cleaned_hex)
            .map_err(|e| Error::KeyError(format!("Invalid hex format: {e}")))?;
        Self::public_key_from_bytes(&key_bytes)
    }

    /// 验证密钥对的有效性
    /// 检查私钥和公钥是否匹配
    ///
    /// # Returns
    /// * `bool` - 密钥对有效返回true，否则返回false
    pub fn validate_keypair(&self) -> bool {
        // 通过私钥重新生成公钥，与当前公钥比较
        let derived_public_key = self.private_key.verifying_key();
        derived_public_key.to_bytes() == self.public_key.to_bytes()
    }

    /// 检查公钥是否为弱密钥
    /// 弱密钥可以用来为几乎任何消息生成有效签名
    ///
    /// # Returns
    /// * `bool` - 如果是弱密钥返回true
    pub fn is_weak_public_key(&self) -> bool {
        self.public_key.is_weak()
    }

    /// 获取密钥对信息摘要
    /// 用于调试和日志记录
    ///
    /// # Returns
    /// * `String` - 密钥对信息摘要
    pub fn key_info(&self) -> String {
        format!(
            "Ed25519 KeyPair (ed25519-dalek):\n  Public Key (hex): {}\n  Public Key (bytes): {} \
             bytes\n  Is weak key: {}",
            self.get_public_key_hex(),
            self.get_public_key_bytes().len(),
            self.is_weak_public_key()
        )
    }

    /// 获取密钥对的完整字节表示 (64字节: 32字节私钥 + 32字节公钥)
    ///
    /// # Returns
    /// * `[u8; 64]` - 64字节的密钥对数据
    pub fn to_keypair_bytes(&self) -> [u8; 64] {
        self.private_key.to_keypair_bytes()
    }

    /// 从64字节的密钥对数据重建密钥对
    ///
    /// # Arguments
    /// * `keypair_bytes` - 64字节的密钥对数据
    ///
    /// # Returns
    /// * `Result<EccKeyPair, EccError>` - 成功返回密钥对
    pub fn from_keypair_bytes(keypair_bytes: &[u8; 64]) -> Result<Self> {
        let private_key = SigningKey::from_keypair_bytes(keypair_bytes)
            .map_err(|e| Error::KeyError(format!("Failed to import keypair: {e}")))?;

        let public_key = private_key.verifying_key();

        Ok(EccKeyPair {
            private_key,
            public_key,
        })
    }

    // ========== 签名相关方法 ==========

    /// 对数据进行签名，包含扩展信息
    ///
    /// # Arguments
    /// * `data` - 要签名的数据
    /// * `location` - 位置信息
    /// * `signer_info` - 签名者信息
    /// * `signature_type` - 签名类型
    ///
    /// # Returns
    /// * `Result<DigitalSignature>` - 数字签名
    pub fn sign_data(
        &self,
        data: &[u8],
        location: LocationInfo,
        signer_info: Option<String>,
        signature_type: Option<String>,
    ) -> Result<DigitalSignature> {
        // 获取当前时间戳
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // 计算数据哈希（使用 SHA-256）
        let data_hash = self.compute_sha256(data);

        // 构建扩展签名信息
        let extended_info = ExtendedSignatureInfo {
            data_hash: data_hash.clone(),
            timestamp,
            location,
            signer_info,
            signature_type,
        };

        // 序列化扩展信息用于签名
        let extended_info_bytes = serde_json::to_vec(&extended_info).map_err(|e| {
            Error::SignatureError(format!("Failed to serialize extended info: {e}"))
        })?;

        // 创建待签名数据：原始数据哈希 + 扩展信息
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&data_hash);
        sign_data.extend_from_slice(&extended_info_bytes);

        // 进行 Ed25519 签名
        let signature = self.private_key.sign(&sign_data);

        Ok(DigitalSignature {
            signature: signature.to_bytes().to_vec(),
            extended_info,
            public_key: self.get_public_key_bytes(),
        })
    }

    /// 验证数字签名
    ///
    /// # Arguments
    /// * `data` - 原始数据
    /// * `digital_signature` - 数字签名
    ///
    /// # Returns
    /// * `Result<bool>` - 签名是否有效
    pub fn verify_signature(
        &self,
        data: &[u8],
        digital_signature: &DigitalSignature,
    ) -> Result<bool> {
        // 重新计算数据哈希
        let computed_hash = self.compute_sha256(data);

        // 检查哈希是否匹配
        if computed_hash != digital_signature.extended_info.data_hash {
            return Ok(false);
        }

        // 重新序列化扩展信息
        let extended_info_bytes =
            serde_json::to_vec(&digital_signature.extended_info).map_err(|e| {
                Error::SignatureError(format!("Failed to serialize extended info: {e}"))
            })?;

        // 重建待验证数据
        let mut verify_data = Vec::new();
        verify_data.extend_from_slice(&computed_hash);
        verify_data.extend_from_slice(&extended_info_bytes);

        // 从字节重建 Ed25519 签名
        let signature = Signature::from_bytes(
            digital_signature
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::SignatureError("Invalid signature length".to_string()))?,
        );

        // 使用数字签名中的公钥进行验证
        let public_key = VerifyingKey::from_bytes(
            digital_signature
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::SignatureError("Invalid public key length".to_string()))?,
        )
        .map_err(|e| Error::SignatureError(format!("Invalid public key: {e}")))?;

        // 执行 Ed25519 验证
        Ok(public_key.verify(&verify_data, &signature).is_ok())
    }

    /// 使用时间戳签名
    ///
    /// # Arguments
    /// * `data` - 要签名的数据
    /// * `signer_info` - 签名者信息
    ///
    /// # Returns
    /// * `Result<DigitalSignature>` - 数字签名
    pub fn sign_with_timestamp(
        &self,
        data: &[u8],
        signer_info: Option<String>,
    ) -> Result<DigitalSignature> {
        self.sign_data(
            data,
            LocationInfo::default(), // 使用默认（空）位置信息
            signer_info,
            Some("时间戳签名".to_string()),
        )
    }

    /// 添加位置信息到现有签名
    ///
    /// # Arguments
    /// * `data` - 原始数据
    /// * `existing_signature` - 现有签名
    /// * `new_location` - 新的位置信息
    ///
    /// # Returns
    /// * `Result<DigitalSignature>` - 新的数字签名
    pub fn add_location_info(
        &self,
        data: &[u8],
        existing_signature: &DigitalSignature,
        new_location: LocationInfo,
    ) -> Result<DigitalSignature> {
        // 复制现有签名的信息，但更新位置
        let mut new_extended_info = existing_signature.extended_info.clone();
        new_extended_info.location = new_location;
        new_extended_info.timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(); // 更新时间戳

        // 重新计算数据哈希
        let data_hash = self.compute_sha256(data);
        new_extended_info.data_hash = data_hash.clone();

        // 序列化新的扩展信息
        let extended_info_bytes = serde_json::to_vec(&new_extended_info).map_err(|e| {
            Error::SignatureError(format!("Failed to serialize extended info: {e}"))
        })?;

        // 创建新的待签名数据
        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&data_hash);
        sign_data.extend_from_slice(&extended_info_bytes);

        // 生成新签名
        let signature = self.private_key.sign(&sign_data);

        Ok(DigitalSignature {
            signature: signature.to_bytes().to_vec(),
            extended_info: new_extended_info,
            public_key: self.get_public_key_bytes(),
        })
    }

    /// 计算 SHA-256 哈希
    fn compute_sha256(&self, data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn test_generate_keypair() {
        let result = EccKeyPair::generate_keypair();
        assert!(result.is_ok());

        let keypair = result.unwrap();
        assert!(keypair.validate_keypair());

        // 验证密钥长度
        assert_eq!(keypair.get_public_key_bytes().len(), 32);
        assert_eq!(keypair.export_private_key_bytes().len(), 32);

        // 验证不是弱密钥
        assert!(!keypair.is_weak_public_key());
    }

    #[test]
    fn test_export_import_private_key_pem() {
        // 生成密钥对
        let original_keypair = EccKeyPair::generate_keypair().unwrap();

        // 导出私钥为PEM
        let exported_pem = original_keypair.export_private_key().unwrap();

        // 验证PEM格式
        assert!(exported_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(exported_pem.contains("-----END PRIVATE KEY-----"));

        // 导入PEM私钥
        let imported_keypair = EccKeyPair::import_private_key(&exported_pem).unwrap();

        // 验证导入的密钥对是否有效
        assert!(imported_keypair.validate_keypair());

        // 验证公钥是否一致
        assert_eq!(
            original_keypair.get_public_key_bytes(),
            imported_keypair.get_public_key_bytes()
        );
    }

    #[test]
    fn test_export_import_private_key_der() {
        // 生成密钥对
        let original_keypair = EccKeyPair::generate_keypair().unwrap();

        // 导出私钥为DER
        let exported_der = original_keypair.export_private_key_der().unwrap();

        // 导入DER私钥
        let imported_keypair = EccKeyPair::import_private_key_der(&exported_der).unwrap();

        // 验证导入的密钥对是否有效
        assert!(imported_keypair.validate_keypair());

        // 验证公钥是否一致
        assert_eq!(
            original_keypair.get_public_key_bytes(),
            imported_keypair.get_public_key_bytes()
        );
    }

    #[test]
    fn test_export_import_private_key_bytes() {
        // 生成密钥对
        let original_keypair = EccKeyPair::generate_keypair().unwrap();

        // 导出私钥原始字节
        let exported_bytes = original_keypair.export_private_key_bytes();
        assert_eq!(exported_bytes.len(), 32);

        // 导入原始字节私钥
        let imported_keypair = EccKeyPair::import_private_key_bytes(&exported_bytes).unwrap();

        // 验证导入的密钥对是否有效
        assert!(imported_keypair.validate_keypair());

        // 验证公钥是否一致
        assert_eq!(
            original_keypair.get_public_key_bytes(),
            imported_keypair.get_public_key_bytes()
        );
    }

    #[test]
    fn test_export_import_private_key_hex() {
        // 生成密钥对
        let original_keypair = EccKeyPair::generate_keypair().unwrap();

        // 导出私钥为十六进制
        let exported_hex = original_keypair.export_private_key_hex();
        assert_eq!(exported_hex.len(), 64); // 32字节 = 64个十六进制字符

        // 导入十六进制私钥
        let imported_keypair = EccKeyPair::import_private_key_hex(&exported_hex).unwrap();

        // 验证导入的密钥对是否有效
        assert!(imported_keypair.validate_keypair());

        // 验证公钥是否一致
        assert_eq!(
            original_keypair.get_public_key_bytes(),
            imported_keypair.get_public_key_bytes()
        );
    }

    #[test]
    fn test_export_import_public_key_pem() {
        let keypair = EccKeyPair::generate_keypair().unwrap();

        // 导出公钥为PEM
        let public_key_pem = keypair.export_public_key_pem().unwrap();
        assert!(public_key_pem.contains("-----BEGIN PUBLIC KEY-----"));

        // 导入公钥
        let imported_public_key = EccKeyPair::import_public_key_pem(&public_key_pem).unwrap();

        // 验证公钥是否一致
        assert_eq!(
            keypair.public_key.to_bytes(),
            imported_public_key.to_bytes()
        );
    }

    #[test]
    fn test_public_key_from_bytes_and_hex() {
        let keypair = EccKeyPair::generate_keypair().unwrap();
        let public_key_bytes = keypair.get_public_key_bytes();
        let public_key_hex = keypair.get_public_key_hex();

        // 从字节数组创建公钥
        let public_key_from_bytes = EccKeyPair::public_key_from_bytes(&public_key_bytes).unwrap();
        assert_eq!(
            keypair.public_key.to_bytes(),
            public_key_from_bytes.to_bytes()
        );

        // 从十六进制创建公钥
        let public_key_from_hex = EccKeyPair::public_key_from_hex(&public_key_hex).unwrap();
        assert_eq!(
            keypair.public_key.to_bytes(),
            public_key_from_hex.to_bytes()
        );
    }

    #[test]
    fn test_keypair_bytes_conversion() {
        let original_keypair = EccKeyPair::generate_keypair().unwrap();

        // 转换为64字节格式
        let keypair_bytes = original_keypair.to_keypair_bytes();
        assert_eq!(keypair_bytes.len(), 64);

        // 从64字节重建密钥对
        let rebuilt_keypair = EccKeyPair::from_keypair_bytes(&keypair_bytes).unwrap();

        // 验证重建的密钥对
        assert!(rebuilt_keypair.validate_keypair());
        assert_eq!(
            original_keypair.get_public_key_bytes(),
            rebuilt_keypair.get_public_key_bytes()
        );
    }

    #[test]
    fn test_invalid_key_lengths() {
        // 测试无效的私钥长度
        let invalid_private_key = vec![0u8; 16]; // 错误的长度
        let result = EccKeyPair::import_private_key_bytes(&invalid_private_key);
        assert!(result.is_err());

        // 测试无效的公钥长度
        let invalid_public_key = vec![0u8; 16]; // 错误的长度
        let result = EccKeyPair::public_key_from_bytes(&invalid_public_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pem_import() {
        let invalid_pem = "invalid pem string";
        let result = EccKeyPair::import_private_key(invalid_pem);
        assert!(result.is_err());

        match result.err().unwrap() {
            Error::KeyError(_) => {}
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_key_info() {
        let keypair = EccKeyPair::generate_keypair().unwrap();
        let info = keypair.key_info();

        assert!(info.contains("Ed25519 KeyPair"));
        assert!(info.contains("ed25519-dalek"));
        assert!(info.contains("Public Key (hex)"));
        assert!(info.contains("32 bytes"));
        assert!(info.contains("Is weak key: false"));
    }
}

// impl EccKeyPair {
//     pub fn generate_keypair() -> Result<Self, EccError> {
//         // 直接生成32字节随机数
//         let mut secret_bytes = [0u8; 32];
//         getrandom::getrandom(&mut secret_bytes)
//             .map_err(|e| EccError::KeyGenerationError(format!("Random generation failed: {}",
// e)))?;

//         let private_key = SigningKey::from_bytes(&secret_bytes);
//         let public_key = private_key.verifying_key();

//         Ok(EccKeyPair { private_key, public_key })
//     }
// }

// impl EccKeyPair {
//     /// 简单的密钥生成 (推荐用法)
//     pub fn generate_keypair() -> Result<Self, EccError> {
//         use rand::rngs::OsRng;
//         let mut rng = OsRng;
//         let private_key = SigningKey::generate(&mut rng);
//         // ...
//     }

//     /// 高级密钥生成 (自定义RNG)
//     pub fn generate_keypair_with_rng<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Result<Self,
// EccError> {         let private_key = SigningKey::generate(rng);
//         // ...
//     }
// }
