use ed25519_dalek::{
    pkcs8::{
        spki::der::pem::LineEnding, DecodePrivateKey, DecodePublicKey, EncodePrivateKey,
        EncodePublicKey,
    },
    SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

/// Ed25519 密钥对
#[wasm_bindgen]
pub struct KeyPair {
    signing_key: SigningKey,
}

#[wasm_bindgen]
impl KeyPair {
    /// 生成新的密钥对
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<KeyPair, JsError> {
        use rand::RngCore;

        let mut csprng = OsRng;
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);

        Ok(KeyPair { signing_key })
    }

    /// 从私钥 PEM 导入
    #[wasm_bindgen(js_name = fromPrivateKeyPem)]
    pub fn from_private_key_pem(pem: &str) -> Result<KeyPair, JsError> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| JsError::new(&format!("Failed to import private key: {}", e)))?;

        Ok(KeyPair { signing_key })
    }

    /// 导出私钥为 PEM 格式
    #[wasm_bindgen(js_name = exportPrivateKeyPem)]
    pub fn export_private_key_pem(&self) -> Result<String, JsError> {
        self.signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|e| JsError::new(&format!("Failed to export private key: {}", e)))
    }

    /// 导出公钥为 PEM 格式
    #[wasm_bindgen(js_name = exportPublicKeyPem)]
    pub fn export_public_key_pem(&self) -> Result<String, JsError> {
        self.signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| JsError::new(&format!("Failed to export public key: {}", e)))
    }

    /// 获取公钥字节（32字节）
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// 签名数据
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        self.signing_key.sign(data).to_bytes().to_vec()
    }
}

/// 公钥
#[wasm_bindgen]
pub struct PublicKey {
    verifying_key: VerifyingKey,
}

#[wasm_bindgen]
impl PublicKey {
    /// 从 PEM 导入公钥
    #[wasm_bindgen(js_name = fromPem)]
    pub fn from_pem(pem: &str) -> Result<PublicKey, JsError> {
        let verifying_key = VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| JsError::new(&format!("Failed to import public key: {}", e)))?;

        Ok(PublicKey { verifying_key })
    }

    /// 从字节数组导入（32字节）
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, JsError> {
        if bytes.len() != 32 {
            return Err(JsError::new("Public key must be 32 bytes"));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| JsError::new(&format!("Invalid public key: {}", e)))?;

        Ok(PublicKey { verifying_key })
    }

    /// 导出为 PEM 格式
    #[wasm_bindgen(js_name = toPem)]
    pub fn to_pem(&self) -> Result<String, JsError> {
        self.verifying_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| JsError::new(&format!("Failed to export public key: {}", e)))
    }

    /// 获取字节表示（32字节）
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }

    /// 验证签名
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
        use ed25519_dalek::{Signature, Verifier};

        if signature.len() != 64 {
            return Err(JsError::new("Signature must be 64 bytes"));
        }

        let signature = Signature::from_bytes(signature.try_into().unwrap());

        match self.verifying_key.verify(message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
