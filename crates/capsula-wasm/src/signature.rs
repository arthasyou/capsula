use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use js_sys::Date;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// 位置信息结构体
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct LocationInfo {
    /// 纬度
    pub latitude: Option<f64>,
    /// 经度
    pub longitude: Option<f64>,
    /// 地址描述
    pub address: Option<String>,
    /// 医疗机构ID
    pub institution_id: Option<String>,
    /// 科室信息
    pub department: Option<String>,
}

/// 扩展签名信息结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedSignatureInfo {
    /// 原始数据的哈希
    pub data_hash: Vec<u8>,
    /// 时间戳 (Unix timestamp)
    pub timestamp: u64,
    /// 位置信息
    pub location: LocationInfo,
    /// 签名者信息
    pub signer_info: Option<String>,
    /// 签名用途/类型
    pub signature_type: Option<String>,
}

/// 完整的数字签名结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSignature {
    /// Ed25519 签名
    pub signature: Vec<u8>,
    /// 扩展签名信息
    pub extended_info: ExtendedSignatureInfo,
    /// 公钥 (用于验证)
    pub public_key: Vec<u8>,
}

impl DigitalSignature {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// 位置信息（用于签名）
#[wasm_bindgen]
pub struct Location {
    inner: LocationInfo,
}

#[wasm_bindgen]
impl Location {
    /// 创建新的位置信息
    #[wasm_bindgen(constructor)]
    pub fn new() -> Location {
        Location {
            inner: LocationInfo {
                latitude: None,
                longitude: None,
                address: None,
                institution_id: None,
                department: None,
            },
        }
    }

    /// 设置纬度
    #[wasm_bindgen(js_name = setLatitude)]
    pub fn set_latitude(&mut self, lat: f64) {
        self.inner.latitude = Some(lat);
    }

    /// 设置经度
    #[wasm_bindgen(js_name = setLongitude)]
    pub fn set_longitude(&mut self, lng: f64) {
        self.inner.longitude = Some(lng);
    }

    /// 设置地址
    #[wasm_bindgen(js_name = setAddress)]
    pub fn set_address(&mut self, address: String) {
        self.inner.address = Some(address);
    }

    /// 设置机构ID
    #[wasm_bindgen(js_name = setInstitutionId)]
    pub fn set_institution_id(&mut self, id: String) {
        self.inner.institution_id = Some(id);
    }

    /// 设置部门
    #[wasm_bindgen(js_name = setDepartment)]
    pub fn set_department(&mut self, dept: String) {
        self.inner.department = Some(dept);
    }
}

/// 创建扩展签名
#[wasm_bindgen(js_name = signWithExtendedInfo)]
pub fn sign_with_extended_info(
    key_pair: &crate::key::KeyPair,
    data: &[u8],
    location: &Location,
    signer_info: Option<String>,
    signature_type: Option<String>,
) -> Result<JsValue, JsError> {
    // 计算数据哈希
    let mut hasher = Sha256::new();
    hasher.update(data);
    let data_hash = hasher.finalize().to_vec();

    // 创建扩展信息
    let extended_info = ExtendedSignatureInfo {
        data_hash: data_hash.clone(),
        timestamp: (Date::now() / 1000.0) as u64, /* JavaScript Date.now() 返回毫秒，除以 1000
                                                   * 得到秒 */
        location: location.inner.clone(),
        signer_info,
        signature_type,
    };

    // 序列化扩展信息
    let extended_info_bytes = serde_json::to_vec(&extended_info)
        .map_err(|e| JsError::new(&format!("Failed to serialize extended info: {}", e)))?;

    // 构建待签名数据
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(&data_hash);
    sign_data.extend_from_slice(&extended_info_bytes);

    // 签名
    let signature_bytes = key_pair.sign(&sign_data);
    let public_key_bytes = key_pair.public_key_bytes();

    // 创建数字签名
    let digital_signature = DigitalSignature {
        signature: signature_bytes,
        extended_info,
        public_key: public_key_bytes,
    };

    // 转换为 JS 对象
    to_value(&digital_signature).map_err(|e| JsError::new(&e.to_string()))
}

/// 验证签名
#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature(data: &[u8], signature_js: JsValue) -> Result<bool, JsError> {
    // 从 JS 对象转换
    let digital_signature: DigitalSignature = from_value(signature_js)
        .map_err(|e| JsError::new(&format!("Failed to parse signature: {}", e)))?;

    // 验证签名
    verify_signature_internal(data, &digital_signature)
}

fn verify_signature_internal(
    data: &[u8],
    digital_signature: &DigitalSignature,
) -> Result<bool, JsError> {
    // 计算原始数据的哈希
    let mut hasher = Sha256::new();
    hasher.update(data);
    let calculated_hash = hasher.finalize().to_vec();

    // 验证哈希是否匹配
    if calculated_hash != digital_signature.extended_info.data_hash {
        return Ok(false);
    }

    // 重构要验证的数据
    let extended_info_bytes = serde_json::to_vec(&digital_signature.extended_info)
        .map_err(|e| JsError::new(&format!("Failed to serialize extended info: {}", e)))?;

    let mut verify_data = Vec::new();
    verify_data.extend_from_slice(&digital_signature.extended_info.data_hash);
    verify_data.extend_from_slice(&extended_info_bytes);

    // 处理公钥格式（可能是 SPKI DER 格式）
    let public_key_bytes = if digital_signature.public_key.len() == 32 {
        digital_signature.public_key.as_slice()
    } else if digital_signature.public_key.len() >= 44 {
        // SPKI DER format, extract public key part
        &digital_signature.public_key[12 ..]
    } else {
        return Err(JsError::new("Invalid public key format"));
    };

    if public_key_bytes.len() != 32 {
        return Err(JsError::new("Invalid public key length after extraction"));
    }

    // 解析公钥
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(public_key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| JsError::new(&format!("Invalid public key: {}", e)))?;

    // 验证签名
    if digital_signature.signature.len() != 64 {
        return Err(JsError::new("Invalid signature length"));
    }

    let sig_bytes: [u8; 64] = digital_signature.signature.clone().try_into().unwrap();
    let signature = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify(&verify_data, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// 从 JSON 字符串解析签名
#[wasm_bindgen(js_name = parseSignature)]
pub fn parse_signature(json: &str) -> Result<JsValue, JsError> {
    let digital_signature = DigitalSignature::from_json(json)
        .map_err(|e| JsError::new(&format!("Failed to parse signature JSON: {}", e)))?;

    to_value(&digital_signature).map_err(|e| JsError::new(&e.to_string()))
}

/// 将签名转换为 JSON 字符串
#[wasm_bindgen(js_name = signatureToJson)]
pub fn signature_to_json(signature_js: JsValue) -> Result<String, JsError> {
    let digital_signature: DigitalSignature = from_value(signature_js)
        .map_err(|e| JsError::new(&format!("Failed to parse signature object: {}", e)))?;

    digital_signature
        .to_json()
        .map_err(|e| JsError::new(&format!("Failed to convert to JSON: {}", e)))
}
