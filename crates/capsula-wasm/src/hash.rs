use wasm_bindgen::prelude::*;
use sha2::{Sha256, Sha512, Digest};
use hex;

/// 计算 SHA256 哈希
#[wasm_bindgen(js_name = sha256)]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// 计算 SHA256 哈希并返回十六进制字符串
#[wasm_bindgen(js_name = sha256Hex)]
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256(data);
    hex::encode(hash)
}

/// 计算 SHA512 哈希
#[wasm_bindgen(js_name = sha512)]
pub fn sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// 计算 SHA512 哈希并返回十六进制字符串
#[wasm_bindgen(js_name = sha512Hex)]
pub fn sha512_hex(data: &[u8]) -> String {
    let hash = sha512(data);
    hex::encode(hash)
}

/// 验证哈希
#[wasm_bindgen(js_name = verifyHash)]
pub fn verify_hash(data: &[u8], hash: &[u8], algorithm: &str) -> Result<bool, JsError> {
    let computed_hash = match algorithm.to_lowercase().as_str() {
        "sha256" => sha256(data),
        "sha512" => sha512(data),
        _ => return Err(JsError::new("Unsupported algorithm. Use 'sha256' or 'sha512'")),
    };
    
    Ok(computed_hash == hash)
}