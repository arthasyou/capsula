//! 编码转换 API
//!
//! 提供 Base64、Hex 等编码格式的转换功能

use base64::{Engine as _, engine::general_purpose};
use crate::{Result, ApiError};

/// 编码转换 API
pub struct EncodingApi;

impl EncodingApi {
    /// 编码为 Base64 (标准格式)
    pub fn encode_base64(data: &[u8]) -> String {
        general_purpose::STANDARD.encode(data)
    }

    /// 从 Base64 解码 (标准格式)
    pub fn decode_base64(encoded: &str) -> Result<Vec<u8>> {
        general_purpose::STANDARD.decode(encoded).map_err(|e| e.into())
    }

    /// 编码为 Hex
    pub fn encode_hex(data: &[u8]) -> String {
        hex::encode(data)
    }

    /// 从 Hex 解码
    pub fn decode_hex(encoded: &str) -> Result<Vec<u8>> {
        hex::decode(encoded).map_err(|e| ApiError::EncodingError(e.to_string()))
    }

    /// Base64 URL-safe 编码 (用于 URL 参数)
    pub fn encode_base64_url(data: &[u8]) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    /// Base64 URL-safe 解码
    pub fn decode_base64_url(encoded: &str) -> Result<Vec<u8>> {
        Ok(general_purpose::URL_SAFE_NO_PAD.decode(encoded)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_decode() {
        let data = b"Hello, Capsula!";
        let encoded = EncodingApi::encode_base64(data);
        let decoded = EncodingApi::decode_base64(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = b"Hello, Capsula!";
        let encoded = EncodingApi::encode_hex(data);
        let decoded = EncodingApi::decode_hex(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_base64_url_encode_decode() {
        let data = b"Hello+World/Test=";
        let encoded = EncodingApi::encode_base64_url(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));

        let decoded = EncodingApi::decode_base64_url(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }
}
