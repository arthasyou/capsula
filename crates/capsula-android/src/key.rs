//! 密钥管理 JNI 接口
//!
//! 使用统一的 capsula-api 层，确保与其他语言绑定的功能对齐

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use capsula_api::{Algorithm, KeyPair, EncodingApi};
use serde_json::json;
use crate::{CapsulaAndroidError, to_jni_result, to_java_string};

/// 创建新密钥对
///
/// # 参数
/// - `algorithm`: 算法名称 ("Curve25519", "P256", "RSA2048", "RSA4096")
///
/// # 返回
/// JSON 字符串，包含：
/// ```json
/// {
///   "public_key": "base64编码的公钥 (SPKI DER)",
///   "private_key": "base64编码的私钥 (PKCS#8 DER)",
///   "algorithm": "算法名称"
/// }
/// ```
#[no_mangle]
pub extern "system" fn Java_com_capsula_android_KeyManager_createKeyPair<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    algorithm: JString<'local>,
) -> jstring {
    let result = create_key_pair_internal(&mut env, algorithm);

    match to_jni_result(&mut env, result) {
        Some(json_str) => {
            match to_java_string(&mut env, json_str) {
                Ok(jstr) => jstr,
                Err(_) => std::ptr::null_mut(),
            }
        }
        None => std::ptr::null_mut(),
    }
}

fn create_key_pair_internal(
    env: &mut JNIEnv,
    algorithm: JString,
) -> Result<String, CapsulaAndroidError> {
    // 获取算法字符串
    let algorithm_str: String = env
        .get_string(&algorithm)
        .map_err(|e| CapsulaAndroidError::JniError(format!("Failed to get algorithm string: {}", e)))?
        .into();

    // 使用 API 层解析算法
    let algo = algorithm_str.parse::<Algorithm>()?;

    // 生成密钥对
    let keypair = KeyPair::generate(algo)?;

    // 导出为 DER 格式
    let public_der = keypair.public_key_to_der()?;
    let private_der = keypair.private_key_to_der()?;

    // 转换为 base64
    let public_key_b64 = EncodingApi::encode_base64(&public_der);
    let private_key_b64 = EncodingApi::encode_base64(&private_der);

    // 构建 JSON 响应
    let response = json!({
        "public_key": public_key_b64,
        "private_key": private_key_b64,
        "algorithm": algo.name(),
        "format": "SPKI/PKCS8"
    });

    Ok(response.to_string())
}

/// 从私钥 JSON 导入密钥对
///
/// # 参数
/// - `json`: KeyPair JSON 格式（由 KeyPair.to_json() 生成）
///
/// # 返回
/// 密钥对句柄（内存地址），用于后续操作
#[no_mangle]
pub extern "system" fn Java_com_capsula_android_KeyManager_importKeyPair<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    json: JString<'local>,
) -> jstring {
    let result = import_key_pair_internal(&mut env, json);

    match to_jni_result(&mut env, result) {
        Some(json_str) => {
            match to_java_string(&mut env, json_str) {
                Ok(jstr) => jstr,
                Err(_) => std::ptr::null_mut(),
            }
        }
        None => std::ptr::null_mut(),
    }
}

fn import_key_pair_internal(
    env: &mut JNIEnv,
    json: JString,
) -> Result<String, CapsulaAndroidError> {
    let json_str: String = env
        .get_string(&json)
        .map_err(|e| CapsulaAndroidError::JniError(format!("Failed to get JSON string: {}", e)))?
        .into();

    // 使用 API 层导入
    let keypair = KeyPair::from_json(&json_str)?;

    // 返回算法信息
    let response = json!({
        "algorithm": keypair.algorithm().name(),
        "status": "imported"
    });

    Ok(response.to_string())
}

/// 对消息进行签名
///
/// # 参数
/// - `private_key_b64`: Base64 编码的私钥 (PKCS#8 DER)
/// - `message_b64`: Base64 编码的待签名消息
///
/// # 返回
/// JSON 字符串：
/// ```json
/// {
///   "signature": "base64编码的签名"
/// }
/// ```
#[no_mangle]
pub extern "system" fn Java_com_capsula_android_KeyManager_sign<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    private_key_b64: JString<'local>,
    message_b64: JString<'local>,
) -> jstring {
    let result = sign_internal(&mut env, private_key_b64, message_b64);

    match to_jni_result(&mut env, result) {
        Some(json_str) => {
            match to_java_string(&mut env, json_str) {
                Ok(jstr) => jstr,
                Err(_) => std::ptr::null_mut(),
            }
        }
        None => std::ptr::null_mut(),
    }
}

fn sign_internal(
    env: &mut JNIEnv,
    private_key_b64: JString,
    message_b64: JString,
) -> Result<String, CapsulaAndroidError> {
    // 获取私钥 base64
    let private_key_str: String = env
        .get_string(&private_key_b64)
        .map_err(|e| CapsulaAndroidError::JniError(format!("Failed to get private key: {}", e)))?
        .into();

    // 获取消息 base64
    let message_str: String = env
        .get_string(&message_b64)
        .map_err(|e| CapsulaAndroidError::JniError(format!("Failed to get message: {}", e)))?
        .into();

    // 解码 base64
    let private_key_der = EncodingApi::decode_base64(&private_key_str)?;
    let message = EncodingApi::decode_base64(&message_str)?;

    // 自动检测算法并导入密钥
    let keypair = KeyPair::from_pkcs8_der_auto_detect(&private_key_der)?;

    // 签名
    let signature = keypair.sign(&message)?;

    // 编码签名
    let signature_b64 = EncodingApi::encode_base64(&signature);

    // 构建 JSON 响应
    let response = json!({
        "signature": signature_b64
    });

    Ok(response.to_string())
}

/// 导出密钥对为 JSON
///
/// # 参数
/// - `private_key_b64`: Base64 编码的私钥 (PKCS#8 DER)
///
/// # 返回
/// KeyPair JSON 格式字符串（可用于跨语言传输）
#[no_mangle]
pub extern "system" fn Java_com_capsula_android_KeyManager_exportToJson<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    private_key_b64: JString<'local>,
) -> jstring {
    let result = export_to_json_internal(&mut env, private_key_b64);

    match to_jni_result(&mut env, result) {
        Some(json_str) => {
            match to_java_string(&mut env, json_str) {
                Ok(jstr) => jstr,
                Err(_) => std::ptr::null_mut(),
            }
        }
        None => std::ptr::null_mut(),
    }
}

fn export_to_json_internal(
    env: &mut JNIEnv,
    private_key_b64: JString,
) -> Result<String, CapsulaAndroidError> {
    let private_key_str: String = env
        .get_string(&private_key_b64)
        .map_err(|e| CapsulaAndroidError::JniError(format!("Failed to get private key: {}", e)))?
        .into();

    let private_key_der = EncodingApi::decode_base64(&private_key_str)?;
    let keypair = KeyPair::from_pkcs8_der_auto_detect(&private_key_der)?;

    // 使用 API 层导出为标准 JSON
    let json = keypair.to_json()?;

    Ok(json)
}

/// 获取支持的算法列表
#[no_mangle]
pub extern "system" fn Java_com_capsula_android_KeyManager_getSupportedAlgorithms<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    let algorithms = json!({
        "algorithms": [
            {
                "name": "Curve25519",
                "type": "EdDSA/ECDH",
                "usage": "Signing/Key Agreement",
                "key_size": 256,
                "description": "Ed25519 signing + X25519 key agreement"
            },
            {
                "name": "P256",
                "type": "ECDSA",
                "usage": "Signing",
                "key_size": 256,
                "curve": "secp256r1"
            },
            {
                "name": "RSA2048",
                "type": "RSA",
                "usage": "Signing",
                "key_size": 2048
            },
            {
                "name": "RSA4096",
                "type": "RSA",
                "usage": "Signing",
                "key_size": 4096
            }
        ]
    });

    match to_java_string(&mut env, algorithms.to_string()) {
        Ok(jstr) => jstr,
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_and_signing() {
        // 测试密钥生成
        let keypair = KeyPair::generate(Algorithm::Curve25519).unwrap();

        // 测试签名
        let message = b"Test message for Android";
        let signature = keypair.sign(message).unwrap();

        assert_eq!(signature.len(), 64); // Ed25519 签名固定 64 字节
    }

    #[test]
    fn test_json_export_import() {
        // 测试 JSON 导出导入
        let keypair = KeyPair::generate(Algorithm::P256).unwrap();
        let json = keypair.to_json().unwrap();

        let restored = KeyPair::from_json(&json).unwrap();
        assert_eq!(keypair.algorithm(), restored.algorithm());
    }

    #[test]
    fn test_all_algorithms() {
        // 测试所有支持的算法
        for algo in &[Algorithm::Curve25519, Algorithm::P256, Algorithm::Rsa2048] {
            let keypair = KeyPair::generate(*algo).unwrap();
            let message = b"Test";
            let signature = keypair.sign(message).unwrap();
            assert!(!signature.is_empty());
        }
    }
}
