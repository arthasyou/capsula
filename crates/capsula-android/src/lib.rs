//! Capsula Android 库
//!
//! 提供 Android 平台的密钥管理和数据封装功能，通过 JNI 接口暴露给 Java/Kotlin

use jni::JNIEnv;
use jni::sys::jstring;

mod key;
mod error;

pub use key::*;
pub use error::*;

/// JNI 错误处理辅助函数
fn to_jni_result<T>(env: &mut JNIEnv, result: Result<T, CapsulaAndroidError>) -> Option<T>
where
    T: std::fmt::Debug
{
    match result {
        Ok(value) => Some(value),
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", e.to_string());
            None
        }
    }
}

/// 将 Rust String 转换为 Java String
fn to_java_string(env: &mut JNIEnv, s: String) -> Result<jstring, CapsulaAndroidError> {
    env.new_string(s)
        .map(|js| js.into_raw())
        .map_err(|e| CapsulaAndroidError::JniError(format!("Failed to create Java string: {}", e)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_library_loads() {
        // 基础测试确保库可以加载
        assert!(true);
    }
}
