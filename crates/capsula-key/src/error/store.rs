use super::Error;
use crate::types::KeyHandle;

/// 存储相关的错误扩展
impl Error {
    /// 密钥未找到错误
    pub fn key_not_found(handle: KeyHandle) -> Self {
        Error::KeyError(format!("Key not found: {:?}", handle))
    }
    
    /// 密钥已存在错误
    pub fn key_exists(handle: KeyHandle) -> Self {
        Error::KeyError(format!("Key already exists: {:?}", handle))
    }
    
    /// 存储IO错误
    pub fn storage_io(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
    
    /// 序列化错误
    pub fn serialization(err: impl std::fmt::Display) -> Self {
        Error::EncodingError(format!("Serialization error: {}", err))
    }
    
    /// 反序列化错误
    pub fn deserialization(err: impl std::fmt::Display) -> Self {
        Error::EncodingError(format!("Deserialization error: {}", err))
    }
    
    /// 加密错误
    pub fn encryption(err: impl std::fmt::Display) -> Self {
        Error::KeyError(format!("Encryption error: {}", err))
    }
    
    /// 解密错误
    pub fn decryption(err: impl std::fmt::Display) -> Self {
        Error::KeyError(format!("Decryption error: {}", err))
    }
    
    /// HSM错误
    pub fn hsm(err: impl std::fmt::Display) -> Self {
        Error::Other(format!("HSM error: {}", err))
    }
    
    /// HSM不可用
    pub fn hsm_not_available() -> Self {
        Error::Other("HSM not available".to_string())
    }
    
    /// 无效配置
    pub fn invalid_configuration(msg: impl std::fmt::Display) -> Self {
        Error::Other(format!("Invalid configuration: {}", msg))
    }
    
    /// 权限拒绝
    pub fn permission_denied(msg: impl std::fmt::Display) -> Self {
        Error::Other(format!("Permission denied: {}", msg))
    }
    
    /// 锁错误
    pub fn lock_error(msg: impl std::fmt::Display) -> Self {
        Error::Other(format!("Lock error: {}", msg))
    }
}

/// 为serde_json::Error实现From trait
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::serialization(err)
    }
}