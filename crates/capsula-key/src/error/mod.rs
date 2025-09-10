mod store;

use thiserror::Error;

/// Crypto模块的错误类型
#[derive(Error, Debug)]
pub enum Error {
    /// 密钥相关错误
    #[error("Key error: {0}")]
    KeyError(String),

    /// 签名相关错误
    #[error("Signature error: {0}")]
    SignatureError(String),

    /// 哈希相关错误
    #[error("Hash error: {0}")]
    HashError(String),

    /// 证书相关错误
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// 证书生成错误
    #[error("Certificate generation error: {0}")]
    GenerationError(String),

    /// 证书签名错误
    #[error("Certificate signing error: {0}")]
    SigningError(String),

    /// 证书解析错误
    #[error("Certificate parse error: {0}")]
    ParseError(String),

    /// 证书导出错误
    #[error("Certificate export error: {0}")]
    ExportError(String),

    /// 证书导入错误
    #[error("Certificate import error: {0}")]
    ImportError(String),

    /// 证书已过期
    #[error("Certificate has expired")]
    CertificateExpired,

    /// 证书尚未生效
    #[error("Certificate is not yet valid")]
    CertificateNotYetValid,

    /// 无效的密钥长度
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    /// 无效的签名
    #[error("Invalid signature")]
    InvalidSignature,

    /// 编码/解码错误
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// IO错误
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    CryptoError(#[from] capsula_crypto::error::Error),

    /// 系统时间错误
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    /// 其他错误
    #[error("Other error: {0}")]
    Other(String),
}

/// Result类型别名
pub type Result<T> = std::result::Result<T, Error>;
