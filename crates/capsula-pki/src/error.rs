use thiserror::Error;

/// PKI模块的错误类型
#[derive(Error, Debug)]
pub enum PkiError {
    /// 证书相关错误
    #[error("Certificate error: {0}")]
    CertError(String),

    /// CA相关错误
    #[error("CA error: {0}")]
    CAError(String),

    /// CRL相关错误
    #[error("CRL error: {0}")]
    CRLError(String),

    /// 存储相关错误
    #[error("Store error: {0}")]
    StoreError(String),

    /// 证书链验证错误
    #[error("Chain validation error: {0}")]
    ChainError(String),

    /// 证书已存在
    #[error("Certificate already exists: {0}")]
    CertificateExists(String),

    /// 证书未找到
    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),

    /// 证书已撤销
    #[error("Certificate revoked: {0}")]
    CertificateRevoked(String),

    /// 无效的证书链
    #[error("Invalid certificate chain")]
    InvalidChain,

    /// 验证错误
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// 解析错误
    #[error("Parse error: {0}")]
    ParseError(String),

    /// 导入错误
    #[error("Import error: {0}")]
    ImportError(String),

    /// 导出错误
    #[error("Export error: {0}")]
    ExportError(String),

    /// 签名错误
    #[error("Signature error: {0}")]
    SignatureError(String),

    /// 证书生成错误
    #[error("Generation error: {0}")]
    GenerationError(String),

    /// 签名错误
    #[error("Signing error: {0}")]
    SigningError(String),

    /// 证书已过期
    #[error("Certificate expired")]
    CertificateExpired,

    /// 证书尚未生效
    #[error("Certificate not yet valid")]
    CertificateNotYetValid,

    /// 密钥错误
    #[error("Key error: {0}")]
    KeyError(String),

    /// IO错误
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// 序列化错误
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Result类型别名
pub type Result<T> = std::result::Result<T, PkiError>;

/// 从本模块的 Error 类型重新导出
#[derive(Error, Debug)]
pub enum Error {
    /// 密钥相关错误
    #[error("Key error: {0}")]
    KeyError(String),

    /// 签名相关错误
    #[error("Signature error: {0}")]
    SignatureError(String),

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

    /// 系统时间错误
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    /// 其他错误
    #[error("Other error: {0}")]
    Other(String),
}
