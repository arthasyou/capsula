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

    /// CSR相关错误
    #[error("CSR error: {0}")]
    CsrError(String),

    /// 存储相关错误
    #[error("Store error: {0}")]
    StoreError(String),

    /// 证书链验证错误
    #[error("Chain validation error: {0}")]
    ChainError(String),

    /// 生命周期管理错误
    #[error("Lifecycle management error: {0}")]
    LifecycleError(String),

    /// 证书已存在
    #[error("Certificate already exists: {0}")]
    CertificateExists(String),

    /// 证书未找到
    #[error("Certificate not found: {0}")]
    CertificateNotFound(String),

    /// 通用资源未找到错误
    #[error("Not found: {0}")]
    NotFound(String),

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

    /// 身份认证错误
    #[error("Authentication error: {0}")]
    AuthError(String),

    /// 策略违反错误
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// IO错误
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// 序列化错误
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Capsula Key错误
    #[error("Capsula key error: {0}")]
    CapsulaKeyError(#[from] capsula_key::error::Error),
}

/// Result类型别名
pub type Result<T> = std::result::Result<T, PkiError>;
