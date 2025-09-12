use thiserror::Error;

/// Crypto模块的错误类型
#[derive(Error, Debug)]
pub enum Error {
    #[error("Getrandom error: {0}")]
    GetrandomError(String),

    #[error("PKCS8 error: {0}")]
    Pkcs8Error(#[from] pkcs8::Error),

    #[error("SPKI error: {0}")]
    SpkiError(#[from] pkcs8::spki::Error),

    #[error("Ed25519 error: {0}")]
    Ed25519Error(#[from] ed25519_dalek::ed25519::Error),

    #[error("RSA error: {0}")]
    RsaError(#[from] rsa::Error),

    #[error("P256 error: {0}")]
    P256Error(#[from] p256::elliptic_curve::Error),

    #[error("DER error: {0}")]
    DerError(#[from] pkcs8::der::Error),

    /// 系统时间错误
    #[error("System time error: {0}")]
    SystemTimeError(#[from] std::time::SystemTimeError),

    /// 其他错误
    #[error("Other error: {0}")]
    Other(String),
}

/// Result类型别名
pub type Result<T> = std::result::Result<T, Error>;
