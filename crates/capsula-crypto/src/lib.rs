//! Capsula Crypto - 基础加密原语库
//!
//! 提供密钥管理、数字签名和哈希功能

pub mod cert;
pub mod error;
pub mod hash;
pub mod key;
pub mod signature;

// 重新导出常用类型
pub use cert::{
    create_certificate, export_certificate, import_certificate, parse_certificate,
    sign_certificate, verify_certificate, CertificateInfo, CertificateSigningRequest,
    CertificateSubject, X509Certificate,
};
pub use error::{Error, Result};
pub use hash::{hash_data, hash_data_hex, sha256, sha512, verify_hash, HashAlgorithm};
pub use key::ecc::EccKeyPair;
pub use signature::ecc::{DigitalSignature, LocationInfo, SignError};

/// 预导入模块，包含最常用的类型和函数
pub mod prelude {
    pub use crate::{
        error::{Error, Result},
        hash::{sha256, sha512, HashAlgorithm},
        key::ecc::EccKeyPair,
        signature::ecc::DigitalSignature,
    };
}
