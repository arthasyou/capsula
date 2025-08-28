//! Capsula PKI - 公钥基础设施库
//!
//! 提供完整的PKI功能，包括证书管理、CA、CRL等

pub mod ca;
pub mod cert;
pub mod chain;
pub mod crl;
pub mod error;
pub mod key;
pub mod store;
pub mod types;

// 重新导出常用类型
pub use ca::{CAConfig, CAExport, CertificateAuthority};
// 重新导出证书相关类型
pub use cert::{
    create_certificate, export_certificate, import_certificate, parse_certificate,
    sign_certificate, verify_certificate, CertificateInfo, CertificateSubject, X509Certificate,
};
pub use chain::{build_certificate_chain, ChainValidator, ValidationResult};
pub use crl::{CRLManager, CertificateRevocationList, RevocationEntry};
pub use error::{PkiError, Result};
pub use store::{CertificateStore, FileSystemBackend, StorageBackend};
pub use types::{CertificateMetadata, CertificateStatus, RevocationReason};

/// 预导入模块，包含最常用的类型和函数
pub mod prelude {
    pub use crate::{
        ca::{CAConfig, CertificateAuthority},
        chain::ChainValidator,
        crl::CertificateRevocationList,
        error::{PkiError, Result},
        store::CertificateStore,
        types::{CertificateStatus, RevocationReason},
    };
    pub use crate::cert::{create_certificate, CertificateSubject, X509Certificate};
}
