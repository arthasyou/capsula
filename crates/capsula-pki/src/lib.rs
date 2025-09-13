//! Capsula PKI - 公钥基础设施库
//!
//! 提供完整的PKI功能，按照5大核心模块组织：
//!
//! ## 核心模块
//!
//! ### 1. CA (Certificate Authority) - 证书颁发机构
//! - 根证书生成与管理（Root CA）
//! - 中间证书管理（Intermediate CA）
//! - 签发数字证书（X.509）
//! - 支持多种算法（RSA、ECC、Ed25519 等）
//!
//! ### 2. RA (Registration Authority) - 注册机构
//! - 接收并验证证书请求（CSR）
//! - 身份认证（个人/设备/服务）
//! - 审批流程控制（手动/自动）
//!
//! ### 3. Lifecycle - 证书生命周期管理
//! - 证书签发
//! - 证书更新（renewal）
//! - 证书吊销（revocation）
//! - 证书过期通知
//! - 证书链验证
//!
//! ### 4. Status - 证书状态查询
//! - CRL（证书吊销列表）
//! - OCSP（在线证书状态协议）
//! - 证书状态验证
//!
//! ### 5. Keystore - 密钥管理
//! - 私钥生成（支持 HSM、软硬件）
//! - 密钥托管与导出（可选）
//! - 密钥恢复/轮换
//! - 存储后端管理

// 核心5大模块
pub mod ca;
pub mod keystore;
pub mod lifecycle;
pub mod ra;
pub mod status;

// 通用模块
pub mod error;
pub mod types;

// 重新导出核心类型
// CA 模块
// pub use ca::{CAConfig, CAExport, CertificateAuthority};

// RA 模块 - 重新导出证书和CSR相关类型
// 错误类型
pub use error::{PkiError, Result};
// Keystore 模块
pub use keystore::{
    CertificateStore, FileSystemBackend, KeyGenerationConfig, KeyType, KeyUsage, KeystoreManager,
    StorageBackend,
};
// Lifecycle 模块
pub use lifecycle::{
    build_certificate_chain, ChainValidator, LifecycleManager, LifecyclePolicy, ValidationResult,
};
pub use ra::{
    // CSR相关
    build_unsigned,
    // 证书相关
    create_certificate,
    create_csr,
    create_self_signed_certificate,
    export_certificate,
    import_certificate,
    parse_certificate,
    sign_certificate,
    verify_certificate,
    CertReqInfo,
    CertificateInfo,
    CertificateSigningRequest,
    CertificateSubject,
    Csr,
    CsrSubject,
    // RA配置
    RAConfig,
    X509Certificate,
};
// Status 模块
pub use status::{
    CRLManager, CertificateRevocationList, CertificateStatus, CertificateStatusManager,
    RevocationEntry, RevocationReason,
};
// 通用类型
pub use types::CertificateMetadata;

/// 预导入模块，包含最常用的类型和函数
pub mod prelude {
    // RA 模块 - 证书和CSR操作
    // 错误处理
    pub use crate::error::{PkiError, Result};
    // Keystore 模块
    pub use crate::keystore::{CertificateStore, KeyGenerationConfig, KeystoreManager};
    // CA 模块
    // pub use crate::ca::{CAConfig, CertificateAuthority};

    // Lifecycle 模块
    pub use crate::lifecycle::{ChainValidator, LifecycleManager, LifecyclePolicy};
    pub use crate::ra::{
        // CSR操作
        build_unsigned,
        // 证书操作
        create_certificate,
        create_csr,
        create_self_signed_certificate,
        CertReqInfo,
        CertificateInfo,
        CertificateSigningRequest,
        CertificateSubject,
        Csr,
        CsrSubject,
        // RA配置
        RAConfig,
        X509Certificate,
    };
    // Status 模块
    pub use crate::status::{
        CertificateRevocationList, CertificateStatus, CertificateStatusManager, RevocationReason,
    };
}
