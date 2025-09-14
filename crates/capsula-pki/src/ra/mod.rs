//! RA (Registration Authority) 模块
//!
//! 提供注册机构功能，包括：
//! - CSR接收与验证
//! - 身份认证（个人/设备/服务）
//! - 审批流程控制（手动/自动）

pub mod approval;
pub mod cert;
pub mod csr;
pub mod identity;
pub mod validation;

// 重新导出CSR和证书相关类型
pub use cert::{
    create_certificate, create_self_signed_certificate, export_certificate, import_certificate,
    parse_certificate, sign_certificate, verify_certificate, CertificateInfo, CertificateSubject,
    X509Certificate,
};
pub use csr::{build_unsigned, create_csr, CertReqInfo, Csr, CsrSubject, PublicKeyInfo};
pub use identity::{
    AuthResult, IdentityAuth, IdentityContext, IdentityType, TrustEvaluator,
    TrustPolicy as IdentityTrustPolicy, VerificationCredential, VerificationMethod,
};
pub use validation::{
    ValidationIssue, ValidationOutcome, ValidationPolicy, ValidationSeverity, Validator,
};

/// RA配置
#[derive(Debug, Clone)]
pub struct RAConfig {
    /// RA名称
    pub name: String,
    /// 自动审批阈值
    pub auto_approval_threshold: u8,
    /// 启用身份验证
    pub enable_identity_verification: bool,
    /// 最大待处理请求数
    pub max_pending_requests: usize,
}

impl Default for RAConfig {
    fn default() -> Self {
        Self {
            name: "Default RA".to_string(),
            auto_approval_threshold: 80,
            enable_identity_verification: true,
            max_pending_requests: 1000,
        }
    }
}
