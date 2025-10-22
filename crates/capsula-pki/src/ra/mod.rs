//! RA (Registration Authority) 模块
//!
//! 提供注册机构功能，包括：
//! - CSR接收与验证
//! - 身份认证与信任评估
//! - 证书申请确认决策

pub mod approval;
pub mod cert;
pub mod csr;
pub mod identity;
pub mod processor;
pub mod validation;

// 重新导出主要类型和函数
// 确认决策模块
pub use approval::{ConfirmationPolicy, ConfirmationResult, Confirmer, Decision};
pub use cert::{
    create_certificate, create_self_signed_certificate, export_certificate, import_certificate,
    parse_certificate, sign_certificate, verify_certificate, CertificateInfo, CertificateSubject,
    X509Certificate,
};
pub use csr::{build_unsigned, create_csr, CertReqInfo, Csr, CsrSubject, PublicKeyInfo};
// 身份认证模块 - 使用新的类型名称
pub use identity::{
    AuthOutcome, Context, Credential, Credentials, Evaluator, IdentityType, Policy as TrustPolicy,
    VerificationMethod,
};
// RA处理器模块
pub use processor::{ProcessingResult, ProcessingStats, Processor};
// 验证模块
pub use validation::{
    ValidationIssue, ValidationOutcome, ValidationPolicy, ValidationSeverity, Validator,
};

/// RA配置
#[derive(Debug, Clone)]
pub struct RAConfig {
    /// RA名称
    pub name: String,
    /// 确认策略配置
    pub confirmation_policy: ConfirmationPolicy,
    /// 信任评估策略
    pub trust_policy: TrustPolicy,
    /// 验证策略
    pub validation_policy: ValidationPolicy,
    /// 最大待处理请求数
    pub max_pending_requests: usize,
}

impl Default for RAConfig {
    fn default() -> Self {
        Self {
            name: "Default RA".to_string(),
            confirmation_policy: ConfirmationPolicy::new(80),
            trust_policy: TrustPolicy::default(),
            validation_policy: ValidationPolicy::default(),
            max_pending_requests: 1000,
        }
    }
}

impl RAConfig {
    /// 创建新的RA配置
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// 设置确认策略
    pub fn with_confirmation_policy(mut self, policy: ConfirmationPolicy) -> Self {
        self.confirmation_policy = policy;
        self
    }

    /// 设置信任评估策略  
    pub fn with_trust_policy(mut self, policy: TrustPolicy) -> Self {
        self.trust_policy = policy;
        self
    }

    /// 设置验证策略
    pub fn with_validation_policy(mut self, policy: ValidationPolicy) -> Self {
        self.validation_policy = policy;
        self
    }
}
