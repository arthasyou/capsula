//! 请求验证模块
//!
//! 提供CSR请求的完整性和合规性验证

use crate::ra::csr::CertificateSigningRequest;
use crate::error::Result;

/// 验证结果
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// 是否通过验证
    pub is_valid: bool,
    /// 错误消息
    pub errors: Vec<String>,
    /// 验证分数 (0-100)
    pub score: u8,
}

/// 请求验证器
pub struct RequestValidator;

impl RequestValidator {
    /// 创建新的请求验证器
    pub fn new() -> Self {
        Self
    }

    /// 验证CSR请求
    pub fn validate_csr(&self, csr: &CertificateSigningRequest) -> Result<ValidationResult> {
        let mut errors = Vec::new();
        let mut score = 100u8;

        // 基本验证：检查CSR签名
        match csr.verify() {
            Ok(true) => {
                // 签名有效
            }
            Ok(false) => {
                errors.push("Invalid CSR signature".to_string());
                score = score.saturating_sub(50);
            }
            Err(e) => {
                errors.push(format!("CSR verification failed: {}", e));
                score = score.saturating_sub(50);
            }
        }

        // 检查主题信息
        let subject_info = csr.get_subject_info();
        if subject_info.common_name.is_empty() {
            errors.push("Common Name is required".to_string());
            score = score.saturating_sub(20);
        }

        Ok(ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            score,
        })
    }
}