//! RA证书申请处理器
//!
//! 将验证、身份认证和确认决策整合在一起的核心处理器

use crate::error::{PkiError, Result};
use crate::ra::{
    Confirmer, ConfirmationResult, Context, Csr, Evaluator, ValidationOutcome, Validator,
    X509Certificate,
};

/// RA证书申请处理器
/// 
/// 整合验证、身份认证和确认决策的完整流程
pub struct Processor {
    /// CSR验证器
    validator: Validator,
    /// 身份认证评估器
    identity_evaluator: Evaluator,
    /// 确认决策器
    confirmer: Confirmer,
}

/// 处理结果
#[derive(Debug, Clone)]
pub struct ProcessingResult {
    /// 验证结果
    pub validation: ValidationOutcome,
    /// 确认结果
    pub confirmation: ConfirmationResult,
    /// 是否可以签发证书
    pub can_issue_certificate: bool,
    /// 处理总结
    pub summary: String,
}

impl ProcessingResult {
    /// 是否成功
    pub fn is_success(&self) -> bool {
        self.can_issue_certificate
    }

    /// 是否需要人工干预
    pub fn requires_manual_review(&self) -> bool {
        self.confirmation.requires_review()
    }

    /// 是否被拒绝
    pub fn is_rejected(&self) -> bool {
        self.confirmation.is_rejected() || !self.validation.is_valid
    }
}

impl Processor {
    /// 创建新的处理器
    pub fn new(validator: Validator, identity_evaluator: Evaluator, confirmer: Confirmer) -> Self {
        Self {
            validator,
            identity_evaluator,
            confirmer,
        }
    }

    /// 创建默认处理器
    pub fn default() -> Self {
        Self {
            validator: Validator::default(),
            identity_evaluator: Evaluator::disabled(), // 默认禁用身份验证
            confirmer: Confirmer::default(),
        }
    }

    /// 处理证书申请
    pub fn process_request(&self, csr: &Csr, context: &Context) -> Result<ProcessingResult> {
        // 第一步：验证CSR
        let validation = self.validator.validate_csr(csr)?;
        
        // 如果CSR验证失败，直接返回
        if !validation.is_valid {
            return Ok(ProcessingResult {
                validation: validation.clone(),
                confirmation: ConfirmationResult::new(
                    crate::ra::Decision::Rejected,
                    0,
                    "CSR验证失败".to_string(),
                ),
                can_issue_certificate: false,
                summary: format!("CSR验证失败: {:?}", validation.issues),
            });
        }

        // 第二步：身份认证评估
        let auth_result = self.identity_evaluator.evaluate_trust(context, &[])?;
        
        // 第三步：确认决策
        let confirmation = self.confirmer.confirm(&auth_result);
        
        // 第四步：综合决策
        let can_issue_certificate = validation.is_valid && confirmation.is_approved();
        
        let summary = if can_issue_certificate {
            format!(
                "处理成功: 信任级别 {}, 验证通过",
                confirmation.trust_level
            )
        } else if confirmation.requires_review() {
            format!(
                "需要人工审核: 信任级别 {}, {}",
                confirmation.trust_level, confirmation.reason
            )
        } else {
            format!(
                "处理拒绝: {}",
                confirmation.reason
            )
        };

        Ok(ProcessingResult {
            validation,
            confirmation,
            can_issue_certificate,
            summary,
        })
    }

    /// 处理并签发证书
    pub fn process_and_issue(
        &self,
        csr: &Csr,
        context: &Context,
        _ca_cert: &X509Certificate,
        _ca_private_key: &[u8],
    ) -> Result<X509Certificate> {
        // 处理申请
        let result = self.process_request(csr, context)?;
        
        // 检查是否可以签发
        if !result.can_issue_certificate {
            return Err(PkiError::ValidationError(format!(
                "无法签发证书: {}",
                result.summary
            )));
        }

        // TODO: 签发证书需要更多参数，这里先返回错误
        Err(PkiError::SigningError(
            "签发证书功能传入参数不完整，需要CertificateInfo".to_string()
        ))
    }

    /// 批量处理申请
    pub fn batch_process(
        &self,
        requests: &[(Csr, Context)],
    ) -> Vec<Result<ProcessingResult>> {
        requests
            .iter()
            .map(|(csr, context)| self.process_request(csr, context))
            .collect()
    }

    /// 获取处理统计
    pub fn get_statistics(&self, results: &[ProcessingResult]) -> ProcessingStats {
        let total = results.len();
        let approved = results.iter().filter(|r| r.is_success()).count();
        let rejected = results.iter().filter(|r| r.is_rejected()).count();
        let pending = total - approved - rejected;

        ProcessingStats {
            total,
            approved,
            rejected,
            pending,
            approval_rate: if total > 0 { approved as f64 / total as f64 } else { 0.0 },
        }
    }
}

/// 处理统计
#[derive(Debug, Clone)]
pub struct ProcessingStats {
    /// 总请求数
    pub total: usize,
    /// 通过数
    pub approved: usize,
    /// 拒绝数
    pub rejected: usize,
    /// 待审核数
    pub pending: usize,
    /// 通过率
    pub approval_rate: f64,
}

impl ProcessingStats {
    /// 格式化统计信息
    pub fn format(&self) -> String {
        format!(
            "总计: {}, 通过: {}, 拒绝: {}, 待审核: {}, 通过率: {:.1}%",
            self.total,
            self.approved,
            self.rejected,
            self.pending,
            self.approval_rate * 100.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ra::*;

    #[test]
    fn test_processor_creation() {
        let _processor = Processor::default();
        assert!(true); // 基本创建测试
    }

    #[test]
    fn test_processing_stats() {
        let results = vec![
            ProcessingResult {
                validation: ValidationOutcome {
                    is_valid: true,
                    issues: vec![],
                    score: 90,
                    trust_level: 80,
                },
                confirmation: ConfirmationResult::new(
                    Decision::Approved,
                    80,
                    "通过".to_string(),
                ),
                can_issue_certificate: true,
                summary: "成功".to_string(),
            },
            ProcessingResult {
                validation: ValidationOutcome {
                    is_valid: false,
                    issues: vec![],
                    score: 30,
                    trust_level: 20,
                },
                confirmation: ConfirmationResult::new(
                    Decision::Rejected,
                    20,
                    "拒绝".to_string(),
                ),
                can_issue_certificate: false,
                summary: "失败".to_string(),
            },
        ];

        let processor = Processor::default();
        let stats = processor.get_statistics(&results);
        
        assert_eq!(stats.total, 2);
        assert_eq!(stats.approved, 1);
        assert_eq!(stats.rejected, 1);
        assert_eq!(stats.pending, 0);
        assert_eq!(stats.approval_rate, 0.5);
    }
}