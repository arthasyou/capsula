//! 生命周期策略配置
//!
//! 定义证书生命周期管理的各种策略和配置

use serde::{Deserialize, Serialize};

/// 生命周期策略配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecyclePolicy {
    /// 续期策略
    pub renewal_policy: RenewalPolicy,
    /// 过期监控策略
    pub expiry_policy: ExpiryPolicy,
    /// 自动化策略
    pub automation_policy: AutomationPolicy,
    /// 吊销策略
    pub revocation_policy: RevocationPolicy,
}

/// 续期策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalPolicy {
    /// 续期提前通知天数
    pub advance_notification_days: u32,
    /// 允许过期后续期
    pub allow_expired_renewal: bool,
    /// 过期后宽限期（天）
    pub expired_renewal_grace_period_days: u32,
    /// 最大续期次数（None表示无限制）
    pub max_renewal_count: Option<u32>,
    /// 续期时自动延长有效期（天）
    pub renewal_extension_days: u32,
    /// 是否需要重新验证主体身份
    pub require_identity_revalidation: bool,
}

/// 过期监控策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiryPolicy {
    /// 过期警告阈值（天）
    pub warning_threshold_days: u32,
    /// 严重警告阈值（天）
    pub critical_threshold_days: u32,
    /// 检查频率（小时）
    pub check_frequency_hours: u32,
    /// 通知方式
    pub notification_methods: Vec<NotificationMethod>,
    /// 是否发送每日摘要
    pub daily_summary_enabled: bool,
}

/// 自动化策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationPolicy {
    /// 启用自动续期
    pub enable_auto_renewal: bool,
    /// 自动续期阈值（天）
    pub auto_renewal_threshold_days: u32,
    /// 自动续期适用的证书类型
    pub auto_renewal_certificate_types: Vec<String>,
    /// 启用自动吊销检查
    pub enable_auto_revocation_check: bool,
    /// 自动任务运行频率（小时）
    pub automation_frequency_hours: u32,
}

/// 吊销策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationPolicy {
    /// 默认吊销宽限期（小时）
    pub default_grace_period_hours: u32,
    /// 紧急吊销模式（跳过宽限期）
    pub emergency_revocation_enabled: bool,
    /// 吊销后通知相关方
    pub notify_relying_parties: bool,
    /// CRL更新频率（小时）
    pub crl_update_frequency_hours: u32,
}

/// 通知方式
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationMethod {
    /// 邮件通知
    Email { 
        recipients: Vec<String>,
        template: String,
    },
    /// 系统日志
    SystemLog {
        level: LogLevel,
    },
    /// Webhook通知
    Webhook {
        url: String,
        secret: Option<String>,
    },
    /// 文件通知
    FileOutput {
        path: String,
        format: OutputFormat,
    },
}

/// 日志级别
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Critical,
}

/// 输出格式
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Csv,
    PlainText,
}

/// 策略违规类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// 违规类型
    pub violation_type: ViolationType,
    /// 证书序列号
    pub certificate_serial: String,
    /// 违规描述
    pub description: String,
    /// 违规严重程度
    pub severity: ViolationSeverity,
    /// 建议操作
    pub recommended_action: String,
}

/// 违规类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationType {
    /// 过期未续期
    ExpiredNotRenewed,
    /// 超过最大续期次数
    ExceededMaxRenewals,
    /// 未经授权的操作
    UnauthorizedOperation,
    /// 策略配置冲突
    PolicyConfigConflict,
}

/// 违规严重程度
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// 策略模板
pub struct PolicyTemplate;

impl PolicyTemplate {
    /// 开发环境策略模板
    pub fn development() -> LifecyclePolicy {
        LifecyclePolicy {
            renewal_policy: RenewalPolicy {
                advance_notification_days: 7,
                allow_expired_renewal: true,
                expired_renewal_grace_period_days: 30,
                max_renewal_count: None,
                renewal_extension_days: 365,
                require_identity_revalidation: false,
            },
            expiry_policy: ExpiryPolicy {
                warning_threshold_days: 30,
                critical_threshold_days: 7,
                check_frequency_hours: 24,
                notification_methods: vec![
                    NotificationMethod::SystemLog {
                        level: LogLevel::Info,
                    }
                ],
                daily_summary_enabled: false,
            },
            automation_policy: AutomationPolicy {
                enable_auto_renewal: false,
                auto_renewal_threshold_days: 7,
                auto_renewal_certificate_types: vec!["development".to_string()],
                enable_auto_revocation_check: false,
                automation_frequency_hours: 24,
            },
            revocation_policy: RevocationPolicy {
                default_grace_period_hours: 1,
                emergency_revocation_enabled: true,
                notify_relying_parties: false,
                crl_update_frequency_hours: 24,
            },
        }
    }

    /// 生产环境策略模板
    pub fn production() -> LifecyclePolicy {
        LifecyclePolicy {
            renewal_policy: RenewalPolicy {
                advance_notification_days: 30,
                allow_expired_renewal: false,
                expired_renewal_grace_period_days: 7,
                max_renewal_count: Some(10),
                renewal_extension_days: 365,
                require_identity_revalidation: true,
            },
            expiry_policy: ExpiryPolicy {
                warning_threshold_days: 60,
                critical_threshold_days: 14,
                check_frequency_hours: 6,
                notification_methods: vec![
                    NotificationMethod::Email {
                        recipients: vec!["admin@example.com".to_string()],
                        template: "expiry_warning".to_string(),
                    },
                    NotificationMethod::SystemLog {
                        level: LogLevel::Warning,
                    }
                ],
                daily_summary_enabled: true,
            },
            automation_policy: AutomationPolicy {
                enable_auto_renewal: true,
                auto_renewal_threshold_days: 30,
                auto_renewal_certificate_types: vec!["server".to_string(), "client".to_string()],
                enable_auto_revocation_check: true,
                automation_frequency_hours: 6,
            },
            revocation_policy: RevocationPolicy {
                default_grace_period_hours: 24,
                emergency_revocation_enabled: true,
                notify_relying_parties: true,
                crl_update_frequency_hours: 6,
            },
        }
    }
}

impl Default for LifecyclePolicy {
    fn default() -> Self {
        PolicyTemplate::development()
    }
}

impl LifecyclePolicy {
    /// 验证策略配置的一致性
    pub fn validate(&self) -> Result<(), Vec<PolicyViolation>> {
        let mut violations = Vec::new();

        // 检查过期策略阈值
        if self.expiry_policy.critical_threshold_days >= self.expiry_policy.warning_threshold_days {
            violations.push(PolicyViolation {
                violation_type: ViolationType::PolicyConfigConflict,
                certificate_serial: "POLICY".to_string(),
                description: "Critical threshold should be less than warning threshold".to_string(),
                severity: ViolationSeverity::High,
                recommended_action: "Adjust threshold values to ensure critical < warning".to_string(),
            });
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_templates() {
        let dev_policy = PolicyTemplate::development();
        assert!(dev_policy.renewal_policy.allow_expired_renewal);
        assert!(!dev_policy.automation_policy.enable_auto_renewal);

        let prod_policy = PolicyTemplate::production();
        assert!(!prod_policy.renewal_policy.allow_expired_renewal);
        assert!(prod_policy.automation_policy.enable_auto_renewal);
    }

    #[test]
    fn test_policy_validation() {
        let mut policy = PolicyTemplate::development();
        
        // 测试有效策略
        assert!(policy.validate().is_ok());

        // 测试无效策略 - 阈值配置错误
        policy.expiry_policy.critical_threshold_days = 100;
        policy.expiry_policy.warning_threshold_days = 50;
        let result = policy.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }
}