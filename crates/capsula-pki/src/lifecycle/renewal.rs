//! 证书续期管理模块
//!
//! 提供证书续期功能，包括续期策略、续期请求处理和续期结果管理

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use std::collections::HashMap;

use crate::{
    error::{PkiError, Result as PkiResult},
    ca::Manager as CAManager,
};

use super::policy::RenewalPolicy;

/// 续期管理器
pub struct RenewalManager {
    /// 续期策略
    policy: RenewalPolicy,
    /// 续期历史记录
    renewal_history: HashMap<String, Vec<RenewalRecord>>,
}

/// 续期请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalRequest {
    /// 证书序列号
    pub certificate_serial: String,
    /// 续期原因
    pub reason: RenewalReason,
    /// 请求者
    pub requested_by: String,
    /// 新的有效期（天数）
    pub new_validity_days: Option<u32>,
    /// 是否强制续期（忽略策略限制）
    pub force_renewal: bool,
    /// 续期时间戳
    pub requested_at: OffsetDateTime,
}

/// 续期结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalResult {
    /// 原证书序列号
    pub original_serial: String,
    /// 新证书序列号
    pub new_serial: String,
    /// 新证书（PEM格式）
    pub new_certificate_pem: Option<String>,
    /// 新的过期日期
    pub new_expiry_date: OffsetDateTime,
    /// 续期原因
    pub renewal_reason: String,
    /// 处理者
    pub renewed_by: String,
    /// 续期时间
    pub renewed_at: OffsetDateTime,
    /// 续期状态
    pub status: RenewalStatus,
}

/// 续期原因
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RenewalReason {
    /// 即将过期
    Expiring,
    /// 密钥轮换
    KeyRotation,
    /// 配置更新
    ConfigUpdate,
    /// 安全要求
    SecurityRequirement,
    /// 手动续期
    Manual { reason: String },
    /// 自动续期
    Automatic,
}

/// 续期状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RenewalStatus {
    /// 续期成功
    Success,
    /// 续期失败
    Failed { error: String },
    /// 续期待处理
    Pending,
    /// 续期被拒绝
    Rejected { reason: String },
}

/// 续期记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalRecord {
    /// 续期请求
    pub request: RenewalRequest,
    /// 续期结果
    pub result: RenewalResult,
    /// 处理时间
    pub processed_at: OffsetDateTime,
}

impl RenewalManager {
    /// 创建新的续期管理器
    pub fn new(policy: RenewalPolicy) -> Self {
        Self {
            policy,
            renewal_history: HashMap::new(),
        }
    }

    /// 处理续期请求
    pub fn renew_certificate(
        &mut self,
        _ca_manager: &mut CAManager, // TODO: Use for actual CA operations
        request: RenewalRequest,
    ) -> PkiResult<RenewalResult> {
        // 验证续期请求
        self.validate_renewal_request(&request)?;

        // 检查续期策略
        if !request.force_renewal {
            self.check_renewal_policy(&request)?;
        }

        // 执行续期
        let renewal_result = self.perform_renewal(_ca_manager, &request)?;

        // 记录续期历史
        self.record_renewal(&request, &renewal_result)?;

        Ok(renewal_result)
    }

    /// 检查证书是否可以续期
    pub fn can_renew_certificate(&self, certificate_serial: &str) -> PkiResult<bool> {
        // 检查是否超过最大续期次数
        if let Some(max_count) = self.policy.max_renewal_count {
            let renewal_count = self.get_renewal_count(certificate_serial);
            if renewal_count >= max_count {
                return Ok(false);
            }
        }

        // 检查过期后续期策略
        if !self.policy.allow_expired_renewal {
            // TODO: 检查证书是否已过期
            // 这里需要从生命周期管理器获取证书状态
        }

        Ok(true)
    }

    /// 获取续期建议
    pub fn get_renewal_suggestion(&self, _certificate_serial: &str, days_until_expiry: u32) -> RenewalSuggestion {
        if days_until_expiry <= self.policy.advance_notification_days {
            if days_until_expiry <= 7 {
                RenewalSuggestion::Urgent {
                    days_left: days_until_expiry,
                    recommended_action: "立即续期以避免服务中断".to_string(),
                }
            } else {
                RenewalSuggestion::Recommended {
                    days_left: days_until_expiry,
                    recommended_action: "建议在未来几天内续期".to_string(),
                }
            }
        } else {
            RenewalSuggestion::NotNeeded {
                days_left: days_until_expiry,
                next_check_date: OffsetDateTime::now_utc() + 
                    time::Duration::days((days_until_expiry - self.policy.advance_notification_days) as i64),
            }
        }
    }

    /// 获取证书的续期历史
    pub fn get_renewal_history(&self, certificate_serial: &str) -> Vec<&RenewalRecord> {
        self.renewal_history
            .get(certificate_serial)
            .map(|records| records.iter().collect())
            .unwrap_or_default()
    }

    /// 获取续期次数
    pub fn get_renewal_count(&self, certificate_serial: &str) -> u32 {
        self.renewal_history
            .get(certificate_serial)
            .map(|records| records.len() as u32)
            .unwrap_or(0)
    }

    /// 更新续期策略
    pub fn update_policy(&mut self, new_policy: RenewalPolicy) {
        self.policy = new_policy;
    }

    // 私有方法

    /// 验证续期请求
    fn validate_renewal_request(&self, request: &RenewalRequest) -> PkiResult<()> {
        if request.certificate_serial.is_empty() {
            return Err(PkiError::LifecycleError("Certificate serial number is required".to_string()));
        }

        if request.requested_by.is_empty() {
            return Err(PkiError::LifecycleError("Requester information is required".to_string()));
        }

        // 验证新的有效期
        if let Some(validity_days) = request.new_validity_days {
            if validity_days == 0 || validity_days > 3650 { // 最长10年
                return Err(PkiError::LifecycleError("Invalid validity period".to_string()));
            }
        }

        Ok(())
    }

    /// 检查续期策略
    fn check_renewal_policy(&self, request: &RenewalRequest) -> PkiResult<()> {
        // 检查最大续期次数
        if let Some(max_count) = self.policy.max_renewal_count {
            let current_count = self.get_renewal_count(&request.certificate_serial);
            if current_count >= max_count {
                return Err(PkiError::LifecycleError(
                    format!("Certificate has exceeded maximum renewal count: {}/{}", current_count, max_count)
                ));
            }
        }

        // TODO: 检查其他策略限制
        // - 过期后续期检查
        // - 身份重新验证要求

        Ok(())
    }

    /// 执行证书续期
    fn perform_renewal(
        &mut self,
        _ca_manager: &mut CAManager, // TODO: Use for actual certificate renewal
        request: &RenewalRequest,
    ) -> PkiResult<RenewalResult> {
        // TODO: 实现实际的证书续期逻辑
        // 这里需要：
        // 1. 从CA管理器获取原证书
        // 2. 生成新的证书
        // 3. 保持相同的公钥和主体信息
        // 4. 更新有效期

        let new_validity_days = request.new_validity_days.unwrap_or(self.policy.renewal_extension_days);
        let new_expiry_date = OffsetDateTime::now_utc() + time::Duration::days(new_validity_days as i64);
        
        // 生成新的序列号
        let new_serial = format!("RENEWED-{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());

        let renewal_result = RenewalResult {
            original_serial: request.certificate_serial.clone(),
            new_serial: new_serial,
            new_certificate_pem: None, // TODO: 生成实际的新证书PEM
            new_expiry_date,
            renewal_reason: self.renewal_reason_to_string(&request.reason),
            renewed_by: request.requested_by.clone(),
            renewed_at: OffsetDateTime::now_utc(),
            status: RenewalStatus::Success,
        };

        Ok(renewal_result)
    }

    /// 记录续期历史
    fn record_renewal(&mut self, request: &RenewalRequest, result: &RenewalResult) -> PkiResult<()> {
        let record = RenewalRecord {
            request: request.clone(),
            result: result.clone(),
            processed_at: OffsetDateTime::now_utc(),
        };

        self.renewal_history
            .entry(request.certificate_serial.clone())
            .or_insert_with(Vec::new)
            .push(record);

        Ok(())
    }

    /// 将续期原因转换为字符串
    fn renewal_reason_to_string(&self, reason: &RenewalReason) -> String {
        match reason {
            RenewalReason::Expiring => "Certificate expiring".to_string(),
            RenewalReason::KeyRotation => "Key rotation".to_string(),
            RenewalReason::ConfigUpdate => "Configuration update".to_string(),
            RenewalReason::SecurityRequirement => "Security requirement".to_string(),
            RenewalReason::Manual { reason } => format!("Manual renewal: {}", reason),
            RenewalReason::Automatic => "Automatic renewal".to_string(),
        }
    }
}

/// 续期建议
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RenewalSuggestion {
    /// 紧急续期
    Urgent {
        days_left: u32,
        recommended_action: String,
    },
    /// 推荐续期
    Recommended {
        days_left: u32,
        recommended_action: String,
    },
    /// 暂不需要续期
    NotNeeded {
        days_left: u32,
        next_check_date: OffsetDateTime,
    },
}

impl Default for RenewalManager {
    fn default() -> Self {
        use super::policy::RenewalPolicy;
        
        Self::new(RenewalPolicy {
            advance_notification_days: 30,
            allow_expired_renewal: false,
            expired_renewal_grace_period_days: 7,
            max_renewal_count: Some(10),
            renewal_extension_days: 365,
            require_identity_revalidation: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_renewal_manager_creation() {
        let policy = RenewalPolicy {
            advance_notification_days: 30,
            allow_expired_renewal: true,
            expired_renewal_grace_period_days: 7,
            max_renewal_count: Some(5),
            renewal_extension_days: 365,
            require_identity_revalidation: false,
        };
        
        let manager = RenewalManager::new(policy);
        assert_eq!(manager.policy.advance_notification_days, 30);
        assert!(manager.policy.allow_expired_renewal);
    }

    #[test]
    fn test_renewal_request_validation() {
        let manager = RenewalManager::default();
        
        // 有效请求
        let valid_request = RenewalRequest {
            certificate_serial: "CERT-12345".to_string(),
            reason: RenewalReason::Expiring,
            requested_by: "admin@example.com".to_string(),
            new_validity_days: Some(365),
            force_renewal: false,
            requested_at: OffsetDateTime::now_utc(),
        };
        
        assert!(manager.validate_renewal_request(&valid_request).is_ok());
        
        // 无效请求 - 空序列号
        let invalid_request = RenewalRequest {
            certificate_serial: "".to_string(),
            reason: RenewalReason::Expiring,
            requested_by: "admin@example.com".to_string(),
            new_validity_days: Some(365),
            force_renewal: false,
            requested_at: OffsetDateTime::now_utc(),
        };
        
        assert!(manager.validate_renewal_request(&invalid_request).is_err());
    }

    #[test]
    fn test_renewal_suggestions() {
        let manager = RenewalManager::default();
        
        // 紧急续期建议
        let urgent = manager.get_renewal_suggestion("CERT-123", 5);
        assert!(matches!(urgent, RenewalSuggestion::Urgent { .. }));
        
        // 推荐续期
        let recommended = manager.get_renewal_suggestion("CERT-123", 20);
        assert!(matches!(recommended, RenewalSuggestion::Recommended { .. }));
        
        // 暂不需要续期
        let not_needed = manager.get_renewal_suggestion("CERT-123", 100);
        assert!(matches!(not_needed, RenewalSuggestion::NotNeeded { .. }));
    }

    #[test]
    fn test_renewal_count_tracking() {
        let mut manager = RenewalManager::default();
        let serial = "CERT-12345";
        
        // 初始续期次数应为0
        assert_eq!(manager.get_renewal_count(serial), 0);
        
        // 模拟续期记录
        let request = RenewalRequest {
            certificate_serial: serial.to_string(),
            reason: RenewalReason::Expiring,
            requested_by: "admin@example.com".to_string(),
            new_validity_days: Some(365),
            force_renewal: false,
            requested_at: OffsetDateTime::now_utc(),
        };
        
        let result = RenewalResult {
            original_serial: serial.to_string(),
            new_serial: "RENEWED-12345".to_string(),
            new_certificate_pem: None,
            new_expiry_date: OffsetDateTime::now_utc() + time::Duration::days(365),
            renewal_reason: "Certificate expiring".to_string(),
            renewed_by: "admin@example.com".to_string(),
            renewed_at: OffsetDateTime::now_utc(),
            status: RenewalStatus::Success,
        };
        
        manager.record_renewal(&request, &result).unwrap();
        
        // 续期次数应为1
        assert_eq!(manager.get_renewal_count(serial), 1);
        
        // 续期历史应包含1条记录
        let history = manager.get_renewal_history(serial);
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_max_renewal_count_policy() {
        let policy = RenewalPolicy {
            advance_notification_days: 30,
            allow_expired_renewal: false,
            expired_renewal_grace_period_days: 7,
            max_renewal_count: Some(2), // 最多续期2次
            renewal_extension_days: 365,
            require_identity_revalidation: false,
        };
        
        let manager = RenewalManager::new(policy);
        let serial = "CERT-12345";
        
        // 初始应该可以续期
        assert!(manager.can_renew_certificate(serial).unwrap());
    }
}