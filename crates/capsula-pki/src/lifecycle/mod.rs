//! 证书生命周期管理模块
//!
//! 提供完整的证书生命周期管理功能，包括：
//! - 证书续期管理 (Certificate Renewal)
//! - 证书吊销管理 (Certificate Revocation)
//! - 过期监控和通知 (Expiry Monitoring & Notification)
//! - 自动化生命周期管理 (Automated Lifecycle Management)
//! - 生命周期策略配置 (Lifecycle Policy Configuration)

pub mod automation;
pub mod expiry;
pub mod policy;
pub mod renewal;
pub mod revocation;

// 重新导出主要类型
use std::collections::HashMap;

pub use automation::{AutomationAction, AutomationEngine, AutomationEvent, AutomationTask};
pub use expiry::{DailySummary, ExpiryAlert, ExpiryCheckResult, ExpiryMonitor, ExpiryNotification};
pub use policy::{
    AutomationPolicy, ExpiryPolicy, LifecyclePolicy, PolicyTemplate, PolicyViolation,
    RenewalPolicy, RevocationPolicy,
};
pub use renewal::{RenewalManager, RenewalReason, RenewalRequest, RenewalResult};
pub use revocation::{RevocationEntry, RevocationManager, RevocationReason, RevocationRequest};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    ca::Manager as CAManager,
    error::{PkiError, Result as PkiResult},
    ra::cert::X509Certificate,
};

/// 证书生命周期状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CertificateStatus {
    /// 有效
    Valid,
    /// 即将过期 (X天内过期)
    Expiring(u32),
    /// 已过期
    Expired,
    /// 已吊销
    Revoked {
        reason: RevocationReason,
        date: OffsetDateTime,
    },
    /// 暂停使用
    Suspended,
    /// 待续期
    PendingRenewal,
}

/// 证书生命周期信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateLifecycle {
    /// 证书序列号
    pub serial_number: String,
    /// 证书主题
    pub subject: String,
    /// 颁发日期
    pub issued_date: OffsetDateTime,
    /// 过期日期
    pub expiry_date: OffsetDateTime,
    /// 当前状态
    pub status: CertificateStatus,
    /// 颁发CA ID
    pub issuing_ca_id: String,
    /// 续期历史
    pub renewal_history: Vec<RenewalEntry>,
    /// 最后检查时间
    pub last_checked: OffsetDateTime,
}

/// 续期历史记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalEntry {
    /// 续期日期
    pub renewal_date: OffsetDateTime,
    /// 新的过期日期
    pub new_expiry_date: OffsetDateTime,
    /// 续期原因
    pub reason: String,
    /// 处理者
    pub renewed_by: String,
}

/// 生命周期管理器 - 统一管理证书生命周期
pub struct LifecycleManager {
    /// CA管理器引用
    ca_manager: CAManager,
    /// 续期管理器
    renewal_manager: RenewalManager,
    /// 吊销管理器
    revocation_manager: RevocationManager,
    /// 过期监控器
    expiry_monitor: ExpiryMonitor,
    /// 自动化引擎
    automation_engine: AutomationEngine,
    /// 生命周期策略
    lifecycle_policy: LifecyclePolicy,
    /// 证书生命周期数据存储
    certificates: HashMap<String, CertificateLifecycle>,
}

impl LifecycleManager {
    /// 创建新的生命周期管理器
    pub fn new(ca_manager: CAManager, lifecycle_policy: LifecyclePolicy) -> Self {
        let renewal_manager = RenewalManager::new(lifecycle_policy.renewal_policy.clone());
        let revocation_manager = RevocationManager::new();
        let expiry_monitor = ExpiryMonitor::new(lifecycle_policy.expiry_policy.clone());
        let automation_engine = AutomationEngine::new(lifecycle_policy.automation_policy.clone());

        Self {
            ca_manager,
            renewal_manager,
            revocation_manager,
            expiry_monitor,
            automation_engine,
            lifecycle_policy,
            certificates: HashMap::new(),
        }
    }

    /// 注册证书到生命周期管理
    pub fn register_certificate(
        &mut self,
        certificate: &X509Certificate,
        issuing_ca_id: String,
    ) -> PkiResult<()> {
        let subject = certificate.subject()?;
        let serial_number = self.extract_serial_number(certificate)?;

        let lifecycle = CertificateLifecycle {
            serial_number: serial_number.clone(),
            subject: subject.common_name,
            issued_date: OffsetDateTime::now_utc(), // TODO: 从证书中提取
            expiry_date: self.extract_expiry_date(certificate)?,
            status: CertificateStatus::Valid,
            issuing_ca_id,
            renewal_history: Vec::new(),
            last_checked: OffsetDateTime::now_utc(),
        };

        self.certificates.insert(serial_number, lifecycle);
        Ok(())
    }

    /// 检查所有证书的生命周期状态
    pub fn check_all_certificates(&mut self) -> PkiResult<Vec<CertificateLifecycle>> {
        let now = OffsetDateTime::now_utc();
        let mut updated_certificates = Vec::new();

        // 收集需要更新的证书信息
        let mut updates = Vec::new();
        for (serial, lifecycle) in self.certificates.iter() {
            let new_status = self.calculate_certificate_status(lifecycle, now)?;
            if new_status != lifecycle.status {
                updates.push((serial.clone(), new_status));
            }
        }

        // 应用更新
        for (serial, new_status) in updates {
            if let Some(lifecycle) = self.certificates.get_mut(&serial) {
                lifecycle.status = new_status;
                lifecycle.last_checked = now;
                updated_certificates.push(lifecycle.clone());
            }
        }

        Ok(updated_certificates)
    }

    /// 续期证书
    pub fn renew_certificate(
        &mut self,
        serial_number: &str,
        renewal_request: RenewalRequest,
    ) -> PkiResult<RenewalResult> {
        // 先检查证书是否存在并验证续期资格
        if let Some(lifecycle) = self.certificates.get(serial_number) {
            self.validate_renewal_eligibility(lifecycle)?;
        } else {
            return Err(PkiError::LifecycleError(format!(
                "Certificate {} not found",
                serial_number
            )));
        }

        // 执行续期
        let renewal_result = self
            .renewal_manager
            .renew_certificate(&mut self.ca_manager, renewal_request)?;

        // 更新生命周期记录
        let renewal_entry = RenewalEntry {
            renewal_date: OffsetDateTime::now_utc(),
            new_expiry_date: renewal_result.new_expiry_date,
            reason: renewal_result.renewal_reason.clone(),
            renewed_by: renewal_result.renewed_by.clone(),
        };

        // 现在可以安全地获取可变引用
        if let Some(lifecycle) = self.certificates.get_mut(serial_number) {
            lifecycle.expiry_date = renewal_result.new_expiry_date;
            lifecycle.status = CertificateStatus::Valid;
            lifecycle.renewal_history.push(renewal_entry);
            lifecycle.last_checked = OffsetDateTime::now_utc();
        }

        Ok(renewal_result)
    }

    /// 吊销证书
    pub fn revoke_certificate(
        &mut self,
        serial_number: &str,
        reason: RevocationReason,
        revoked_by: String,
    ) -> PkiResult<()> {
        let lifecycle = self.certificates.get_mut(serial_number).ok_or_else(|| {
            PkiError::LifecycleError(format!("Certificate {} not found", serial_number))
        })?;

        // 执行吊销
        let revocation_date = OffsetDateTime::now_utc();
        self.revocation_manager
            .revoke_certificate(serial_number, reason.clone(), revoked_by)?;

        // 更新生命周期记录
        lifecycle.status = CertificateStatus::Revoked {
            reason,
            date: revocation_date,
        };
        lifecycle.last_checked = revocation_date;

        Ok(())
    }

    /// 运行自动化任务
    pub fn run_automation(&mut self) -> PkiResult<Vec<AutomationEvent>> {
        let mut events = Vec::new();

        // 自动过期检查
        let expiring = self
            .expiry_monitor
            .check_expiring_certificates(&self.certificates)?;
        for (serial, days_until_expiry) in expiring {
            events.push(AutomationEvent::ExpiryAlert {
                serial_number: serial,
                days_until_expiry,
                timestamp: OffsetDateTime::now_utc(),
            });
        }

        // 自动续期处理
        if self.lifecycle_policy.automation_policy.enable_auto_renewal {
            let auto_renewals = self
                .automation_engine
                .process_auto_renewals(&mut self.certificates, &mut self.ca_manager)?;
            events.extend(auto_renewals);
        }

        // 自动吊销检查
        let auto_revocations = self
            .automation_engine
            .check_auto_revocations(&self.certificates)?;
        events.extend(auto_revocations);

        Ok(events)
    }

    /// 获取证书生命周期统计信息
    pub fn get_statistics(&self) -> LifecycleStatistics {
        let total_certificates = self.certificates.len();
        let mut valid_count = 0;
        let mut expiring_count = 0;
        let mut expired_count = 0;
        let mut revoked_count = 0;

        for lifecycle in self.certificates.values() {
            match lifecycle.status {
                CertificateStatus::Valid => valid_count += 1,
                CertificateStatus::Expiring(_) => expiring_count += 1,
                CertificateStatus::Expired => expired_count += 1,
                CertificateStatus::Revoked { .. } => revoked_count += 1,
                _ => {}
            }
        }

        LifecycleStatistics {
            total_certificates,
            valid_certificates: valid_count,
            expiring_certificates: expiring_count,
            expired_certificates: expired_count,
            revoked_certificates: revoked_count,
            average_days_until_expiry: self.calculate_average_expiry(),
        }
    }

    /// 获取指定证书的生命周期信息
    pub fn get_certificate_lifecycle(&self, serial_number: &str) -> Option<&CertificateLifecycle> {
        self.certificates.get(serial_number)
    }

    /// 列出所有证书的生命周期信息
    pub fn list_certificates(&self) -> Vec<&CertificateLifecycle> {
        self.certificates.values().collect()
    }

    // 私有辅助方法
    fn extract_serial_number(&self, _certificate: &X509Certificate) -> PkiResult<String> {
        // TODO: 从证书中提取真实的序列号
        Ok(format!(
            "CERT-{}",
            uuid::Uuid::new_v4().to_string()[.. 8].to_uppercase()
        ))
    }

    fn extract_expiry_date(&self, _certificate: &X509Certificate) -> PkiResult<OffsetDateTime> {
        // TODO: 从证书中提取真实的过期日期
        Ok(OffsetDateTime::now_utc() + time::Duration::days(365))
    }

    fn calculate_certificate_status(
        &self,
        lifecycle: &CertificateLifecycle,
        now: OffsetDateTime,
    ) -> PkiResult<CertificateStatus> {
        if let CertificateStatus::Revoked { .. } = lifecycle.status {
            return Ok(lifecycle.status.clone());
        }

        let days_until_expiry = (lifecycle.expiry_date - now).whole_days();

        if days_until_expiry < 0 {
            Ok(CertificateStatus::Expired)
        } else if days_until_expiry
            <= self.lifecycle_policy.expiry_policy.warning_threshold_days as i64
        {
            Ok(CertificateStatus::Expiring(days_until_expiry as u32))
        } else {
            Ok(CertificateStatus::Valid)
        }
    }

    fn validate_renewal_eligibility(&self, lifecycle: &CertificateLifecycle) -> PkiResult<()> {
        match &lifecycle.status {
            CertificateStatus::Revoked { .. } => Err(PkiError::LifecycleError(
                "Cannot renew revoked certificate".to_string(),
            )),
            CertificateStatus::Expired => {
                if !self.lifecycle_policy.renewal_policy.allow_expired_renewal {
                    return Err(PkiError::LifecycleError(
                        "Cannot renew expired certificate".to_string(),
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn calculate_average_expiry(&self) -> f64 {
        if self.certificates.is_empty() {
            return 0.0;
        }

        let now = OffsetDateTime::now_utc();
        let total_days: i64 = self
            .certificates
            .values()
            .map(|lifecycle| (lifecycle.expiry_date - now).whole_days().max(0))
            .sum();

        total_days as f64 / self.certificates.len() as f64
    }
}

/// 生命周期统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleStatistics {
    /// 总证书数量
    pub total_certificates: usize,
    /// 有效证书数量
    pub valid_certificates: usize,
    /// 即将过期证书数量
    pub expiring_certificates: usize,
    /// 已过期证书数量
    pub expired_certificates: usize,
    /// 已吊销证书数量
    pub revoked_certificates: usize,
    /// 平均剩余有效天数
    pub average_days_until_expiry: f64,
}

impl Default for LifecycleManager {
    fn default() -> Self {
        let ca_manager = CAManager::new();
        let lifecycle_policy = LifecyclePolicy::default();
        Self::new(ca_manager, lifecycle_policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_manager_creation() {
        let ca_manager = CAManager::new();
        let policy = LifecyclePolicy::default();
        let manager = LifecycleManager::new(ca_manager, policy);

        let stats = manager.get_statistics();
        assert_eq!(stats.total_certificates, 0);
    }

    #[test]
    fn test_certificate_status_calculation() {
        let ca_manager = CAManager::new();
        let policy = LifecyclePolicy::default();
        let manager = LifecycleManager::new(ca_manager, policy);

        // 测试状态计算逻辑
        let now = OffsetDateTime::now_utc();
        let lifecycle = CertificateLifecycle {
            serial_number: "TEST-123".to_string(),
            subject: "Test Certificate".to_string(),
            issued_date: now - time::Duration::days(30),
            expiry_date: now + time::Duration::days(10),
            status: CertificateStatus::Valid,
            issuing_ca_id: "test-ca".to_string(),
            renewal_history: Vec::new(),
            last_checked: now,
        };

        let status = manager
            .calculate_certificate_status(&lifecycle, now)
            .unwrap();
        assert!(matches!(status, CertificateStatus::Expiring(_)));
    }

    #[test]
    fn test_lifecycle_statistics() {
        let ca_manager = CAManager::new();
        let policy = LifecyclePolicy::default();
        let mut manager = LifecycleManager::new(ca_manager, policy);

        // 添加一些测试证书
        let now = OffsetDateTime::now_utc();
        manager.certificates.insert(
            "CERT-1".to_string(),
            CertificateLifecycle {
                serial_number: "CERT-1".to_string(),
                subject: "Test Certificate 1".to_string(),
                issued_date: now - time::Duration::days(30),
                expiry_date: now + time::Duration::days(335),
                status: CertificateStatus::Valid,
                issuing_ca_id: "test-ca".to_string(),
                renewal_history: Vec::new(),
                last_checked: now,
            },
        );

        let stats = manager.get_statistics();
        assert_eq!(stats.total_certificates, 1);
        assert_eq!(stats.valid_certificates, 1);
        assert!(stats.average_days_until_expiry > 300.0);
    }
}
