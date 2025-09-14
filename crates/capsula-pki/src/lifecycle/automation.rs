//! 证书生命周期自动化引擎
//!
//! 提供证书生命周期的自动化管理功能，包括自动续期、自动吊销检查等

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use std::collections::HashMap;

use crate::{
    error::{PkiError, Result as PkiResult},
    ca::Manager as CAManager,
};

use super::{
    CertificateLifecycle, CertificateStatus,
    policy::AutomationPolicy,
    renewal::{RenewalRequest, RenewalReason},
};

/// 自动化引擎
pub struct AutomationEngine {
    /// 自动化策略
    policy: AutomationPolicy,
    /// 自动化任务历史
    task_history: Vec<AutomationTask>,
    /// 最后运行时间
    last_run_time: OffsetDateTime,
}

/// 自动化事件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutomationEvent {
    /// 过期警告事件
    ExpiryAlert {
        serial_number: String,
        days_until_expiry: u32,
        timestamp: OffsetDateTime,
    },
    /// 自动续期事件
    AutoRenewal {
        original_serial: String,
        new_serial: String,
        reason: String,
        timestamp: OffsetDateTime,
        success: bool,
        error: Option<String>,
    },
    /// 自动吊销检查事件
    RevocationCheck {
        serial_number: String,
        check_result: RevocationCheckResult,
        timestamp: OffsetDateTime,
    },
    /// 策略违规事件
    PolicyViolation {
        serial_number: String,
        violation_type: String,
        severity: String,
        timestamp: OffsetDateTime,
    },
}

/// 自动化操作
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AutomationAction {
    /// 自动续期
    AutoRenewal {
        certificate_serial: String,
        new_validity_days: u32,
    },
    /// 发送通知
    SendNotification {
        recipient: String,
        message: String,
    },
    /// 记录日志
    LogEvent {
        level: String,
        message: String,
    },
    /// 更新证书状态
    UpdateStatus {
        certificate_serial: String,
        new_status: CertificateStatus,
    },
}

/// 自动化任务
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationTask {
    /// 任务ID
    pub task_id: String,
    /// 任务类型
    pub task_type: AutomationTaskType,
    /// 证书序列号
    pub certificate_serial: String,
    /// 任务状态
    pub status: TaskStatus,
    /// 创建时间
    pub created_at: OffsetDateTime,
    /// 执行时间
    pub executed_at: Option<OffsetDateTime>,
    /// 完成时间
    pub completed_at: Option<OffsetDateTime>,
    /// 任务结果
    pub result: Option<String>,
    /// 错误信息
    pub error: Option<String>,
}

/// 自动化任务类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AutomationTaskType {
    /// 自动续期任务
    AutoRenewal,
    /// 过期检查任务
    ExpiryCheck,
    /// 吊销检查任务
    RevocationCheck,
    /// 通知发送任务
    NotificationSend,
}

/// 任务状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskStatus {
    /// 待执行
    Pending,
    /// 执行中
    Running,
    /// 已完成
    Completed,
    /// 失败
    Failed,
    /// 已跳过
    Skipped,
}

/// 吊销检查结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationCheckResult {
    /// 证书正常
    Normal,
    /// 发现可疑活动
    Suspicious { reason: String },
    /// 建议吊销
    RecommendRevocation { reason: String },
    /// 检查失败
    CheckFailed { error: String },
}

/// 自动化统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationStatistics {
    /// 总任务数
    pub total_tasks: usize,
    /// 待执行任务数
    pub pending_tasks: usize,
    /// 运行中任务数
    pub running_tasks: usize,
    /// 已完成任务数
    pub completed_tasks: usize,
    /// 失败任务数
    pub failed_tasks: usize,
    /// 自动续期成功次数
    pub auto_renewal_success: usize,
    /// 自动续期失败次数
    pub auto_renewal_failed: usize,
    /// 最后运行时间
    pub last_run_time: OffsetDateTime,
}

impl AutomationEngine {
    /// 创建新的自动化引擎
    pub fn new(policy: AutomationPolicy) -> Self {
        Self {
            policy,
            task_history: Vec::new(),
            last_run_time: OffsetDateTime::now_utc(),
        }
    }

    /// 处理自动续期
    pub fn process_auto_renewals(
        &mut self,
        certificates: &mut HashMap<String, CertificateLifecycle>,
        ca_manager: &mut CAManager,
    ) -> PkiResult<Vec<AutomationEvent>> {
        if !self.policy.enable_auto_renewal {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        let now = OffsetDateTime::now_utc();
        let renewal_threshold = self.policy.auto_renewal_threshold_days;

        // 查找需要自动续期的证书
        let mut certificates_to_renew = Vec::new();
        for (serial, lifecycle) in certificates.iter() {
            // 检查证书类型是否支持自动续期
            if !self.is_certificate_type_eligible_for_auto_renewal(&lifecycle.subject) {
                continue;
            }

            // 检查是否在自动续期阈值内
            let days_until_expiry = (lifecycle.expiry_date - now).whole_days();
            if days_until_expiry <= renewal_threshold as i64 && days_until_expiry > 0 {
                certificates_to_renew.push(serial.clone());
            }
        }

        // 执行自动续期
        for serial in certificates_to_renew {
            let renewal_result = self.perform_auto_renewal(&serial, certificates, ca_manager);
            
            match renewal_result {
                Ok(new_serial) => {
                    events.push(AutomationEvent::AutoRenewal {
                        original_serial: serial.clone(),
                        new_serial: new_serial.clone(),
                        reason: "Automatic renewal due to approaching expiry".to_string(),
                        timestamp: now,
                        success: true,
                        error: None,
                    });

                    // 记录成功任务
                    self.record_task(AutomationTask {
                        task_id: format!("AUTO_RENEW_{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase()),
                        task_type: AutomationTaskType::AutoRenewal,
                        certificate_serial: serial,
                        status: TaskStatus::Completed,
                        created_at: now,
                        executed_at: Some(now),
                        completed_at: Some(now),
                        result: Some(format!("Renewed to certificate {}", new_serial)),
                        error: None,
                    });
                },
                Err(error) => {
                    events.push(AutomationEvent::AutoRenewal {
                        original_serial: serial.clone(),
                        new_serial: String::new(),
                        reason: "Automatic renewal failed".to_string(),
                        timestamp: now,
                        success: false,
                        error: Some(error.to_string()),
                    });

                    // 记录失败任务
                    self.record_task(AutomationTask {
                        task_id: format!("AUTO_RENEW_{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase()),
                        task_type: AutomationTaskType::AutoRenewal,
                        certificate_serial: serial,
                        status: TaskStatus::Failed,
                        created_at: now,
                        executed_at: Some(now),
                        completed_at: Some(now),
                        result: None,
                        error: Some(error.to_string()),
                    });
                }
            }
        }

        self.last_run_time = now;
        Ok(events)
    }

    /// 检查自动吊销条件
    pub fn check_auto_revocations(
        &mut self,
        certificates: &HashMap<String, CertificateLifecycle>,
    ) -> PkiResult<Vec<AutomationEvent>> {
        if !self.policy.enable_auto_revocation_check {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        let now = OffsetDateTime::now_utc();

        for (serial, lifecycle) in certificates {
            // 执行吊销检查
            let check_result = self.perform_revocation_check(lifecycle);
            
            events.push(AutomationEvent::RevocationCheck {
                serial_number: serial.clone(),
                check_result: check_result.clone(),
                timestamp: now,
            });

            // 记录检查任务
            let task_result = match &check_result {
                RevocationCheckResult::Normal => "Certificate is normal".to_string(),
                RevocationCheckResult::Suspicious { reason } => format!("Suspicious activity: {}", reason),
                RevocationCheckResult::RecommendRevocation { reason } => format!("Recommend revocation: {}", reason),
                RevocationCheckResult::CheckFailed { error } => format!("Check failed: {}", error),
            };

            self.record_task(AutomationTask {
                task_id: format!("REVOKE_CHECK_{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase()),
                task_type: AutomationTaskType::RevocationCheck,
                certificate_serial: serial.clone(),
                status: TaskStatus::Completed,
                created_at: now,
                executed_at: Some(now),
                completed_at: Some(now),
                result: Some(task_result),
                error: None,
            });
        }

        self.last_run_time = now;
        Ok(events)
    }

    /// 运行定期自动化任务
    pub fn run_scheduled_tasks(
        &mut self,
        certificates: &mut HashMap<String, CertificateLifecycle>,
        ca_manager: &mut CAManager,
    ) -> PkiResult<Vec<AutomationEvent>> {
        let now = OffsetDateTime::now_utc();
        let time_since_last_run = now - self.last_run_time;
        let automation_frequency = time::Duration::hours(self.policy.automation_frequency_hours as i64);

        // 检查是否需要运行自动化任务
        if time_since_last_run < automation_frequency {
            return Ok(Vec::new());
        }

        let mut all_events = Vec::new();

        // 执行自动续期
        if self.policy.enable_auto_renewal {
            let renewal_events = self.process_auto_renewals(certificates, ca_manager)?;
            all_events.extend(renewal_events);
        }

        // 执行自动吊销检查
        if self.policy.enable_auto_revocation_check {
            let revocation_events = self.check_auto_revocations(certificates)?;
            all_events.extend(revocation_events);
        }

        Ok(all_events)
    }

    /// 获取自动化统计信息
    pub fn get_statistics(&self) -> AutomationStatistics {
        let mut pending_count = 0;
        let mut running_count = 0;
        let mut completed_count = 0;
        let mut failed_count = 0;
        let mut auto_renewal_success = 0;
        let mut auto_renewal_failed = 0;

        for task in &self.task_history {
            match task.status {
                TaskStatus::Pending => pending_count += 1,
                TaskStatus::Running => running_count += 1,
                TaskStatus::Completed => {
                    completed_count += 1;
                    if task.task_type == AutomationTaskType::AutoRenewal {
                        auto_renewal_success += 1;
                    }
                },
                TaskStatus::Failed => {
                    failed_count += 1;
                    if task.task_type == AutomationTaskType::AutoRenewal {
                        auto_renewal_failed += 1;
                    }
                },
                TaskStatus::Skipped => {},
            }
        }

        AutomationStatistics {
            total_tasks: self.task_history.len(),
            pending_tasks: pending_count,
            running_tasks: running_count,
            completed_tasks: completed_count,
            failed_tasks: failed_count,
            auto_renewal_success,
            auto_renewal_failed,
            last_run_time: self.last_run_time,
        }
    }

    /// 获取任务历史
    pub fn get_task_history(&self) -> &Vec<AutomationTask> {
        &self.task_history
    }

    /// 获取指定类型的任务历史
    pub fn get_task_history_by_type(&self, task_type: AutomationTaskType) -> Vec<&AutomationTask> {
        self.task_history
            .iter()
            .filter(|task| task.task_type == task_type)
            .collect()
    }

    /// 清理旧的任务历史
    pub fn cleanup_old_tasks(&mut self, retention_days: u32) {
        let cutoff_date = OffsetDateTime::now_utc() - time::Duration::days(retention_days as i64);
        
        self.task_history.retain(|task| task.created_at > cutoff_date);
    }

    /// 更新自动化策略
    pub fn update_policy(&mut self, new_policy: AutomationPolicy) {
        self.policy = new_policy;
    }

    // 私有方法

    /// 检查证书类型是否符合自动续期条件
    fn is_certificate_type_eligible_for_auto_renewal(&self, subject: &str) -> bool {
        // 如果配置为空，则所有证书都符合条件
        if self.policy.auto_renewal_certificate_types.is_empty() {
            return true;
        }

        // 检查证书主题是否包含配置的类型关键词
        for cert_type in &self.policy.auto_renewal_certificate_types {
            if subject.to_lowercase().contains(&cert_type.to_lowercase()) {
                return true;
            }
        }

        false
    }

    /// 执行自动续期
    fn perform_auto_renewal(
        &self,
        certificate_serial: &str,
        certificates: &mut HashMap<String, CertificateLifecycle>,
        _ca_manager: &mut CAManager, // TODO: Use for actual renewal via CA
    ) -> PkiResult<String> {
        // TODO: 实现实际的自动续期逻辑
        // 这里需要：
        // 1. 创建续期请求
        // 2. 调用续期管理器
        // 3. 更新证书生命周期信息

        let _lifecycle = certificates.get(certificate_serial)
            .ok_or_else(|| PkiError::LifecycleError(format!("Certificate {} not found", certificate_serial)))?;

        // 创建自动续期请求
        let _renewal_request = RenewalRequest {
            certificate_serial: certificate_serial.to_string(),
            reason: RenewalReason::Automatic,
            requested_by: "AutomationEngine".to_string(),
            new_validity_days: Some(365), // 默认1年
            force_renewal: false,
            requested_at: OffsetDateTime::now_utc(),
        };

        // 生成新的证书序列号（占位符实现）
        let new_serial = format!("AUTO_RENEWED_{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase());

        // TODO: 实际调用续期管理器执行续期
        // let mut renewal_manager = RenewalManager::default();
        // let renewal_result = renewal_manager.renew_certificate(ca_manager, renewal_request)?;

        // 更新证书生命周期信息（占位符实现）
        if let Some(lifecycle) = certificates.get_mut(certificate_serial) {
            lifecycle.expiry_date = OffsetDateTime::now_utc() + time::Duration::days(365);
            lifecycle.status = CertificateStatus::Valid;
            lifecycle.last_checked = OffsetDateTime::now_utc();
        }

        Ok(new_serial)
    }

    /// 执行吊销检查
    fn perform_revocation_check(&self, lifecycle: &CertificateLifecycle) -> RevocationCheckResult {
        // TODO: 实现实际的吊销检查逻辑
        // 这里可以包括：
        // 1. 检查证书使用模式异常
        // 2. 检查密钥泄露迹象
        // 3. 检查证书滥用情况
        // 4. 其他安全检查

        // 简单的检查逻辑（占位符）
        let now = OffsetDateTime::now_utc();
        let days_since_issued = (now - lifecycle.issued_date).whole_days();
        
        // 检查证书是否异常长时间未使用
        if days_since_issued > 365 && lifecycle.last_checked < now - time::Duration::days(90) {
            RevocationCheckResult::Suspicious {
                reason: "Certificate has not been checked for over 90 days".to_string(),
            }
        } else {
            RevocationCheckResult::Normal
        }
    }

    /// 记录自动化任务
    fn record_task(&mut self, task: AutomationTask) {
        self.task_history.push(task);
        
        // 限制历史记录数量，避免内存泄漏
        const MAX_HISTORY_SIZE: usize = 10000;
        if self.task_history.len() > MAX_HISTORY_SIZE {
            // 保留最近的记录
            self.task_history.drain(0..MAX_HISTORY_SIZE / 2);
        }
    }
}

impl Default for AutomationEngine {
    fn default() -> Self {
        use super::policy::AutomationPolicy;
        
        Self::new(AutomationPolicy {
            enable_auto_renewal: false,
            auto_renewal_threshold_days: 30,
            auto_renewal_certificate_types: vec![],
            enable_auto_revocation_check: false,
            automation_frequency_hours: 24,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::{CertificateLifecycle, CertificateStatus};

    fn create_test_certificate(serial: &str, days_until_expiry: i64) -> CertificateLifecycle {
        let now = OffsetDateTime::now_utc();
        CertificateLifecycle {
            serial_number: serial.to_string(),
            subject: "CN=Test Certificate,O=Test Org".to_string(),
            issued_date: now - time::Duration::days(365),
            expiry_date: now + time::Duration::days(days_until_expiry),
            status: CertificateStatus::Valid,
            issuing_ca_id: "test-ca".to_string(),
            renewal_history: Vec::new(),
            last_checked: now,
        }
    }

    #[test]
    fn test_automation_engine_creation() {
        let policy = AutomationPolicy {
            enable_auto_renewal: true,
            auto_renewal_threshold_days: 30,
            auto_renewal_certificate_types: vec!["server".to_string()],
            enable_auto_revocation_check: true,
            automation_frequency_hours: 6,
        };
        
        let engine = AutomationEngine::new(policy);
        assert!(engine.policy.enable_auto_renewal);
        assert_eq!(engine.policy.auto_renewal_threshold_days, 30);
    }

    #[test]
    fn test_certificate_type_eligibility() {
        let policy = AutomationPolicy {
            enable_auto_renewal: true,
            auto_renewal_threshold_days: 30,
            auto_renewal_certificate_types: vec!["server".to_string(), "client".to_string()],
            enable_auto_revocation_check: false,
            automation_frequency_hours: 24,
        };
        
        let engine = AutomationEngine::new(policy);
        
        // 符合条件的证书类型
        assert!(engine.is_certificate_type_eligible_for_auto_renewal("CN=server.example.com"));
        assert!(engine.is_certificate_type_eligible_for_auto_renewal("CN=client-cert"));
        
        // 不符合条件的证书类型
        assert!(!engine.is_certificate_type_eligible_for_auto_renewal("CN=root-ca"));
    }

    #[test]
    fn test_revocation_check() {
        let engine = AutomationEngine::default();
        
        // 正常证书
        let normal_cert = create_test_certificate("CERT-001", 100);
        let result = engine.perform_revocation_check(&normal_cert);
        assert!(matches!(result, RevocationCheckResult::Normal));
        
        // 长时间未检查的证书
        let mut old_cert = create_test_certificate("CERT-002", 100);
        old_cert.issued_date = OffsetDateTime::now_utc() - time::Duration::days(400);
        old_cert.last_checked = OffsetDateTime::now_utc() - time::Duration::days(100);
        let result = engine.perform_revocation_check(&old_cert);
        assert!(matches!(result, RevocationCheckResult::Suspicious { .. }));
    }

    #[test]
    fn test_task_recording() {
        let mut engine = AutomationEngine::default();
        
        let task = AutomationTask {
            task_id: "TEST-001".to_string(),
            task_type: AutomationTaskType::AutoRenewal,
            certificate_serial: "CERT-123".to_string(),
            status: TaskStatus::Completed,
            created_at: OffsetDateTime::now_utc(),
            executed_at: Some(OffsetDateTime::now_utc()),
            completed_at: Some(OffsetDateTime::now_utc()),
            result: Some("Success".to_string()),
            error: None,
        };
        
        engine.record_task(task);
        
        assert_eq!(engine.task_history.len(), 1);
        assert_eq!(engine.task_history[0].task_id, "TEST-001");
    }

    #[test]
    fn test_statistics() {
        let mut engine = AutomationEngine::default();
        
        // 添加一些任务历史
        engine.record_task(AutomationTask {
            task_id: "TASK-001".to_string(),
            task_type: AutomationTaskType::AutoRenewal,
            certificate_serial: "CERT-001".to_string(),
            status: TaskStatus::Completed,
            created_at: OffsetDateTime::now_utc(),
            executed_at: Some(OffsetDateTime::now_utc()),
            completed_at: Some(OffsetDateTime::now_utc()),
            result: Some("Success".to_string()),
            error: None,
        });
        
        engine.record_task(AutomationTask {
            task_id: "TASK-002".to_string(),
            task_type: AutomationTaskType::AutoRenewal,
            certificate_serial: "CERT-002".to_string(),
            status: TaskStatus::Failed,
            created_at: OffsetDateTime::now_utc(),
            executed_at: Some(OffsetDateTime::now_utc()),
            completed_at: Some(OffsetDateTime::now_utc()),
            result: None,
            error: Some("Test error".to_string()),
        });
        
        let stats = engine.get_statistics();
        assert_eq!(stats.total_tasks, 2);
        assert_eq!(stats.completed_tasks, 1);
        assert_eq!(stats.failed_tasks, 1);
        assert_eq!(stats.auto_renewal_success, 1);
        assert_eq!(stats.auto_renewal_failed, 1);
    }

    #[test]
    fn test_task_history_by_type() {
        let mut engine = AutomationEngine::default();
        
        // 添加不同类型的任务
        engine.record_task(AutomationTask {
            task_id: "RENEWAL-001".to_string(),
            task_type: AutomationTaskType::AutoRenewal,
            certificate_serial: "CERT-001".to_string(),
            status: TaskStatus::Completed,
            created_at: OffsetDateTime::now_utc(),
            executed_at: Some(OffsetDateTime::now_utc()),
            completed_at: Some(OffsetDateTime::now_utc()),
            result: Some("Success".to_string()),
            error: None,
        });
        
        engine.record_task(AutomationTask {
            task_id: "CHECK-001".to_string(),
            task_type: AutomationTaskType::RevocationCheck,
            certificate_serial: "CERT-002".to_string(),
            status: TaskStatus::Completed,
            created_at: OffsetDateTime::now_utc(),
            executed_at: Some(OffsetDateTime::now_utc()),
            completed_at: Some(OffsetDateTime::now_utc()),
            result: Some("Normal".to_string()),
            error: None,
        });
        
        let renewal_tasks = engine.get_task_history_by_type(AutomationTaskType::AutoRenewal);
        assert_eq!(renewal_tasks.len(), 1);
        assert_eq!(renewal_tasks[0].task_id, "RENEWAL-001");
        
        let check_tasks = engine.get_task_history_by_type(AutomationTaskType::RevocationCheck);
        assert_eq!(check_tasks.len(), 1);
        assert_eq!(check_tasks[0].task_id, "CHECK-001");
    }

    #[test]
    fn test_cleanup_old_tasks() {
        let mut engine = AutomationEngine::default();
        
        // 添加旧任务
        let old_task = AutomationTask {
            task_id: "OLD-001".to_string(),
            task_type: AutomationTaskType::AutoRenewal,
            certificate_serial: "CERT-001".to_string(),
            status: TaskStatus::Completed,
            created_at: OffsetDateTime::now_utc() - time::Duration::days(60),
            executed_at: Some(OffsetDateTime::now_utc() - time::Duration::days(60)),
            completed_at: Some(OffsetDateTime::now_utc() - time::Duration::days(60)),
            result: Some("Success".to_string()),
            error: None,
        };
        
        // 添加新任务
        let new_task = AutomationTask {
            task_id: "NEW-001".to_string(),
            task_type: AutomationTaskType::AutoRenewal,
            certificate_serial: "CERT-002".to_string(),
            status: TaskStatus::Completed,
            created_at: OffsetDateTime::now_utc() - time::Duration::days(5),
            executed_at: Some(OffsetDateTime::now_utc() - time::Duration::days(5)),
            completed_at: Some(OffsetDateTime::now_utc() - time::Duration::days(5)),
            result: Some("Success".to_string()),
            error: None,
        };
        
        engine.record_task(old_task);
        engine.record_task(new_task);
        
        // 清理30天前的任务
        engine.cleanup_old_tasks(30);
        
        // 应该只保留新任务
        assert_eq!(engine.task_history.len(), 1);
        assert_eq!(engine.task_history[0].task_id, "NEW-001");
    }
}