//! 证书过期监控模块
//!
//! 提供证书过期监控、通知和预警功能

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{
    policy::{ExpiryPolicy, LogLevel, NotificationMethod, OutputFormat},
    CertificateLifecycle,
};
use crate::error::Result as PkiResult;

/// 过期监控器
pub struct ExpiryMonitor {
    /// 过期监控策略
    policy: ExpiryPolicy,
    /// 通知历史
    notification_history: HashMap<String, Vec<ExpiryNotification>>,
    /// 最后检查时间
    last_check_time: OffsetDateTime,
}

/// 过期通知
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiryNotification {
    /// 证书序列号
    pub certificate_serial: String,
    /// 通知类型
    pub notification_type: NotificationType,
    /// 通知内容
    pub message: String,
    /// 剩余天数
    pub days_until_expiry: u32,
    /// 通知时间
    pub notified_at: OffsetDateTime,
    /// 通知方法
    pub notification_method: NotificationMethod,
    /// 通知状态
    pub status: NotificationStatus,
}

/// 过期警告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiryAlert {
    /// 证书序列号
    pub certificate_serial: String,
    /// 证书主题
    pub certificate_subject: String,
    /// 警告级别
    pub alert_level: AlertLevel,
    /// 过期日期
    pub expiry_date: OffsetDateTime,
    /// 剩余天数
    pub days_until_expiry: u32,
    /// 建议操作
    pub recommended_action: String,
    /// 生成时间
    pub generated_at: OffsetDateTime,
}

/// 通知类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NotificationType {
    /// 即将过期警告
    ExpiryWarning,
    /// 严重过期警告
    CriticalExpiry,
    /// 已过期通知
    Expired,
    /// 每日摘要
    DailySummary,
}

/// 警告级别
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertLevel {
    /// 信息
    Info,
    /// 警告
    Warning,
    /// 严重
    Critical,
    /// 紧急
    Emergency,
}

/// 通知状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NotificationStatus {
    /// 待发送
    Pending,
    /// 已发送
    Sent,
    /// 发送失败
    Failed { error: String },
    /// 已跳过
    Skipped { reason: String },
}

/// 过期检查结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpiryCheckResult {
    /// 检查时间
    pub checked_at: OffsetDateTime,
    /// 总证书数量
    pub total_certificates: usize,
    /// 即将过期证书
    pub expiring_certificates: Vec<ExpiryAlert>,
    /// 已过期证书
    pub expired_certificates: Vec<ExpiryAlert>,
    /// 新生成的通知数量
    pub notifications_generated: usize,
}

/// 每日摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailySummary {
    /// 摘要日期
    pub summary_date: OffsetDateTime,
    /// 总证书数量
    pub total_certificates: usize,
    /// 健康证书数量
    pub healthy_certificates: usize,
    /// 即将过期证书（警告阈值内）
    pub warning_certificates: usize,
    /// 严重过期证书（严重阈值内）
    pub critical_certificates: usize,
    /// 已过期证书
    pub expired_certificates: usize,
    /// 今日新增过期
    pub new_expired_today: usize,
    /// 推荐操作列表
    pub recommended_actions: Vec<String>,
}

impl ExpiryMonitor {
    /// 创建新的过期监控器
    pub fn new(policy: ExpiryPolicy) -> Self {
        Self {
            policy,
            notification_history: HashMap::new(),
            last_check_time: OffsetDateTime::now_utc(),
        }
    }

    /// 检查即将过期的证书
    pub fn check_expiring_certificates(
        &mut self,
        certificates: &HashMap<String, CertificateLifecycle>,
    ) -> PkiResult<Vec<(String, u32)>> {
        let now = OffsetDateTime::now_utc();
        let mut expiring_certificates = Vec::new();

        for (serial, lifecycle) in certificates {
            let days_until_expiry = (lifecycle.expiry_date - now).whole_days();

            if days_until_expiry <= 0 {
                // 已过期
                continue;
            }

            let days_until_expiry = days_until_expiry as u32;

            // 检查是否在警告阈值内
            if days_until_expiry <= self.policy.warning_threshold_days {
                expiring_certificates.push((serial.clone(), days_until_expiry));
            }
        }

        self.last_check_time = now;
        Ok(expiring_certificates)
    }

    /// 执行完整的过期检查
    pub fn perform_full_expiry_check(
        &mut self,
        certificates: &HashMap<String, CertificateLifecycle>,
    ) -> PkiResult<ExpiryCheckResult> {
        let now = OffsetDateTime::now_utc();
        let mut expiring_certificates = Vec::new();
        let mut expired_certificates = Vec::new();
        let mut notifications_generated = 0;

        for (serial, lifecycle) in certificates {
            let days_until_expiry = (lifecycle.expiry_date - now).whole_days();

            if days_until_expiry <= 0 {
                // 已过期
                let alert = ExpiryAlert {
                    certificate_serial: serial.clone(),
                    certificate_subject: lifecycle.subject.clone(),
                    alert_level: AlertLevel::Emergency,
                    expiry_date: lifecycle.expiry_date,
                    days_until_expiry: 0,
                    recommended_action: "Certificate has expired - immediate renewal required"
                        .to_string(),
                    generated_at: now,
                };

                expired_certificates.push(alert);

                // 生成过期通知
                if self.should_send_notification(serial, NotificationType::Expired)? {
                    self.generate_notification(
                        serial.clone(),
                        NotificationType::Expired,
                        format!("Certificate {} has expired", serial),
                        0,
                    )?;
                    notifications_generated += 1;
                }
            } else {
                let days_until_expiry = days_until_expiry as u32;

                // 检查警告阈值
                if days_until_expiry <= self.policy.critical_threshold_days {
                    let alert = ExpiryAlert {
                        certificate_serial: serial.clone(),
                        certificate_subject: lifecycle.subject.clone(),
                        alert_level: AlertLevel::Critical,
                        expiry_date: lifecycle.expiry_date,
                        days_until_expiry,
                        recommended_action: "Critical: Certificate expires soon - urgent renewal \
                                             needed"
                            .to_string(),
                        generated_at: now,
                    };

                    expiring_certificates.push(alert);

                    // 生成严重警告通知
                    if self.should_send_notification(serial, NotificationType::CriticalExpiry)? {
                        self.generate_notification(
                            serial.clone(),
                            NotificationType::CriticalExpiry,
                            format!(
                                "Certificate {} expires in {} days (CRITICAL)",
                                serial, days_until_expiry
                            ),
                            days_until_expiry,
                        )?;
                        notifications_generated += 1;
                    }
                } else if days_until_expiry <= self.policy.warning_threshold_days {
                    let alert = ExpiryAlert {
                        certificate_serial: serial.clone(),
                        certificate_subject: lifecycle.subject.clone(),
                        alert_level: AlertLevel::Warning,
                        expiry_date: lifecycle.expiry_date,
                        days_until_expiry,
                        recommended_action: "Warning: Certificate should be renewed soon"
                            .to_string(),
                        generated_at: now,
                    };

                    expiring_certificates.push(alert);

                    // 生成警告通知
                    if self.should_send_notification(serial, NotificationType::ExpiryWarning)? {
                        self.generate_notification(
                            serial.clone(),
                            NotificationType::ExpiryWarning,
                            format!(
                                "Certificate {} expires in {} days",
                                serial, days_until_expiry
                            ),
                            days_until_expiry,
                        )?;
                        notifications_generated += 1;
                    }
                }
            }
        }

        self.last_check_time = now;

        Ok(ExpiryCheckResult {
            checked_at: now,
            total_certificates: certificates.len(),
            expiring_certificates,
            expired_certificates,
            notifications_generated,
        })
    }

    /// 生成每日摘要
    pub fn generate_daily_summary(
        &self,
        certificates: &HashMap<String, CertificateLifecycle>,
    ) -> PkiResult<DailySummary> {
        let now = OffsetDateTime::now_utc();
        let mut healthy_count = 0;
        let mut warning_count = 0;
        let mut critical_count = 0;
        let mut expired_count = 0;
        let mut new_expired_today = 0;

        for lifecycle in certificates.values() {
            let days_until_expiry = (lifecycle.expiry_date - now).whole_days();

            if days_until_expiry <= 0 {
                expired_count += 1;

                // 检查是否是今天过期的
                let expiry_date_start = lifecycle.expiry_date.replace_time(time::Time::MIDNIGHT);
                let today_start = now.replace_time(time::Time::MIDNIGHT);
                if expiry_date_start == today_start {
                    new_expired_today += 1;
                }
            } else {
                let days_until_expiry = days_until_expiry as u32;

                if days_until_expiry <= self.policy.critical_threshold_days {
                    critical_count += 1;
                } else if days_until_expiry <= self.policy.warning_threshold_days {
                    warning_count += 1;
                } else {
                    healthy_count += 1;
                }
            }
        }

        let mut recommended_actions = Vec::new();

        if expired_count > 0 {
            recommended_actions.push(format!(
                "Immediate action: {} certificates have expired",
                expired_count
            ));
        }

        if critical_count > 0 {
            recommended_actions.push(format!(
                "Urgent: Renew {} certificates expiring within {} days",
                critical_count, self.policy.critical_threshold_days
            ));
        }

        if warning_count > 0 {
            recommended_actions.push(format!(
                "Plan renewal for {} certificates expiring within {} days",
                warning_count, self.policy.warning_threshold_days
            ));
        }

        Ok(DailySummary {
            summary_date: now,
            total_certificates: certificates.len(),
            healthy_certificates: healthy_count,
            warning_certificates: warning_count,
            critical_certificates: critical_count,
            expired_certificates: expired_count,
            new_expired_today,
            recommended_actions,
        })
    }

    /// 发送每日摘要通知
    pub fn send_daily_summary_notification(
        &mut self,
        certificates: &HashMap<String, CertificateLifecycle>,
    ) -> PkiResult<()> {
        if !self.policy.daily_summary_enabled {
            return Ok(());
        }

        let summary = self.generate_daily_summary(certificates)?;
        let summary_message = self.format_daily_summary(&summary);

        // 为每种通知方法生成通知
        for method in &self.policy.notification_methods {
            let notification = ExpiryNotification {
                certificate_serial: "DAILY_SUMMARY".to_string(),
                notification_type: NotificationType::DailySummary,
                message: summary_message.clone(),
                days_until_expiry: 0,
                notified_at: OffsetDateTime::now_utc(),
                notification_method: method.clone(),
                status: NotificationStatus::Pending,
            };

            // TODO: 实际发送通知
            self.send_notification(&notification)?;
        }

        Ok(())
    }

    /// 获取通知历史
    pub fn get_notification_history(&self, certificate_serial: &str) -> Vec<&ExpiryNotification> {
        self.notification_history
            .get(certificate_serial)
            .map(|notifications| notifications.iter().collect())
            .unwrap_or_default()
    }

    /// 获取所有通知历史
    pub fn get_all_notification_history(&self) -> &HashMap<String, Vec<ExpiryNotification>> {
        &self.notification_history
    }

    /// 清理旧的通知历史
    pub fn cleanup_old_notifications(&mut self, retention_days: u32) {
        let cutoff_date = OffsetDateTime::now_utc() - time::Duration::days(retention_days as i64);

        for notifications in self.notification_history.values_mut() {
            notifications.retain(|notification| notification.notified_at > cutoff_date);
        }

        // 移除空的条目
        self.notification_history
            .retain(|_, notifications| !notifications.is_empty());
    }

    /// 更新策略
    pub fn update_policy(&mut self, new_policy: ExpiryPolicy) {
        self.policy = new_policy;
    }

    // 私有方法

    /// 检查是否应该发送通知
    fn should_send_notification(
        &self,
        certificate_serial: &str,
        notification_type: NotificationType,
    ) -> PkiResult<bool> {
        if let Some(notifications) = self.notification_history.get(certificate_serial) {
            // 检查最近是否已发送相同类型的通知
            let recent_notification = notifications
                .iter()
                .filter(|n| n.notification_type == notification_type)
                .max_by_key(|n| n.notified_at);

            if let Some(recent) = recent_notification {
                let time_since_last = OffsetDateTime::now_utc() - recent.notified_at;

                // 避免短时间内重复发送相同通知（至少间隔1小时）
                if time_since_last < time::Duration::hours(1) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// 生成通知
    fn generate_notification(
        &mut self,
        certificate_serial: String,
        notification_type: NotificationType,
        message: String,
        days_until_expiry: u32,
    ) -> PkiResult<()> {
        for method in &self.policy.notification_methods {
            let notification = ExpiryNotification {
                certificate_serial: certificate_serial.clone(),
                notification_type: notification_type.clone(),
                message: message.clone(),
                days_until_expiry,
                notified_at: OffsetDateTime::now_utc(),
                notification_method: method.clone(),
                status: NotificationStatus::Pending,
            };

            // 发送通知
            self.send_notification(&notification)?;

            // 记录通知历史
            self.notification_history
                .entry(certificate_serial.clone())
                .or_insert_with(Vec::new)
                .push(notification);
        }

        Ok(())
    }

    /// 发送通知（实际实现）
    fn send_notification(&self, notification: &ExpiryNotification) -> PkiResult<()> {
        // TODO: 实现实际的通知发送逻辑
        match &notification.notification_method {
            NotificationMethod::Email {
                recipients,
                template,
            } => {
                // 发送邮件通知
                println!(
                    "Sending email notification to {:?} using template {}: {}",
                    recipients, template, notification.message
                );
            }
            NotificationMethod::SystemLog { level } => {
                // 写入系统日志
                match level {
                    LogLevel::Info => println!("[INFO] {}", notification.message),
                    LogLevel::Warning => println!("[WARNING] {}", notification.message),
                    LogLevel::Error => println!("[ERROR] {}", notification.message),
                    LogLevel::Critical => println!("[CRITICAL] {}", notification.message),
                }
            }
            NotificationMethod::Webhook { url, secret } => {
                // 发送Webhook通知
                println!(
                    "Sending webhook notification to {}: {}",
                    url, notification.message
                );
                if secret.is_some() {
                    println!("Using webhook secret for authentication");
                }
            }
            NotificationMethod::FileOutput { path, format } => {
                // 写入文件
                match format {
                    OutputFormat::Json => {
                        println!(
                            "Writing JSON notification to {}: {}",
                            path,
                            serde_json::to_string(notification).unwrap_or_default()
                        );
                    }
                    OutputFormat::Csv => {
                        println!("Writing CSV notification to {}", path);
                    }
                    OutputFormat::PlainText => {
                        println!(
                            "Writing plain text notification to {}: {}",
                            path, notification.message
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// 格式化每日摘要
    fn format_daily_summary(&self, summary: &DailySummary) -> String {
        let mut message = String::new();
        message.push_str(&format!(
            "Daily Certificate Summary - {}\n",
            summary
                .summary_date
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        ));
        message.push_str(&format!(
            "Total Certificates: {}\n",
            summary.total_certificates
        ));
        message.push_str(&format!(
            "Healthy: {} | Warning: {} | Critical: {} | Expired: {}\n",
            summary.healthy_certificates,
            summary.warning_certificates,
            summary.critical_certificates,
            summary.expired_certificates
        ));

        if summary.new_expired_today > 0 {
            message.push_str(&format!(
                "New Expired Today: {}\n",
                summary.new_expired_today
            ));
        }

        if !summary.recommended_actions.is_empty() {
            message.push_str("\nRecommended Actions:\n");
            for action in &summary.recommended_actions {
                message.push_str(&format!("- {}\n", action));
            }
        }

        message
    }
}

impl Default for ExpiryMonitor {
    fn default() -> Self {
        use super::policy::{ExpiryPolicy, LogLevel, NotificationMethod};

        Self::new(ExpiryPolicy {
            warning_threshold_days: 30,
            critical_threshold_days: 7,
            check_frequency_hours: 24,
            notification_methods: vec![NotificationMethod::SystemLog {
                level: LogLevel::Warning,
            }],
            daily_summary_enabled: true,
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
            subject: format!("Test Certificate {}", serial),
            issued_date: now - time::Duration::days(365),
            expiry_date: now + time::Duration::days(days_until_expiry),
            status: CertificateStatus::Valid,
            issuing_ca_id: "test-ca".to_string(),
            renewal_history: Vec::new(),
            last_checked: now,
        }
    }

    #[test]
    fn test_expiry_monitor_creation() {
        let policy = ExpiryPolicy {
            warning_threshold_days: 30,
            critical_threshold_days: 7,
            check_frequency_hours: 24,
            notification_methods: vec![],
            daily_summary_enabled: true,
        };

        let monitor = ExpiryMonitor::new(policy);
        assert_eq!(monitor.policy.warning_threshold_days, 30);
        assert_eq!(monitor.policy.critical_threshold_days, 7);
    }

    #[test]
    fn test_check_expiring_certificates() {
        let mut monitor = ExpiryMonitor::default();
        let mut certificates = HashMap::new();

        // 添加不同过期时间的证书
        certificates.insert(
            "CERT-001".to_string(),
            create_test_certificate("CERT-001", 100),
        ); // 健康
        certificates.insert(
            "CERT-002".to_string(),
            create_test_certificate("CERT-002", 20),
        ); // 警告
        certificates.insert(
            "CERT-003".to_string(),
            create_test_certificate("CERT-003", 5),
        ); // 严重
        certificates.insert(
            "CERT-004".to_string(),
            create_test_certificate("CERT-004", -5),
        ); // 过期

        let expiring = monitor.check_expiring_certificates(&certificates).unwrap();

        // 应该找到2个即将过期的证书（警告和严重阈值内）
        assert_eq!(expiring.len(), 2);

        // 检查具体的证书
        let serials: Vec<String> = expiring.iter().map(|(serial, _)| serial.clone()).collect();
        assert!(serials.contains(&"CERT-002".to_string()));
        assert!(serials.contains(&"CERT-003".to_string()));
    }

    #[test]
    fn test_full_expiry_check() {
        let mut monitor = ExpiryMonitor::default();
        let mut certificates = HashMap::new();

        certificates.insert(
            "CERT-001".to_string(),
            create_test_certificate("CERT-001", 100),
        ); // 健康
        certificates.insert(
            "CERT-002".to_string(),
            create_test_certificate("CERT-002", 20),
        ); // 警告
        certificates.insert(
            "CERT-003".to_string(),
            create_test_certificate("CERT-003", 5),
        ); // 严重
        certificates.insert(
            "CERT-004".to_string(),
            create_test_certificate("CERT-004", -5),
        ); // 过期

        let result = monitor.perform_full_expiry_check(&certificates).unwrap();

        assert_eq!(result.total_certificates, 4);
        assert_eq!(result.expiring_certificates.len(), 2); // 警告 + 严重
        assert_eq!(result.expired_certificates.len(), 1); // 过期

        // 检查警告级别
        let critical_alerts: Vec<_> = result
            .expiring_certificates
            .iter()
            .filter(|alert| alert.alert_level == AlertLevel::Critical)
            .collect();
        assert_eq!(critical_alerts.len(), 1);

        let warning_alerts: Vec<_> = result
            .expiring_certificates
            .iter()
            .filter(|alert| alert.alert_level == AlertLevel::Warning)
            .collect();
        assert_eq!(warning_alerts.len(), 1);
    }

    #[test]
    fn test_daily_summary_generation() {
        let monitor = ExpiryMonitor::default();
        let mut certificates = HashMap::new();

        certificates.insert(
            "CERT-001".to_string(),
            create_test_certificate("CERT-001", 100),
        ); // 健康
        certificates.insert(
            "CERT-002".to_string(),
            create_test_certificate("CERT-002", 20),
        ); // 警告
        certificates.insert(
            "CERT-003".to_string(),
            create_test_certificate("CERT-003", 5),
        ); // 严重
        certificates.insert(
            "CERT-004".to_string(),
            create_test_certificate("CERT-004", -1),
        ); // 过期

        let summary = monitor.generate_daily_summary(&certificates).unwrap();

        assert_eq!(summary.total_certificates, 4);
        assert_eq!(summary.healthy_certificates, 1);
        assert_eq!(summary.warning_certificates, 1);
        assert_eq!(summary.critical_certificates, 1);
        assert_eq!(summary.expired_certificates, 1);

        // 应该有推荐操作
        assert!(!summary.recommended_actions.is_empty());
    }

    #[test]
    fn test_notification_generation() {
        let mut monitor = ExpiryMonitor::default();

        // 生成通知
        let result = monitor.generate_notification(
            "CERT-123".to_string(),
            NotificationType::ExpiryWarning,
            "Test notification".to_string(),
            15,
        );

        assert!(result.is_ok());

        // 检查通知历史
        let history = monitor.get_notification_history("CERT-123");
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].notification_type,
            NotificationType::ExpiryWarning
        );
    }

    #[test]
    fn test_notification_deduplication() {
        let mut monitor = ExpiryMonitor::default();

        // 第一次应该发送
        assert!(monitor
            .should_send_notification("CERT-123", NotificationType::ExpiryWarning)
            .unwrap());

        // 生成通知
        monitor
            .generate_notification(
                "CERT-123".to_string(),
                NotificationType::ExpiryWarning,
                "Test notification".to_string(),
                15,
            )
            .unwrap();

        // 立即再次检查应该不发送（避免重复）
        assert!(!monitor
            .should_send_notification("CERT-123", NotificationType::ExpiryWarning)
            .unwrap());
    }

    #[test]
    fn test_cleanup_old_notifications() {
        let mut monitor = ExpiryMonitor::default();

        // 添加一些通知历史
        let old_notification = ExpiryNotification {
            certificate_serial: "CERT-123".to_string(),
            notification_type: NotificationType::ExpiryWarning,
            message: "Old notification".to_string(),
            days_until_expiry: 15,
            notified_at: OffsetDateTime::now_utc() - time::Duration::days(60),
            notification_method: NotificationMethod::SystemLog {
                level: LogLevel::Warning,
            },
            status: NotificationStatus::Sent,
        };

        let recent_notification = ExpiryNotification {
            certificate_serial: "CERT-123".to_string(),
            notification_type: NotificationType::ExpiryWarning,
            message: "Recent notification".to_string(),
            days_until_expiry: 15,
            notified_at: OffsetDateTime::now_utc() - time::Duration::days(5),
            notification_method: NotificationMethod::SystemLog {
                level: LogLevel::Warning,
            },
            status: NotificationStatus::Sent,
        };

        monitor.notification_history.insert(
            "CERT-123".to_string(),
            vec![old_notification, recent_notification],
        );

        // 清理30天前的通知
        monitor.cleanup_old_notifications(30);

        // 应该只保留最近的通知
        let history = monitor.get_notification_history("CERT-123");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].message, "Recent notification");
    }
}
