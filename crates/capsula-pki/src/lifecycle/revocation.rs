//! 证书吊销管理模块
//!
//! 提供证书吊销功能，包括吊销原因管理、CRL生成和吊销状态跟踪

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::policy::RevocationPolicy;
use crate::error::{PkiError, Result as PkiResult};

/// 吊销管理器
pub struct RevocationManager {
    /// 吊销策略
    policy: RevocationPolicy,
    /// 吊销列表 - 证书序列号 -> 吊销条目
    revoked_certificates: HashMap<String, RevocationEntry>,
    /// CRL版本号
    crl_version: u64,
    /// 最后CRL更新时间
    last_crl_update: OffsetDateTime,
}

/// 吊销请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// 证书序列号
    pub certificate_serial: String,
    /// 吊销原因
    pub reason: RevocationReason,
    /// 吊销请求者
    pub revoked_by: String,
    /// 吊销生效时间（可选，默认为立即生效）
    pub effective_date: Option<OffsetDateTime>,
    /// 是否紧急吊销（跳过宽限期）
    pub emergency_revocation: bool,
    /// 吊销请求时间
    pub requested_at: OffsetDateTime,
}

/// 吊销条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// 证书序列号
    pub serial_number: String,
    /// 吊销原因
    pub reason: RevocationReason,
    /// 吊销时间
    pub revocation_date: OffsetDateTime,
    /// 吊销者
    pub revoked_by: String,
    /// 生效时间
    pub effective_date: OffsetDateTime,
    /// 吊销状态
    pub status: RevocationStatus,
    /// 通知状态
    pub notification_sent: bool,
}

/// 吊销原因枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// 未指定
    Unspecified,
    /// 密钥泄露
    KeyCompromise,
    /// CA泄露
    CACompromise,
    /// 关联改变
    AffiliationChanged,
    /// 被替代
    Superseded,
    /// 停止操作
    CessationOfOperation,
    /// 证书暂停
    CertificateHold,
    /// 移除证书暂停
    RemoveFromCRL,
    /// 特权撤销
    PrivilegeWithdrawn,
    /// AA泄露
    AACompromise,
}

/// 吊销状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RevocationStatus {
    /// 待处理
    Pending,
    /// 已生效
    Active,
    /// 已暂停
    OnHold,
    /// 已撤销吊销
    Removed,
}

/// CRL生成结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CRLGenerationResult {
    /// CRL版本
    pub version: u64,
    /// 生成时间
    pub generated_at: OffsetDateTime,
    /// 下次更新时间
    pub next_update: OffsetDateTime,
    /// 吊销条目数量
    pub revoked_count: usize,
    /// CRL数据（PEM格式）
    pub crl_data: Option<String>,
}

impl RevocationManager {
    /// 创建新的吊销管理器
    pub fn new() -> Self {
        Self {
            policy: RevocationPolicy {
                default_grace_period_hours: 24,
                emergency_revocation_enabled: true,
                notify_relying_parties: true,
                crl_update_frequency_hours: 6,
            },
            revoked_certificates: HashMap::new(),
            crl_version: 1,
            last_crl_update: OffsetDateTime::now_utc(),
        }
    }

    /// 使用自定义策略创建吊销管理器
    pub fn with_policy(policy: RevocationPolicy) -> Self {
        Self {
            policy,
            revoked_certificates: HashMap::new(),
            crl_version: 1,
            last_crl_update: OffsetDateTime::now_utc(),
        }
    }

    /// 处理吊销请求
    pub fn revoke_certificate(
        &mut self,
        serial_number: &str,
        reason: RevocationReason,
        revoked_by: String,
    ) -> PkiResult<()> {
        let request = RevocationRequest {
            certificate_serial: serial_number.to_string(),
            reason: reason.clone(),
            revoked_by: revoked_by.clone(),
            effective_date: None,
            emergency_revocation: false,
            requested_at: OffsetDateTime::now_utc(),
        };

        self.process_revocation_request(request)
    }

    /// 处理详细的吊销请求
    pub fn process_revocation_request(&mut self, request: RevocationRequest) -> PkiResult<()> {
        // 验证吊销请求
        self.validate_revocation_request(&request)?;

        // 检查证书是否已被吊销
        if self.is_certificate_revoked(&request.certificate_serial) {
            return Err(PkiError::LifecycleError(format!(
                "Certificate {} is already revoked",
                request.certificate_serial
            )));
        }

        // 计算生效时间
        let effective_date = if request.emergency_revocation {
            // 紧急吊销立即生效
            request.requested_at
        } else if let Some(specified_date) = request.effective_date {
            // 使用指定的生效时间
            specified_date
        } else {
            // 使用宽限期
            request.requested_at
                + time::Duration::hours(self.policy.default_grace_period_hours as i64)
        };

        // 创建吊销条目
        let revocation_entry = RevocationEntry {
            serial_number: request.certificate_serial.clone(),
            reason: request.reason,
            revocation_date: request.requested_at,
            revoked_by: request.revoked_by,
            effective_date,
            status: if effective_date <= OffsetDateTime::now_utc() {
                RevocationStatus::Active
            } else {
                RevocationStatus::Pending
            },
            notification_sent: false,
        };

        // 添加到吊销列表
        self.revoked_certificates
            .insert(request.certificate_serial, revocation_entry);

        // 如果需要通知相关方
        if self.policy.notify_relying_parties {
            // TODO: 实现通知逻辑
        }

        Ok(())
    }

    /// 检查证书是否已被吊销
    pub fn is_certificate_revoked(&self, serial_number: &str) -> bool {
        if let Some(entry) = self.revoked_certificates.get(serial_number) {
            matches!(
                entry.status,
                RevocationStatus::Active | RevocationStatus::Pending
            )
        } else {
            false
        }
    }

    /// 获取证书吊销信息
    pub fn get_revocation_info(&self, serial_number: &str) -> Option<&RevocationEntry> {
        self.revoked_certificates.get(serial_number)
    }

    /// 暂停证书（证书暂停状态）
    pub fn hold_certificate(&mut self, serial_number: &str, holder: String) -> PkiResult<()> {
        if let Some(entry) = self.revoked_certificates.get_mut(serial_number) {
            if entry.reason == RevocationReason::CertificateHold {
                return Err(PkiError::LifecycleError(
                    "Certificate is already on hold".to_string(),
                ));
            }

            entry.reason = RevocationReason::CertificateHold;
            entry.status = RevocationStatus::OnHold;
            entry.revoked_by = holder;
            entry.revocation_date = OffsetDateTime::now_utc();
            entry.effective_date = OffsetDateTime::now_utc();
        } else {
            // 创建新的暂停条目
            let hold_entry = RevocationEntry {
                serial_number: serial_number.to_string(),
                reason: RevocationReason::CertificateHold,
                revocation_date: OffsetDateTime::now_utc(),
                revoked_by: holder,
                effective_date: OffsetDateTime::now_utc(),
                status: RevocationStatus::OnHold,
                notification_sent: false,
            };

            self.revoked_certificates
                .insert(serial_number.to_string(), hold_entry);
        }

        Ok(())
    }

    /// 解除证书暂停
    pub fn unhold_certificate(&mut self, serial_number: &str) -> PkiResult<()> {
        if let Some(entry) = self.revoked_certificates.get_mut(serial_number) {
            if entry.reason != RevocationReason::CertificateHold {
                return Err(PkiError::LifecycleError(
                    "Certificate is not on hold".to_string(),
                ));
            }

            // 从CRL中移除（设置为移除状态）
            entry.reason = RevocationReason::RemoveFromCRL;
            entry.status = RevocationStatus::Removed;
        } else {
            return Err(PkiError::LifecycleError(
                "Certificate not found in revocation list".to_string(),
            ));
        }

        Ok(())
    }

    /// 生成证书吊销列表 (CRL)
    pub fn generate_crl(&mut self) -> PkiResult<CRLGenerationResult> {
        // 更新待处理的吊销状态
        self.update_pending_revocations();

        let now = OffsetDateTime::now_utc();
        let next_update =
            now + time::Duration::hours(self.policy.crl_update_frequency_hours as i64);

        // 统计活跃的吊销条目
        let active_revocations: Vec<&RevocationEntry> = self
            .revoked_certificates
            .values()
            .filter(|entry| entry.status == RevocationStatus::Active)
            .collect();

        // TODO: 生成实际的CRL数据
        // 这里应该使用证书库生成标准的CRL格式

        self.crl_version += 1;
        self.last_crl_update = now;

        Ok(CRLGenerationResult {
            version: self.crl_version,
            generated_at: now,
            next_update,
            revoked_count: active_revocations.len(),
            crl_data: None, // TODO: 实际的CRL PEM数据
        })
    }

    /// 获取吊销统计信息
    pub fn get_revocation_statistics(&self) -> RevocationStatistics {
        let mut active_count = 0;
        let mut pending_count = 0;
        let mut on_hold_count = 0;
        let mut removed_count = 0;

        for entry in self.revoked_certificates.values() {
            match entry.status {
                RevocationStatus::Active => active_count += 1,
                RevocationStatus::Pending => pending_count += 1,
                RevocationStatus::OnHold => on_hold_count += 1,
                RevocationStatus::Removed => removed_count += 1,
            }
        }

        RevocationStatistics {
            total_revocations: self.revoked_certificates.len(),
            active_revocations: active_count,
            pending_revocations: pending_count,
            on_hold_revocations: on_hold_count,
            removed_revocations: removed_count,
            crl_version: self.crl_version,
            last_crl_update: self.last_crl_update,
        }
    }

    /// 列出所有吊销条目
    pub fn list_revoked_certificates(&self) -> Vec<&RevocationEntry> {
        self.revoked_certificates.values().collect()
    }

    /// 根据状态筛选吊销条目
    pub fn list_revoked_certificates_by_status(
        &self,
        status: RevocationStatus,
    ) -> Vec<&RevocationEntry> {
        self.revoked_certificates
            .values()
            .filter(|entry| entry.status == status)
            .collect()
    }

    /// 更新策略
    pub fn update_policy(&mut self, new_policy: RevocationPolicy) {
        self.policy = new_policy;
    }

    // 私有方法

    /// 验证吊销请求
    fn validate_revocation_request(&self, request: &RevocationRequest) -> PkiResult<()> {
        if request.certificate_serial.is_empty() {
            return Err(PkiError::LifecycleError(
                "Certificate serial number is required".to_string(),
            ));
        }

        if request.revoked_by.is_empty() {
            return Err(PkiError::LifecycleError(
                "Revoker information is required".to_string(),
            ));
        }

        // 验证吊销原因
        if matches!(request.reason, RevocationReason::RemoveFromCRL) {
            return Err(PkiError::LifecycleError(
                "RemoveFromCRL is not a valid revocation reason for new revocations".to_string(),
            ));
        }

        Ok(())
    }

    /// 更新待处理的吊销状态
    fn update_pending_revocations(&mut self) {
        let now = OffsetDateTime::now_utc();

        for entry in self.revoked_certificates.values_mut() {
            if entry.status == RevocationStatus::Pending && entry.effective_date <= now {
                entry.status = RevocationStatus::Active;
            }
        }
    }
}

/// 吊销统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationStatistics {
    /// 总吊销数量
    pub total_revocations: usize,
    /// 活跃吊销数量
    pub active_revocations: usize,
    /// 待处理吊销数量
    pub pending_revocations: usize,
    /// 暂停状态数量
    pub on_hold_revocations: usize,
    /// 已移除数量
    pub removed_revocations: usize,
    /// 当前CRL版本
    pub crl_version: u64,
    /// 最后CRL更新时间
    pub last_crl_update: OffsetDateTime,
}

impl Default for RevocationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason_str = match self {
            RevocationReason::Unspecified => "unspecified",
            RevocationReason::KeyCompromise => "keyCompromise",
            RevocationReason::CACompromise => "cACompromise",
            RevocationReason::AffiliationChanged => "affiliationChanged",
            RevocationReason::Superseded => "superseded",
            RevocationReason::CessationOfOperation => "cessationOfOperation",
            RevocationReason::CertificateHold => "certificateHold",
            RevocationReason::RemoveFromCRL => "removeFromCRL",
            RevocationReason::PrivilegeWithdrawn => "privilegeWithdrawn",
            RevocationReason::AACompromise => "aACompromise",
        };
        write!(f, "{}", reason_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_manager_creation() {
        let manager = RevocationManager::new();
        assert_eq!(manager.crl_version, 1);
        assert_eq!(manager.revoked_certificates.len(), 0);
    }

    #[test]
    fn test_certificate_revocation() {
        let mut manager = RevocationManager::new();
        let serial = "CERT-12345";

        // 吊销证书
        let result = manager.revoke_certificate(
            serial,
            RevocationReason::KeyCompromise,
            "admin@example.com".to_string(),
        );
        assert!(result.is_ok());

        // 检查证书是否已被吊销
        assert!(manager.is_certificate_revoked(serial));

        // 获取吊销信息
        let info = manager.get_revocation_info(serial);
        assert!(info.is_some());
        assert_eq!(info.unwrap().reason, RevocationReason::KeyCompromise);
    }

    #[test]
    fn test_duplicate_revocation() {
        let mut manager = RevocationManager::new();
        let serial = "CERT-12345";

        // 第一次吊销
        manager
            .revoke_certificate(
                serial,
                RevocationReason::KeyCompromise,
                "admin@example.com".to_string(),
            )
            .unwrap();

        // 第二次吊销应该失败
        let result = manager.revoke_certificate(
            serial,
            RevocationReason::Superseded,
            "admin@example.com".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_certificate_hold() {
        let mut manager = RevocationManager::new();
        let serial = "CERT-12345";

        // 暂停证书
        let result = manager.hold_certificate(serial, "admin@example.com".to_string());
        assert!(result.is_ok());

        // 检查是否处于暂停状态
        let info = manager.get_revocation_info(serial);
        assert!(info.is_some());
        assert_eq!(info.unwrap().reason, RevocationReason::CertificateHold);
        assert_eq!(info.unwrap().status, RevocationStatus::OnHold);

        // 解除暂停
        let result = manager.unhold_certificate(serial);
        assert!(result.is_ok());

        // 检查状态是否更新
        let info = manager.get_revocation_info(serial);
        assert_eq!(info.unwrap().status, RevocationStatus::Removed);
    }

    #[test]
    fn test_crl_generation() {
        let mut manager = RevocationManager::new();

        // 使用紧急吊销来立即生效
        let emergency_request1 = RevocationRequest {
            certificate_serial: "CERT-001".to_string(),
            reason: RevocationReason::KeyCompromise,
            revoked_by: "admin@example.com".to_string(),
            effective_date: None,
            emergency_revocation: true,
            requested_at: OffsetDateTime::now_utc(),
        };

        let emergency_request2 = RevocationRequest {
            certificate_serial: "CERT-002".to_string(),
            reason: RevocationReason::Superseded,
            revoked_by: "admin@example.com".to_string(),
            effective_date: None,
            emergency_revocation: true,
            requested_at: OffsetDateTime::now_utc(),
        };

        manager
            .process_revocation_request(emergency_request1)
            .unwrap();
        manager
            .process_revocation_request(emergency_request2)
            .unwrap();

        // 生成CRL
        let crl_result = manager.generate_crl().unwrap();
        assert_eq!(crl_result.revoked_count, 2);
        assert_eq!(crl_result.version, 2); // 版本应该递增
    }

    #[test]
    fn test_revocation_statistics() {
        let mut manager = RevocationManager::new();

        // 使用紧急吊销来立即生效
        let emergency_request1 = RevocationRequest {
            certificate_serial: "CERT-001".to_string(),
            reason: RevocationReason::KeyCompromise,
            revoked_by: "admin@example.com".to_string(),
            effective_date: None,
            emergency_revocation: true,
            requested_at: OffsetDateTime::now_utc(),
        };

        let emergency_request2 = RevocationRequest {
            certificate_serial: "CERT-002".to_string(),
            reason: RevocationReason::Superseded,
            revoked_by: "admin@example.com".to_string(),
            effective_date: None,
            emergency_revocation: true,
            requested_at: OffsetDateTime::now_utc(),
        };

        manager
            .process_revocation_request(emergency_request1)
            .unwrap();
        manager
            .process_revocation_request(emergency_request2)
            .unwrap();
        manager
            .hold_certificate("CERT-003", "admin@example.com".to_string())
            .unwrap();

        let stats = manager.get_revocation_statistics();
        assert_eq!(stats.total_revocations, 3);
        assert_eq!(stats.active_revocations, 2);
        assert_eq!(stats.on_hold_revocations, 1);
    }

    #[test]
    fn test_revocation_reason_display() {
        assert_eq!(RevocationReason::KeyCompromise.to_string(), "keyCompromise");
        assert_eq!(RevocationReason::CACompromise.to_string(), "cACompromise");
        assert_eq!(
            RevocationReason::CertificateHold.to_string(),
            "certificateHold"
        );
    }

    #[test]
    fn test_list_revoked_certificates() {
        let mut manager = RevocationManager::new();

        // 使用紧急吊销来立即生效
        let emergency_request = RevocationRequest {
            certificate_serial: "CERT-001".to_string(),
            reason: RevocationReason::KeyCompromise,
            revoked_by: "admin@example.com".to_string(),
            effective_date: None,
            emergency_revocation: true,
            requested_at: OffsetDateTime::now_utc(),
        };

        manager
            .process_revocation_request(emergency_request)
            .unwrap();
        manager
            .hold_certificate("CERT-002", "admin@example.com".to_string())
            .unwrap();

        // 列出所有吊销证书
        let all_revoked = manager.list_revoked_certificates();
        assert_eq!(all_revoked.len(), 2);

        // 按状态筛选
        let on_hold = manager.list_revoked_certificates_by_status(RevocationStatus::OnHold);
        assert_eq!(on_hold.len(), 1);

        let active = manager.list_revoked_certificates_by_status(RevocationStatus::Active);
        assert_eq!(active.len(), 1);
    }
}
