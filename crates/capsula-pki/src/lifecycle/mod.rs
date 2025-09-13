//! 证书生命周期管理模块
//!
//! 提供证书生命周期管理功能，包括：
//! - 证书签发
//! - 证书更新（renewal）
//! - 证书吊销（revocation）
//! - 证书过期通知
//! - 证书链验证

pub mod chain;
pub mod issuance;
pub mod renewal;
pub mod revocation;
pub mod expiry_notification;
pub mod policy;

// 重新导出证书链相关类型
pub use chain::{ChainValidator, ValidationResult, CertificateChain};

use crate::error::Result;
use time::OffsetDateTime;

/// 生命周期策略
#[derive(Debug, Clone)]
pub struct LifecyclePolicy {
    /// 默认证书有效期（天）
    pub default_validity_days: u32,
    /// 续期通知提前天数
    pub renewal_notification_days: u32,
    /// 自动续期阈值（剩余天数）
    pub auto_renewal_threshold_days: u32,
    /// 是否启用自动续期
    pub enable_auto_renewal: bool,
    /// 吊销后宽限期（小时）
    pub revocation_grace_period_hours: u32,
}

impl Default for LifecyclePolicy {
    fn default() -> Self {
        Self {
            default_validity_days: 365,
            renewal_notification_days: 30,
            auto_renewal_threshold_days: 7,
            enable_auto_renewal: false,
            revocation_grace_period_hours: 24,
        }
    }
}

/// 证书生命周期管理器
pub struct LifecycleManager {
    /// 生命周期策略
    policy: LifecyclePolicy,
}

impl LifecycleManager {
    /// 创建新的生命周期管理器
    pub fn new(policy: LifecyclePolicy) -> Self {
        Self { policy }
    }

    /// 检查证书是否需要更新
    pub fn needs_renewal(&self, expiry_date: OffsetDateTime) -> bool {
        let now = OffsetDateTime::now_utc();
        let days_until_expiry = (expiry_date - now).whole_days();
        days_until_expiry <= self.policy.renewal_notification_days as i64
    }

    /// 检查是否可以自动更新
    pub fn can_auto_renew(&self, expiry_date: OffsetDateTime) -> bool {
        if !self.policy.enable_auto_renewal {
            return false;
        }
        
        let now = OffsetDateTime::now_utc();
        let days_until_expiry = (expiry_date - now).whole_days();
        days_until_expiry <= self.policy.auto_renewal_threshold_days as i64
    }
}