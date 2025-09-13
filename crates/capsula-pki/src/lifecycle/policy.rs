//! 生命周期策略模块

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
}

impl Default for LifecyclePolicy {
    fn default() -> Self {
        Self {
            default_validity_days: 365,
            renewal_notification_days: 30,
            auto_renewal_threshold_days: 7,
            enable_auto_renewal: false,
        }
    }
}