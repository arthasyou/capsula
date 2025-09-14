//! 证书申请确认模块
//!
//! 基于身份验证结果进行最终确认决策

use crate::ra::identity::AuthOutcome;

/// 确认决策结果
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// 需要人工确认
    RequiresReview,
    /// 自动通过
    Approved,
    /// 自动拒绝
    Rejected,
}

/// 证书申请确认策略
#[derive(Debug, Clone)]
pub struct ConfirmationPolicy {
    /// 自动通过的最低信任级别
    auto_approve_threshold: u8,
    /// 自动拒绝的最高信任级别
    auto_reject_threshold: u8,
}

impl ConfirmationPolicy {
    /// 创建新的确认策略
    pub fn new(auto_approve_threshold: u8) -> Self {
        Self {
            auto_approve_threshold,
            auto_reject_threshold: 30,
        }
    }

    /// 创建自定义确认策略
    pub fn with_thresholds(auto_approve: u8, auto_reject: u8) -> Self {
        Self {
            auto_approve_threshold: auto_approve,
            auto_reject_threshold: auto_reject,
        }
    }

    /// 基于身份验证结果做出确认决策
    pub fn decide(&self, auth_result: &AuthOutcome) -> Decision {
        if auth_result.trust_level >= self.auto_approve_threshold {
            Decision::Approved
        } else if auth_result.trust_level <= self.auto_reject_threshold {
            Decision::Rejected
        } else {
            Decision::RequiresReview
        }
    }

    /// 获取自动通过阈值
    pub fn auto_approve_threshold(&self) -> u8 {
        self.auto_approve_threshold
    }

    /// 获取自动拒绝阈值
    pub fn auto_reject_threshold(&self) -> u8 {
        self.auto_reject_threshold
    }
}

/// 确认决策的结果信息
#[derive(Debug, Clone)]
pub struct ConfirmationResult {
    /// 决策结果
    pub decision: Decision,
    /// 信任级别
    pub trust_level: u8,
    /// 决策理由
    pub reason: String,
}

impl ConfirmationResult {
    /// 创建确认结果
    pub fn new(decision: Decision, trust_level: u8, reason: String) -> Self {
        Self {
            decision,
            trust_level,
            reason,
        }
    }

    /// 是否通过确认
    pub fn is_approved(&self) -> bool {
        matches!(self.decision, Decision::Approved)
    }

    /// 是否需要人工审核
    pub fn requires_review(&self) -> bool {
        matches!(self.decision, Decision::RequiresReview)
    }

    /// 是否被拒绝
    pub fn is_rejected(&self) -> bool {
        matches!(self.decision, Decision::Rejected)
    }
}

/// 增强版确认器，提供详细的确认结果
pub struct Confirmer {
    policy: ConfirmationPolicy,
}

impl Confirmer {
    /// 创建新的确认器
    pub fn new(policy: ConfirmationPolicy) -> Self {
        Self { policy }
    }

    /// 创建默认确认器
    pub fn default() -> Self {
        Self {
            policy: ConfirmationPolicy::new(70),
        }
    }

    /// 执行详细确认
    pub fn confirm(&self, auth_result: &AuthOutcome) -> ConfirmationResult {
        let decision = self.policy.decide(auth_result);
        let reason = match decision {
            Decision::Approved => format!(
                "信任级别 {} 达到自动通过阈值 {}",
                auth_result.trust_level, self.policy.auto_approve_threshold
            ),
            Decision::Rejected => format!(
                "信任级别 {} 低于自动拒绝阈值 {}",
                auth_result.trust_level, self.policy.auto_reject_threshold
            ),
            Decision::RequiresReview => format!(
                "信任级别 {} 介于阈值之间，需要人工确认",
                auth_result.trust_level
            ),
        };

        ConfirmationResult::new(decision, auth_result.trust_level, reason)
    }
}
