//! 审批工作流模块
//!
//! 提供手动/自动审批流程控制

use crate::error::Result;
use crate::ra::identity_auth::AuthResult;

/// 工作流状态
#[derive(Debug, Clone, PartialEq)]
pub enum WorkflowState {
    /// 待审批
    Pending,
    /// 审批通过
    Approved,
    /// 审批拒绝
    Rejected,
}

/// 审批工作流
pub struct ApprovalWorkflow {
    /// 自动审批阈值
    auto_approval_threshold: u8,
}

impl ApprovalWorkflow {
    /// 创建新的审批工作流
    pub fn new(auto_approval_threshold: u8) -> Self {
        Self {
            auto_approval_threshold,
        }
    }

    /// 评估是否可以自动审批
    pub fn evaluate(&self, auth_result: &AuthResult) -> WorkflowState {
        if auth_result.trust_level >= self.auto_approval_threshold {
            WorkflowState::Approved
        } else if auth_result.trust_level < 30 {
            WorkflowState::Rejected
        } else {
            WorkflowState::Pending
        }
    }
}