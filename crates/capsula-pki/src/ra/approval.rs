//! 审批工作流模块
//!
//! 提供手动/自动审批流程控制

use crate::ra::identity::AuthOutcome;

/// 工作流状态
#[derive(Debug, Clone, PartialEq)]
pub enum State {
    /// 待审批
    Pending,
    /// 审批通过
    Approved,
    /// 审批拒绝
    Rejected,
}

/// 审批工作流
pub struct Workflow {
    /// 自动审批阈值
    auto_approval_threshold: u8,
}

impl Workflow {
    /// 创建新的审批工作流
    pub fn new(auto_approval_threshold: u8) -> Self {
        Self {
            auto_approval_threshold,
        }
    }

    /// 评估是否可以自动审批
    pub fn evaluate(&self, auth_result: &AuthOutcome) -> State {
        if auth_result.trust_level >= self.auto_approval_threshold {
            State::Approved
        } else if auth_result.trust_level < 30 {
            State::Rejected
        } else {
            State::Pending
        }
    }
}

// 重新导出为旧名称以保持向后兼容
pub type WorkflowState = State;
pub type ApprovalWorkflow = Workflow;
