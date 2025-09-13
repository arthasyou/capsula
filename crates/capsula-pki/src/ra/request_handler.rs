//! CSR请求处理器
//!
//! 负责接收、验证和处理证书签名请求

use crate::ra::csr::CertificateSigningRequest;
use crate::error::{PkiError, Result};
use std::collections::HashMap;

/// 请求状态
#[derive(Debug, Clone, PartialEq)]
pub enum RequestStatus {
    /// 待处理
    Pending,
    /// 审核中
    UnderReview,
    /// 已批准
    Approved,
    /// 已拒绝
    Rejected,
    /// 已完成（证书已签发）
    Completed,
}

/// CSR请求信息
#[derive(Debug, Clone)]
pub struct CsrRequest {
    /// 请求ID
    pub request_id: String,
    /// CSR内容
    pub csr: CertificateSigningRequest,
    /// 请求状态
    pub status: RequestStatus,
    /// 提交时间
    pub submitted_at: time::OffsetDateTime,
    /// 更新时间
    pub updated_at: time::OffsetDateTime,
    /// 审批备注
    pub notes: Option<String>,
}

/// CSR请求处理器
pub struct RequestHandler {
    /// 待处理请求
    pending_requests: HashMap<String, CsrRequest>,
    /// 请求计数器
    request_counter: u64,
}

impl RequestHandler {
    /// 创建新的请求处理器
    pub fn new() -> Self {
        Self {
            pending_requests: HashMap::new(),
            request_counter: 0,
        }
    }

    /// 接收新的CSR请求
    pub fn receive_request(&mut self, csr: CertificateSigningRequest) -> Result<String> {
        self.request_counter += 1;
        let request_id = format!("REQ-{:08}", self.request_counter);
        
        let request = CsrRequest {
            request_id: request_id.clone(),
            csr,
            status: RequestStatus::Pending,
            submitted_at: time::OffsetDateTime::now_utc(),
            updated_at: time::OffsetDateTime::now_utc(),
            notes: None,
        };

        self.pending_requests.insert(request_id.clone(), request);
        Ok(request_id)
    }

    /// 获取请求信息
    pub fn get_request(&self, request_id: &str) -> Option<&CsrRequest> {
        self.pending_requests.get(request_id)
    }

    /// 更新请求状态
    pub fn update_request_status(
        &mut self,
        request_id: &str,
        status: RequestStatus,
        notes: Option<String>,
    ) -> Result<()> {
        let request = self.pending_requests.get_mut(request_id)
            .ok_or_else(|| PkiError::NotFound(format!("Request {} not found", request_id)))?;
        
        request.status = status;
        request.updated_at = time::OffsetDateTime::now_utc();
        if let Some(notes) = notes {
            request.notes = Some(notes);
        }

        Ok(())
    }
}