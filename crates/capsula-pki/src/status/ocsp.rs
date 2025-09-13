//! OCSP (在线证书状态协议) 模块

use crate::error::Result;

/// OCSP响应状态
#[derive(Debug, Clone, PartialEq)]
pub enum OCSPStatus {
    /// 良好
    Good,
    /// 已吊销
    Revoked,
    /// 未知
    Unknown,
}

/// OCSP响应
#[derive(Debug, Clone)]
pub struct OCSPResponse {
    /// 证书序列号
    pub serial_number: String,
    /// 状态
    pub status: OCSPStatus,
    /// 响应时间
    pub response_time: time::OffsetDateTime,
}

/// OCSP响应器
pub struct OCSPResponder;

impl OCSPResponder {
    /// 创建新的OCSP响应器
    pub fn new() -> Self {
        Self
    }

    /// 处理OCSP请求
    pub fn handle_request(&self, _serial_number: &str) -> Result<OCSPResponse> {
        // TODO: 实现OCSP请求处理逻辑
        Ok(OCSPResponse {
            serial_number: _serial_number.to_string(),
            status: OCSPStatus::Good,
            response_time: time::OffsetDateTime::now_utc(),
        })
    }
}