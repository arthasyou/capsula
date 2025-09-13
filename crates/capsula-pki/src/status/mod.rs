//! 证书状态查询模块
//!
//! 提供证书状态查询功能，包括：
//! - CRL（证书吊销列表）
//! - OCSP（在线证书状态协议）
//! - 证书状态验证
//! - 状态缓存

pub mod crl;
pub mod ocsp;
pub mod validator;
pub mod cache;

// 重新导出CRL相关类型
pub use crl::{CRLManager, CertificateRevocationList, RevocationEntry};

use crate::error::Result;
use std::collections::HashMap;

/// 证书状态枚举
#[derive(Debug, Clone, PartialEq)]
pub enum CertificateStatus {
    /// 有效
    Valid,
    /// 已吊销
    Revoked {
        /// 吊销原因
        reason: RevocationReason,
        /// 吊销时间
        revoked_at: time::OffsetDateTime,
    },
    /// 已过期
    Expired,
    /// 尚未生效
    NotYetValid,
    /// 未知状态
    Unknown,
}

/// 吊销原因
#[derive(Debug, Clone, PartialEq)]
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
    /// 撤销CRL
    RemoveFromCRL,
    /// 特权撤回
    PrivilegeWithdrawn,
    /// AA泄露
    AACompromise,
}

/// 状态查询响应
#[derive(Debug, Clone)]
pub struct StatusResponse {
    /// 证书序列号
    pub serial_number: String,
    /// 证书状态
    pub status: CertificateStatus,
    /// 查询时间
    pub query_time: time::OffsetDateTime,
    /// 响应来源
    pub source: String,
    /// 缓存是否命中
    pub from_cache: bool,
}

/// 证书状态管理器
pub struct CertificateStatusManager {
    /// CRL管理器
    crl_manager: Option<CRLManager>,
    /// OCSP配置
    ocsp_enabled: bool,
    /// 状态缓存
    status_cache: HashMap<String, StatusResponse>,
    /// 缓存TTL（秒）
    cache_ttl_seconds: u64,
}

impl CertificateStatusManager {
    /// 创建新的状态管理器
    pub fn new(cache_ttl_seconds: u64) -> Self {
        Self {
            crl_manager: None,
            ocsp_enabled: false,
            status_cache: HashMap::new(),
            cache_ttl_seconds,
        }
    }

    /// 启用CRL支持
    pub fn enable_crl(&mut self, crl_manager: CRLManager) {
        self.crl_manager = Some(crl_manager);
    }

    /// 启用OCSP支持
    pub fn enable_ocsp(&mut self) {
        self.ocsp_enabled = true;
    }

    /// 查询证书状态
    pub fn query_certificate_status(&mut self, serial_number: &str) -> Result<StatusResponse> {
        // 首先检查缓存
        if let Some(cached_response) = self.get_cached_status(serial_number) {
            return Ok(cached_response);
        }

        // 尝试CRL查询
        if let Some(crl_manager) = &self.crl_manager {
            if let Some(revocation_entry) = crl_manager.check_revocation_status(serial_number)? {
                let response = StatusResponse {
                    serial_number: serial_number.to_string(),
                    status: CertificateStatus::Revoked {
                        reason: revocation_entry.reason.clone(),
                        revoked_at: revocation_entry.revoked_at,
                    },
                    query_time: time::OffsetDateTime::now_utc(),
                    source: "CRL".to_string(),
                    from_cache: false,
                };
                
                self.cache_status_response(&response);
                return Ok(response);
            }
        }

        // TODO: OCSP查询实现

        // 默认返回未知状态
        let response = StatusResponse {
            serial_number: serial_number.to_string(),
            status: CertificateStatus::Unknown,
            query_time: time::OffsetDateTime::now_utc(),
            source: "Default".to_string(),
            from_cache: false,
        };

        Ok(response)
    }

    /// 获取缓存的状态
    fn get_cached_status(&self, serial_number: &str) -> Option<StatusResponse> {
        if let Some(cached_response) = self.status_cache.get(serial_number) {
            let now = time::OffsetDateTime::now_utc();
            let cache_age = (now - cached_response.query_time).whole_seconds() as u64;
            
            if cache_age < self.cache_ttl_seconds {
                let mut response = cached_response.clone();
                response.from_cache = true;
                return Some(response);
            }
        }
        None
    }

    /// 缓存状态响应
    fn cache_status_response(&mut self, response: &StatusResponse) {
        self.status_cache.insert(response.serial_number.clone(), response.clone());
    }

    /// 清理过期缓存
    pub fn cleanup_expired_cache(&mut self) {
        let now = time::OffsetDateTime::now_utc();
        self.status_cache.retain(|_, response| {
            let cache_age = (now - response.query_time).whole_seconds() as u64;
            cache_age < self.cache_ttl_seconds
        });
    }
}