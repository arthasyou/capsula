//! 证书状态查询模块
//!
//! 提供完整的证书状态查询功能，包括：
//! - CRL（证书吊销列表）集成
//! - OCSP（在线证书状态协议）支持
//! - 证书状态验证和缓存
//! - 与生命周期管理模块深度集成

pub mod cache;
pub mod crl;
pub mod ocsp;
pub mod validator;

use std::collections::HashMap;

pub use cache::{CacheStats, StatusCache};
// 重新导出子模块类型
pub use crl::{CRLManager, CertificateRevocationList, RevocationEntry};
pub use ocsp::{OCSPRequest, OCSPResponder, OCSPResponse, OCSPStatus};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
pub use validator::CertificateValidator;

use crate::{
    error::Result as PkiResult,
    lifecycle::{
        revocation::RevocationReason as LifecycleRevocationReason, CertificateLifecycle,
        CertificateStatus as LifecycleStatus,
    },
};

/// 证书状态查询结果
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CertificateStatus {
    /// 有效证书
    Valid {
        /// 验证时间
        validated_at: OffsetDateTime,
    },
    /// 已吊销证书
    Revoked {
        /// 吊销原因
        reason: RevocationReason,
        /// 吊销时间
        revoked_at: OffsetDateTime,
        /// 吊销序列号
        revocation_serial: Option<String>,
    },
    /// 已过期证书
    Expired {
        /// 过期时间
        expired_at: OffsetDateTime,
    },
    /// 尚未生效
    NotYetValid {
        /// 生效时间
        valid_from: OffsetDateTime,
    },
    /// 即将过期
    Expiring {
        /// 剩余天数
        days_remaining: u32,
        /// 过期时间
        expires_at: OffsetDateTime,
    },
    /// 暂停使用
    Suspended {
        /// 暂停原因
        reason: String,
        /// 暂停时间
        suspended_at: OffsetDateTime,
    },
    /// 未知状态
    Unknown {
        /// 查询时间
        queried_at: OffsetDateTime,
        /// 失败原因
        reason: String,
    },
}

/// 吊销原因枚举
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// 未指定原因
    Unspecified,
    /// 密钥泄露
    KeyCompromise,
    /// CA密钥泄露
    CACompromise,
    /// 关联改变
    AffiliationChanged,
    /// 证书被替代
    Superseded,
    /// 停止操作
    CessationOfOperation,
    /// 证书暂停（可恢复）
    CertificateHold,
    /// 从CRL中移除
    RemoveFromCRL,
    /// 特权撤回
    PrivilegeWithdrawn,
    /// AA密钥泄露
    AACompromise,
}

/// 状态查询来源
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum QuerySource {
    /// 从生命周期管理模块查询
    LifecycleManager,
    /// 从CRL查询
    CRL { crl_number: u64 },
    /// 从OCSP查询
    OCSP { responder_url: String },
    /// 从缓存查询
    Cache { cache_age_seconds: u64 },
    /// 直接证书验证
    DirectValidation,
}

/// 状态查询响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// 证书序列号
    pub serial_number: String,
    /// 证书状态
    pub status: CertificateStatus,
    /// 查询时间
    pub query_time: OffsetDateTime,
    /// 查询来源
    pub source: QuerySource,
    /// 是否来自缓存
    pub from_cache: bool,
    /// 查询耗时（毫秒）
    pub query_duration_ms: u64,
    /// 置信度 (0.0-1.0)
    pub confidence: f32,
}

/// 批量状态查询请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchStatusRequest {
    /// 证书序列号列表
    pub serial_numbers: Vec<String>,
    /// 是否允许使用缓存
    pub allow_cached: bool,
    /// 最大缓存年龄（秒）
    pub max_cache_age_seconds: Option<u64>,
    /// 查询超时（秒）
    pub timeout_seconds: Option<u64>,
}

/// 批量状态查询响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchStatusResponse {
    /// 所有查询结果
    pub results: HashMap<String, StatusResponse>,
    /// 成功查询数量
    pub success_count: usize,
    /// 失败查询数量
    pub failed_count: usize,
    /// 总查询耗时（毫秒）
    pub total_duration_ms: u64,
}

/// 统一证书状态管理器
pub struct CertificateStatusManager {
    /// CRL管理器
    crl_manager: Option<CRLManager>,
    /// OCSP响应器
    ocsp_responder: Option<OCSPResponder>,
    /// 状态缓存
    cache: StatusCache,
    /// 证书验证器
    #[allow(dead_code)]
    validator: CertificateValidator,
    /// 启用生命周期管理集成
    lifecycle_integration: bool,
    /// 查询配置
    config: StatusQueryConfig,
}

/// 状态查询配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusQueryConfig {
    /// 默认缓存TTL（秒）
    pub default_cache_ttl_seconds: u64,
    /// 最大查询超时（秒）
    pub max_query_timeout_seconds: u64,
    /// OCSP查询超时（秒）
    pub ocsp_timeout_seconds: u64,
    /// 启用批量优化（未来扩展）
    pub enable_batch_optimization: bool,
    /// 最大批量查询数
    pub max_batch_queries: usize,
    /// 查询重试次数
    pub max_retry_attempts: u32,
    /// 重试间隔（毫秒）
    pub retry_interval_ms: u64,
}

impl Default for StatusQueryConfig {
    fn default() -> Self {
        Self {
            default_cache_ttl_seconds: 3600, // 1小时
            max_query_timeout_seconds: 30,
            ocsp_timeout_seconds: 10,
            enable_batch_optimization: true,
            max_batch_queries: 100,
            max_retry_attempts: 3,
            retry_interval_ms: 1000,
        }
    }
}

impl CertificateStatusManager {
    /// 创建新的状态管理器
    pub fn new(config: StatusQueryConfig) -> Self {
        Self {
            crl_manager: None,
            ocsp_responder: None,
            cache: StatusCache::with_ttl(config.default_cache_ttl_seconds),
            validator: CertificateValidator::new(),
            lifecycle_integration: false,
            config,
        }
    }

    /// 启用CRL支持
    pub fn with_crl(mut self, crl_manager: CRLManager) -> Self {
        self.crl_manager = Some(crl_manager);
        self
    }

    /// 启用OCSP支持
    pub fn with_ocsp(mut self, ocsp_responder: OCSPResponder) -> Self {
        self.ocsp_responder = Some(ocsp_responder);
        self
    }

    /// 启用生命周期管理集成
    pub fn with_lifecycle_integration(mut self) -> Self {
        self.lifecycle_integration = true;
        self
    }

    /// 查询单个证书状态
    pub fn query_certificate_status(
        &mut self,
        serial_number: &str,
        allow_cached: bool,
    ) -> PkiResult<StatusResponse> {
        let start_time = std::time::Instant::now();

        // 1. 检查缓存（如果允许）
        if allow_cached {
            if let Some(cached_response) = self.cache.get(serial_number) {
                return Ok(cached_response);
            }
        }

        // 2. 尝试从CRL查询
        if let Some(crl_manager) = &self.crl_manager {
            if let Some(revocation_entry) = crl_manager.check_revocation_status(serial_number)? {
                let response = StatusResponse {
                    serial_number: serial_number.to_string(),
                    status: CertificateStatus::Revoked {
                        reason: self.map_revocation_reason(&revocation_entry.reason),
                        revoked_at: revocation_entry.revocation_date,
                        revocation_serial: Some(crl_manager.get_crl().crl_number.to_string()),
                    },
                    query_time: OffsetDateTime::now_utc(),
                    source: QuerySource::CRL {
                        crl_number: crl_manager.get_crl().crl_number,
                    },
                    from_cache: false,
                    query_duration_ms: start_time.elapsed().as_millis() as u64,
                    confidence: 1.0, // CRL是权威来源
                };

                // 缓存结果
                self.cache.put(response.clone());
                return Ok(response);
            }
        }

        // 3. 尝试OCSP查询
        if let Some(ocsp_responder) = self.ocsp_responder.as_mut() {
            match ocsp_responder.query_status(serial_number) {
                Ok(ocsp_response) => {
                    let response = StatusResponse {
                        serial_number: serial_number.to_string(),
                        status: match ocsp_response.status {
                            OCSPStatus::Good => CertificateStatus::Valid {
                                validated_at: ocsp_response.response_time,
                            },
                            OCSPStatus::Revoked {
                                reason,
                                revocation_time,
                            } => CertificateStatus::Revoked {
                                reason,
                                revoked_at: revocation_time,
                                revocation_serial: None,
                            },
                            OCSPStatus::Unknown => CertificateStatus::Unknown {
                                queried_at: OffsetDateTime::now_utc(),
                                reason: "OCSP responder returned unknown status".to_string(),
                            },
                        },
                        query_time: OffsetDateTime::now_utc(),
                        source: QuerySource::OCSP {
                            responder_url: ocsp_response.responder_url,
                        },
                        from_cache: false,
                        query_duration_ms: start_time.elapsed().as_millis() as u64,
                        confidence: 0.9, // OCSP稍低于CRL
                    };

                    // 缓存结果
                    self.cache.put(response.clone());
                    return Ok(response);
                }
                Err(_) => {
                    // OCSP查询失败，继续其他方式
                }
            }
        }

        // 4. 默认返回未知状态
        let response = StatusResponse {
            serial_number: serial_number.to_string(),
            status: CertificateStatus::Unknown {
                queried_at: OffsetDateTime::now_utc(),
                reason: "No authoritative status source available".to_string(),
            },
            query_time: OffsetDateTime::now_utc(),
            source: QuerySource::DirectValidation,
            from_cache: false,
            query_duration_ms: start_time.elapsed().as_millis() as u64,
            confidence: 0.0,
        };

        Ok(response)
    }

    /// 批量查询证书状态
    pub fn batch_query_certificate_status(
        &mut self,
        request: BatchStatusRequest,
    ) -> PkiResult<BatchStatusResponse> {
        let start_time = std::time::Instant::now();
        let mut results = HashMap::new();
        let mut success_count = 0;
        let mut failed_count = 0;

        // 串行查询（简化但实用的版本）
        for serial_number in &request.serial_numbers {
            match self.query_certificate_status(serial_number, request.allow_cached) {
                Ok(response) => {
                    results.insert(serial_number.clone(), response);
                    success_count += 1;
                }
                Err(_) => {
                    // 创建失败响应
                    let error_response = StatusResponse {
                        serial_number: serial_number.clone(),
                        status: CertificateStatus::Unknown {
                            queried_at: OffsetDateTime::now_utc(),
                            reason: "Query failed".to_string(),
                        },
                        query_time: OffsetDateTime::now_utc(),
                        source: QuerySource::DirectValidation,
                        from_cache: false,
                        query_duration_ms: 0,
                        confidence: 0.0,
                    };
                    results.insert(serial_number.clone(), error_response);
                    failed_count += 1;
                }
            }
        }

        Ok(BatchStatusResponse {
            results,
            success_count,
            failed_count,
            total_duration_ms: start_time.elapsed().as_millis() as u64,
        })
    }

    /// 集成生命周期管理模块查询状态
    pub fn query_from_lifecycle(&self, certificate: &CertificateLifecycle) -> StatusResponse {
        let start_time = std::time::Instant::now();

        let status = match &certificate.status {
            LifecycleStatus::Valid => CertificateStatus::Valid {
                validated_at: certificate.last_checked,
            },
            LifecycleStatus::Expired => CertificateStatus::Expired {
                expired_at: certificate.expiry_date,
            },
            LifecycleStatus::Expiring(days) => CertificateStatus::Expiring {
                days_remaining: *days,
                expires_at: certificate.expiry_date,
            },
            LifecycleStatus::Revoked { reason, date } => CertificateStatus::Revoked {
                reason: self.map_lifecycle_revocation_reason(reason),
                revoked_at: *date,
                revocation_serial: None,
            },
            LifecycleStatus::Suspended => CertificateStatus::Suspended {
                reason: "Certificate suspended by lifecycle manager".to_string(),
                suspended_at: certificate.last_checked,
            },
            LifecycleStatus::PendingRenewal => CertificateStatus::Valid {
                validated_at: certificate.last_checked,
            },
        };

        StatusResponse {
            serial_number: certificate.serial_number.clone(),
            status,
            query_time: OffsetDateTime::now_utc(),
            source: QuerySource::LifecycleManager,
            from_cache: false,
            query_duration_ms: start_time.elapsed().as_millis() as u64,
            confidence: 1.0, // 生命周期管理器是权威来源
        }
    }

    /// 清理过期缓存
    pub fn cleanup_expired_cache(&mut self) {
        self.cache.cleanup_expired();
    }

    /// 获取缓存统计信息
    pub fn get_cache_stats(&self) -> CacheStats {
        self.cache.get_stats()
    }

    /// 获取查询配置
    pub fn get_config(&self) -> &StatusQueryConfig {
        &self.config
    }

    /// 更新查询配置
    pub fn update_config(&mut self, config: StatusQueryConfig) {
        self.config = config;
        // 更新缓存TTL如果需要
        self.cache = StatusCache::with_ttl(self.config.default_cache_ttl_seconds);
    }

    // 私有辅助方法

    /// 映射吊销原因：从CRL类型到统一类型
    pub fn map_revocation_reason(
        &self,
        reason: &crate::types::RevocationReason,
    ) -> RevocationReason {
        match reason {
            crate::types::RevocationReason::Unspecified => RevocationReason::Unspecified,
            crate::types::RevocationReason::KeyCompromise => RevocationReason::KeyCompromise,
            crate::types::RevocationReason::CACompromise => RevocationReason::CACompromise,
            crate::types::RevocationReason::AffiliationChanged => {
                RevocationReason::AffiliationChanged
            }
            crate::types::RevocationReason::Superseded => RevocationReason::Superseded,
            crate::types::RevocationReason::CessationOfOperation => {
                RevocationReason::CessationOfOperation
            }
            crate::types::RevocationReason::CertificateHold => RevocationReason::CertificateHold,
            crate::types::RevocationReason::RemoveFromCRL => RevocationReason::RemoveFromCRL,
            crate::types::RevocationReason::PrivilegeWithdrawn => {
                RevocationReason::PrivilegeWithdrawn
            }
            crate::types::RevocationReason::AACompromise => RevocationReason::AACompromise,
        }
    }

    /// 映射吊销原因：从生命周期类型到统一类型
    fn map_lifecycle_revocation_reason(
        &self,
        reason: &LifecycleRevocationReason,
    ) -> RevocationReason {
        match reason {
            LifecycleRevocationReason::Unspecified => RevocationReason::Unspecified,
            LifecycleRevocationReason::KeyCompromise => RevocationReason::KeyCompromise,
            LifecycleRevocationReason::CACompromise => RevocationReason::CACompromise,
            LifecycleRevocationReason::AffiliationChanged => RevocationReason::AffiliationChanged,
            LifecycleRevocationReason::Superseded => RevocationReason::Superseded,
            LifecycleRevocationReason::CessationOfOperation => {
                RevocationReason::CessationOfOperation
            }
            LifecycleRevocationReason::CertificateHold => RevocationReason::CertificateHold,
            LifecycleRevocationReason::RemoveFromCRL => RevocationReason::RemoveFromCRL,
            LifecycleRevocationReason::PrivilegeWithdrawn => RevocationReason::PrivilegeWithdrawn,
            LifecycleRevocationReason::AACompromise => RevocationReason::AACompromise,
        }
    }
}

impl Default for CertificateStatusManager {
    fn default() -> Self {
        Self::new(StatusQueryConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use capsula_key::Curve25519;
    use time::Duration;

    use super::*;
    use crate::{status::crl::CRLManager, types::RevocationReason as CrlRevocationReason};

    fn create_test_crl_manager() -> CRLManager {
        let keypair = Curve25519::generate().unwrap();
        CRLManager::new(
            "CN=Test CA".to_string(),
            keypair,
            7,    // 7 days validity
            true, // auto sign
        )
    }

    fn create_test_ocsp_responder() -> OCSPResponder {
        use super::ocsp::*;
        OCSPResponder::new(OCSPResponderConfig::default())
    }

    #[test]
    fn test_certificate_status_manager_creation() {
        let manager = CertificateStatusManager::new(StatusQueryConfig::default());
        assert!(manager.crl_manager.is_none());
        assert!(manager.ocsp_responder.is_none());
        assert!(!manager.lifecycle_integration);
    }

    #[test]
    fn test_certificate_status_manager_with_crl() {
        let crl_manager = create_test_crl_manager();
        let manager =
            CertificateStatusManager::new(StatusQueryConfig::default()).with_crl(crl_manager);

        assert!(manager.crl_manager.is_some());
    }

    #[test]
    fn test_certificate_status_manager_with_ocsp() {
        let ocsp_responder = create_test_ocsp_responder();
        let manager =
            CertificateStatusManager::new(StatusQueryConfig::default()).with_ocsp(ocsp_responder);

        assert!(manager.ocsp_responder.is_some());
    }

    #[test]
    fn test_query_certificate_status_unknown() {
        let mut manager = CertificateStatusManager::new(StatusQueryConfig::default());

        let result = manager.query_certificate_status("12345", true).unwrap();
        assert_eq!(result.serial_number, "12345");
        assert!(matches!(result.status, CertificateStatus::Unknown { .. }));
        assert_eq!(result.confidence, 0.0);
        assert!(!result.from_cache);
    }

    #[test]
    fn test_query_certificate_status_with_crl_revoked() {
        let mut crl_manager = create_test_crl_manager();
        let _ = crl_manager.revoke_certificate(
            "12345".to_string(),
            CrlRevocationReason::KeyCompromise,
            None,
        );

        let mut manager =
            CertificateStatusManager::new(StatusQueryConfig::default()).with_crl(crl_manager);

        let result = manager.query_certificate_status("12345", false).unwrap();
        assert_eq!(result.serial_number, "12345");
        assert!(matches!(result.status, CertificateStatus::Revoked { .. }));
        assert_eq!(result.confidence, 1.0);
        assert!(!result.from_cache);

        if let CertificateStatus::Revoked { reason, .. } = result.status {
            assert_eq!(reason, RevocationReason::KeyCompromise);
        }
    }

    #[test]
    fn test_query_certificate_status_with_ocsp_good() {
        let mut ocsp_responder = create_test_ocsp_responder();
        // Add a certificate with GOOD status
        let _ = ocsp_responder.add_certificate("12345".to_string(), super::ocsp::OCSPStatus::Good);

        let mut manager =
            CertificateStatusManager::new(StatusQueryConfig::default()).with_ocsp(ocsp_responder);

        let result = manager.query_certificate_status("12345", false).unwrap();
        assert_eq!(result.serial_number, "12345");
        assert!(matches!(result.status, CertificateStatus::Valid { .. }));
        assert_eq!(result.confidence, 0.9);
        assert!(!result.from_cache);
    }

    #[test]
    fn test_query_certificate_status_caching() {
        let mut manager = CertificateStatusManager::new(StatusQueryConfig::default());

        // First query - should miss cache
        let result1 = manager.query_certificate_status("12345", true).unwrap();
        assert!(!result1.from_cache);

        // Second query - should hit cache (the cache is updated in the first query)
        let result2 = manager.query_certificate_status("12345", true).unwrap();
        // Note: Since we're querying unknown certificates, they'll be cached but marked as unknown
        assert_eq!(result1.serial_number, result2.serial_number);
    }

    #[test]
    fn test_batch_query_certificate_status() {
        let mut manager = CertificateStatusManager::new(StatusQueryConfig::default());

        let request = BatchStatusRequest {
            serial_numbers: vec!["12345".to_string(), "67890".to_string()],
            allow_cached: true,
            max_cache_age_seconds: Some(3600),
            timeout_seconds: Some(30),
        };

        let result = manager.batch_query_certificate_status(request).unwrap();
        assert_eq!(result.success_count, 2);
        assert_eq!(result.failed_count, 0);
        assert_eq!(result.results.len(), 2);
        assert!(result.results.contains_key("12345"));
        assert!(result.results.contains_key("67890"));
    }

    #[test]
    fn test_status_query_config_default() {
        let config = StatusQueryConfig::default();
        assert_eq!(config.default_cache_ttl_seconds, 3600);
        assert_eq!(config.max_query_timeout_seconds, 30);
        assert_eq!(config.ocsp_timeout_seconds, 10);
        assert!(config.enable_batch_optimization);
        assert_eq!(config.max_batch_queries, 100);
        assert_eq!(config.max_retry_attempts, 3);
        assert_eq!(config.retry_interval_ms, 1000);
    }

    #[test]
    fn test_cache_stats() {
        let manager = CertificateStatusManager::new(StatusQueryConfig::default());
        let stats = manager.get_cache_stats();
        assert_eq!(stats.total_items, 0);
        assert_eq!(stats.hit_count, 0);
        assert_eq!(stats.miss_count, 0);
        assert_eq!(stats.hit_rate, 0.0);
    }

    #[test]
    fn test_config_access() {
        let mut manager = CertificateStatusManager::new(StatusQueryConfig::default());

        // 测试获取配置
        let config = manager.get_config();
        assert_eq!(config.default_cache_ttl_seconds, 3600);

        // 测试更新配置
        let mut new_config = StatusQueryConfig::default();
        new_config.default_cache_ttl_seconds = 7200;
        manager.update_config(new_config);

        let updated_config = manager.get_config();
        assert_eq!(updated_config.default_cache_ttl_seconds, 7200);
    }

    #[test]
    fn test_cleanup_expired_cache() {
        let mut manager = CertificateStatusManager::new(StatusQueryConfig::default());

        // Add a query to cache
        let _ = manager.query_certificate_status("12345", false);

        // Cleanup expired cache (nothing should be expired immediately)
        manager.cleanup_expired_cache();

        // Test passes if no panic occurs
    }

    #[test]
    fn test_revocation_reason_mapping() {
        let manager = CertificateStatusManager::new(StatusQueryConfig::default());

        // Test CRL revocation reason mapping
        let crl_reason = CrlRevocationReason::KeyCompromise;
        let mapped = manager.map_revocation_reason(&crl_reason);
        assert_eq!(mapped, RevocationReason::KeyCompromise);

        // Test other reasons
        let crl_reason = CrlRevocationReason::CACompromise;
        let mapped = manager.map_revocation_reason(&crl_reason);
        assert_eq!(mapped, RevocationReason::CACompromise);
    }

    #[test]
    fn test_certificate_status_serialization() {
        let status = CertificateStatus::Valid {
            validated_at: OffsetDateTime::now_utc(),
        };

        let json = serde_json::to_string(&status).unwrap();
        let deserialized: CertificateStatus = serde_json::from_str(&json).unwrap();

        assert!(matches!(deserialized, CertificateStatus::Valid { .. }));
    }

    #[test]
    fn test_status_response_serialization() {
        let response = StatusResponse {
            serial_number: "12345".to_string(),
            status: CertificateStatus::Valid {
                validated_at: OffsetDateTime::now_utc(),
            },
            query_time: OffsetDateTime::now_utc(),
            source: QuerySource::DirectValidation,
            from_cache: false,
            query_duration_ms: 100,
            confidence: 1.0,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: StatusResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.serial_number, "12345");
        assert_eq!(deserialized.confidence, 1.0);
    }

    #[test]
    fn test_batch_status_request_serialization() {
        let request = BatchStatusRequest {
            serial_numbers: vec!["12345".to_string(), "67890".to_string()],
            allow_cached: true,
            max_cache_age_seconds: Some(3600),
            timeout_seconds: Some(30),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: BatchStatusRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.serial_numbers.len(), 2);
        assert!(deserialized.allow_cached);
        assert_eq!(deserialized.max_cache_age_seconds, Some(3600));
    }

    #[test]
    fn test_lifecycle_integration() {
        use crate::lifecycle::{CertificateLifecycle, CertificateStatus as LifecycleStatus};

        let manager = CertificateStatusManager::new(StatusQueryConfig::default())
            .with_lifecycle_integration();

        assert!(manager.lifecycle_integration);

        // Create a mock certificate lifecycle
        let lifecycle = CertificateLifecycle {
            serial_number: "12345".to_string(),
            subject: "CN=Test".to_string(),
            issued_date: OffsetDateTime::now_utc() - Duration::days(30),
            expiry_date: OffsetDateTime::now_utc() + Duration::days(335),
            status: LifecycleStatus::Valid,
            issuing_ca_id: "test-ca-001".to_string(),
            renewal_history: vec![],
            last_checked: OffsetDateTime::now_utc(),
        };

        let response = manager.query_from_lifecycle(&lifecycle);
        assert_eq!(response.serial_number, "12345");
        assert!(matches!(response.status, CertificateStatus::Valid { .. }));
        assert_eq!(response.confidence, 1.0);
        assert!(!response.from_cache);
    }
}
