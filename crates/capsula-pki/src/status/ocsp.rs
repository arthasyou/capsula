//! OCSP (在线证书状态协议) 实现
//!
//! 提供OCSP请求和响应处理功能

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::RevocationReason as StatusRevocationReason;
use crate::error::{PkiError, Result as PkiResult};

/// OCSP请求状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OCSPStatus {
    /// 证书有效
    Good,
    /// 证书已吊销
    Revoked {
        /// 吊销原因
        reason: StatusRevocationReason,
        /// 吊销时间
        revocation_time: OffsetDateTime,
    },
    /// 未知状态
    Unknown,
}

/// OCSP请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSPRequest {
    /// 请求的证书序列号
    pub serial_number: String,
    /// 颁发者信息
    pub issuer_name_hash: Vec<u8>,
    /// 颁发者密钥哈希
    pub issuer_key_hash: Vec<u8>,
    /// 请求时间
    pub request_time: OffsetDateTime,
    /// 请求随机数
    pub nonce: Option<Vec<u8>>,
}

/// OCSP响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSPResponse {
    /// 证书序列号
    pub serial_number: String,
    /// 证书状态
    pub status: OCSPStatus,
    /// 响应时间
    pub response_time: OffsetDateTime,
    /// 下次更新时间
    pub next_update: Option<OffsetDateTime>,
    /// 响应器URL
    pub responder_url: String,
    /// 响应签名（简化表示）
    pub signature: Option<Vec<u8>>,
    /// 响应随机数
    pub nonce: Option<Vec<u8>>,
}

/// OCSP响应器配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSPResponderConfig {
    /// 响应器URL
    pub responder_url: String,
    /// 签名密钥ID
    pub signing_key_id: String,
    /// 响应有效期（秒）
    pub response_validity_seconds: u64,
    /// 是否启用缓存
    pub enable_caching: bool,
    /// 缓存TTL（秒）
    pub cache_ttl_seconds: u64,
    /// 最大请求大小
    pub max_request_size_bytes: usize,
}

impl Default for OCSPResponderConfig {
    fn default() -> Self {
        Self {
            responder_url: "http://ocsp.example.com".to_string(),
            signing_key_id: "default".to_string(),
            response_validity_seconds: 3600, // 1小时
            enable_caching: true,
            cache_ttl_seconds: 600,       // 10分钟
            max_request_size_bytes: 1024, // 1KB
        }
    }
}

/// OCSP响应器
pub struct OCSPResponder {
    /// 配置
    config: OCSPResponderConfig,
    /// 证书状态数据库（模拟）
    certificate_database: HashMap<String, OCSPStatus>,
    /// 响应缓存
    response_cache: HashMap<String, (OCSPResponse, OffsetDateTime)>,
    /// 统计信息
    stats: OCSPStats,
}

/// OCSP统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSPStats {
    /// 总请求数
    pub total_requests: u64,
    /// 成功响应数
    pub successful_responses: u64,
    /// 失败响应数
    pub failed_responses: u64,
    /// 缓存命中数
    pub cache_hits: u64,
    /// 平均响应时间（毫秒）
    pub average_response_time_ms: f64,
}

impl Default for OCSPStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_responses: 0,
            failed_responses: 0,
            cache_hits: 0,
            average_response_time_ms: 0.0,
        }
    }
}

impl OCSPResponder {
    /// 创建新的OCSP响应器
    pub fn new(config: OCSPResponderConfig) -> Self {
        Self {
            config,
            certificate_database: HashMap::new(),
            response_cache: HashMap::new(),
            stats: OCSPStats::default(),
        }
    }

    /// 添加证书到数据库
    pub fn add_certificate(&mut self, serial_number: String, status: OCSPStatus) {
        self.certificate_database.insert(serial_number, status);
    }

    /// 批量添加证书状态
    pub fn add_certificates(&mut self, certificates: HashMap<String, OCSPStatus>) {
        for (serial, status) in certificates {
            self.certificate_database.insert(serial, status);
        }
    }

    /// 更新证书状态
    pub fn update_certificate_status(
        &mut self,
        serial_number: &str,
        status: OCSPStatus,
    ) -> PkiResult<()> {
        if !self.certificate_database.contains_key(serial_number) {
            return Err(PkiError::CertError(format!(
                "Certificate {} not found in OCSP database",
                serial_number
            )));
        }

        self.certificate_database
            .insert(serial_number.to_string(), status);

        // 清除相关缓存
        self.response_cache.remove(serial_number);

        Ok(())
    }

    /// 处理OCSP请求（同步版本）
    pub fn query_status(&mut self, serial_number: &str) -> PkiResult<OCSPResponse> {
        let start_time = std::time::Instant::now();
        self.stats.total_requests += 1;

        // 1. 检查缓存
        if self.config.enable_caching {
            if let Some((cached_response, cached_at)) = self.response_cache.get(serial_number) {
                let cache_age = (OffsetDateTime::now_utc() - *cached_at).whole_seconds() as u64;
                if cache_age < self.config.cache_ttl_seconds {
                    self.stats.cache_hits += 1;
                    let mut response = cached_response.clone();
                    response.response_time = OffsetDateTime::now_utc();
                    return Ok(response);
                }
            }
        }

        // 2. 查询证书状态
        let status = self
            .certificate_database
            .get(serial_number)
            .cloned()
            .unwrap_or(OCSPStatus::Unknown);

        // 3. 创建响应
        let response = OCSPResponse {
            serial_number: serial_number.to_string(),
            status,
            response_time: OffsetDateTime::now_utc(),
            next_update: Some(
                OffsetDateTime::now_utc()
                    + time::Duration::seconds(self.config.response_validity_seconds as i64),
            ),
            responder_url: self.config.responder_url.clone(),
            signature: Some(self.generate_signature(serial_number)?),
            nonce: None,
        };

        // 4. 缓存响应
        if self.config.enable_caching {
            self.response_cache.insert(
                serial_number.to_string(),
                (response.clone(), OffsetDateTime::now_utc()),
            );
        }

        // 5. 更新统计
        self.stats.successful_responses += 1;
        let response_time = start_time.elapsed().as_millis() as f64;
        self.update_average_response_time(response_time);

        Ok(response)
    }

    /// 批量查询证书状态
    pub fn batch_query_status(
        &mut self,
        serial_numbers: &[String],
    ) -> Vec<PkiResult<OCSPResponse>> {
        serial_numbers
            .iter()
            .map(|serial| self.query_status(serial))
            .collect()
    }

    /// 处理OCSP请求对象
    pub fn handle_request(&mut self, request: &OCSPRequest) -> PkiResult<OCSPResponse> {
        // 基本验证
        if request.serial_number.is_empty() {
            return Err(PkiError::ValidationError(
                "Empty serial number in OCSP request".to_string(),
            ));
        }

        // 查询状态
        let mut response = self.query_status(&request.serial_number)?;

        // 设置nonce
        response.nonce = request.nonce.clone();

        Ok(response)
    }

    /// 吊销证书
    pub fn revoke_certificate(
        &mut self,
        serial_number: String,
        reason: StatusRevocationReason,
        revocation_time: OffsetDateTime,
    ) -> PkiResult<()> {
        let status = OCSPStatus::Revoked {
            reason,
            revocation_time,
        };

        self.update_certificate_status(&serial_number, status)?;
        Ok(())
    }

    /// 恢复证书（从CertificateHold状态）
    pub fn restore_certificate(&mut self, serial_number: String) -> PkiResult<()> {
        let status = OCSPStatus::Good;
        self.update_certificate_status(&serial_number, status)?;
        Ok(())
    }

    /// 清理过期缓存
    pub fn cleanup_expired_cache(&mut self) {
        let now = OffsetDateTime::now_utc();
        self.response_cache.retain(|_, (_, cached_at)| {
            let cache_age = (now - *cached_at).whole_seconds() as u64;
            cache_age < self.config.cache_ttl_seconds
        });
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> &OCSPStats {
        &self.stats
    }

    /// 获取配置
    pub fn get_config(&self) -> &OCSPResponderConfig {
        &self.config
    }

    /// 更新配置
    pub fn update_config(&mut self, config: OCSPResponderConfig) {
        self.config = config;
    }

    /// 获取数据库中的证书数量
    pub fn certificate_count(&self) -> usize {
        self.certificate_database.len()
    }

    /// 获取缓存大小
    pub fn cache_size(&self) -> usize {
        self.response_cache.len()
    }

    /// 清空数据库
    pub fn clear_database(&mut self) {
        self.certificate_database.clear();
        self.response_cache.clear();
    }

    /// 导出证书状态数据
    pub fn export_database(&self) -> PkiResult<String> {
        serde_json::to_string_pretty(&self.certificate_database)
            .map_err(PkiError::SerializationError)
    }

    /// 导入证书状态数据
    pub fn import_database(&mut self, json_data: &str) -> PkiResult<()> {
        let database: HashMap<String, OCSPStatus> =
            serde_json::from_str(json_data).map_err(PkiError::SerializationError)?;

        self.certificate_database = database;
        // 清除缓存，因为数据已更新
        self.response_cache.clear();

        Ok(())
    }

    // 私有辅助方法

    /// 生成响应签名（简化实现）
    fn generate_signature(&self, _serial_number: &str) -> PkiResult<Vec<u8>> {
        // TODO: 实现实际的数字签名
        // 这里应该使用CA的私钥对响应进行签名
        Ok(vec![0u8; 64]) // 临时64字节签名
    }

    /// 更新平均响应时间
    fn update_average_response_time(&mut self, new_response_time: f64) {
        let total_successful = self.stats.successful_responses;
        if total_successful == 1 {
            self.stats.average_response_time_ms = new_response_time;
        } else {
            // 计算移动平均值
            self.stats.average_response_time_ms = (self.stats.average_response_time_ms
                * (total_successful - 1) as f64
                + new_response_time)
                / total_successful as f64;
        }
    }
}

impl Default for OCSPResponder {
    fn default() -> Self {
        Self::new(OCSPResponderConfig::default())
    }
}

/// OCSP客户端（用于查询远程OCSP服务器）
pub struct OCSPClient {
    /// 客户端配置
    config: OCSPClientConfig,
    /// 请求统计
    stats: OCSPClientStats,
}

/// OCSP客户端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSPClientConfig {
    /// 默认超时时间（秒）
    pub default_timeout_seconds: u64,
    /// 最大重试次数
    pub max_retries: u32,
    /// 重试间隔（秒）
    pub retry_interval_seconds: u64,
    /// 是否验证响应签名
    pub verify_signature: bool,
}

impl Default for OCSPClientConfig {
    fn default() -> Self {
        Self {
            default_timeout_seconds: 10,
            max_retries: 3,
            retry_interval_seconds: 1,
            verify_signature: true,
        }
    }
}

/// OCSP客户端统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OCSPClientStats {
    /// 总请求数
    pub total_requests: u64,
    /// 成功请求数
    pub successful_requests: u64,
    /// 失败请求数
    pub failed_requests: u64,
    /// 超时请求数
    pub timeout_requests: u64,
    /// 平均响应时间（毫秒）
    pub average_response_time_ms: f64,
}

impl Default for OCSPClientStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            timeout_requests: 0,
            average_response_time_ms: 0.0,
        }
    }
}

impl OCSPClient {
    /// 创建新的OCSP客户端
    pub fn new(config: OCSPClientConfig) -> Self {
        Self {
            config,
            stats: OCSPClientStats::default(),
        }
    }

    /// 查询远程OCSP服务器（模拟实现）
    pub fn query_remote_ocsp(
        &mut self,
        responder_url: &str,
        serial_number: &str,
    ) -> PkiResult<OCSPResponse> {
        let start_time = std::time::Instant::now();
        self.stats.total_requests += 1;

        // TODO: 实现实际的HTTP请求到OCSP服务器
        // 这里是一个模拟实现

        // 模拟网络延迟
        std::thread::sleep(std::time::Duration::from_millis(100));

        // 模拟响应
        let response = OCSPResponse {
            serial_number: serial_number.to_string(),
            status: OCSPStatus::Good, // 模拟返回Good状态
            response_time: OffsetDateTime::now_utc(),
            next_update: Some(OffsetDateTime::now_utc() + time::Duration::hours(1)),
            responder_url: responder_url.to_string(),
            signature: Some(vec![0u8; 64]),
            nonce: None,
        };

        // 更新统计
        self.stats.successful_requests += 1;
        let response_time = start_time.elapsed().as_millis() as f64;
        self.update_average_response_time(response_time);

        Ok(response)
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> &OCSPClientStats {
        &self.stats
    }

    /// 获取客户端配置
    pub fn get_config(&self) -> &OCSPClientConfig {
        &self.config
    }

    // 私有辅助方法
    fn update_average_response_time(&mut self, new_response_time: f64) {
        let total_successful = self.stats.successful_requests;
        if total_successful == 1 {
            self.stats.average_response_time_ms = new_response_time;
        } else {
            self.stats.average_response_time_ms = (self.stats.average_response_time_ms
                * (total_successful - 1) as f64
                + new_response_time)
                / total_successful as f64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_responder_creation() {
        let responder = OCSPResponder::default();
        assert_eq!(responder.certificate_count(), 0);
        assert_eq!(responder.cache_size(), 0);
    }

    #[test]
    fn test_add_certificate() {
        let mut responder = OCSPResponder::default();
        responder.add_certificate("12345".to_string(), OCSPStatus::Good);

        assert_eq!(responder.certificate_count(), 1);
    }

    #[test]
    fn test_query_status() {
        let mut responder = OCSPResponder::default();
        responder.add_certificate("12345".to_string(), OCSPStatus::Good);

        let response = responder.query_status("12345").unwrap();
        assert_eq!(response.serial_number, "12345");
        assert!(matches!(response.status, OCSPStatus::Good));
    }

    #[test]
    fn test_query_unknown_certificate() {
        let mut responder = OCSPResponder::default();
        let response = responder.query_status("unknown").unwrap();
        assert!(matches!(response.status, OCSPStatus::Unknown));
    }

    #[test]
    fn test_revoke_certificate() {
        let mut responder = OCSPResponder::default();
        responder.add_certificate("12345".to_string(), OCSPStatus::Good);

        responder
            .revoke_certificate(
                "12345".to_string(),
                StatusRevocationReason::KeyCompromise,
                OffsetDateTime::now_utc(),
            )
            .unwrap();

        let response = responder.query_status("12345").unwrap();
        assert!(matches!(response.status, OCSPStatus::Revoked { .. }));
    }

    #[test]
    fn test_caching() {
        let config = OCSPResponderConfig {
            enable_caching: true,
            cache_ttl_seconds: 60,
            ..Default::default()
        };
        let mut responder = OCSPResponder::new(config);
        responder.add_certificate("12345".to_string(), OCSPStatus::Good);

        // 第一次查询
        let _response1 = responder.query_status("12345").unwrap();
        assert_eq!(responder.get_stats().cache_hits, 0);

        // 第二次查询（应该命中缓存）
        let _response2 = responder.query_status("12345").unwrap();
        assert_eq!(responder.get_stats().cache_hits, 1);
    }

    #[test]
    fn test_batch_query() {
        let mut responder = OCSPResponder::default();
        responder.add_certificate("12345".to_string(), OCSPStatus::Good);
        responder.add_certificate(
            "67890".to_string(),
            OCSPStatus::Revoked {
                reason: StatusRevocationReason::KeyCompromise,
                revocation_time: OffsetDateTime::now_utc(),
            },
        );

        let serials = vec![
            "12345".to_string(),
            "67890".to_string(),
            "unknown".to_string(),
        ];
        let results = responder.batch_query_status(&serials);

        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(results[2].is_ok());
    }

    #[test]
    fn test_export_import_database() {
        let mut responder = OCSPResponder::default();
        responder.add_certificate("12345".to_string(), OCSPStatus::Good);
        responder.add_certificate(
            "67890".to_string(),
            OCSPStatus::Revoked {
                reason: StatusRevocationReason::KeyCompromise,
                revocation_time: OffsetDateTime::now_utc(),
            },
        );

        // 导出
        let exported = responder.export_database().unwrap();
        assert!(!exported.is_empty());

        // 清空并导入
        responder.clear_database();
        assert_eq!(responder.certificate_count(), 0);

        responder.import_database(&exported).unwrap();
        assert_eq!(responder.certificate_count(), 2);
    }

    #[test]
    fn test_ocsp_client_creation() {
        let client = OCSPClient::new(OCSPClientConfig::default());
        assert_eq!(client.get_stats().total_requests, 0);
    }

    #[test]
    fn test_ocsp_client_config_access() {
        let config = OCSPClientConfig::default();
        let client = OCSPClient::new(config.clone());

        let client_config = client.get_config();
        assert_eq!(
            client_config.default_timeout_seconds,
            config.default_timeout_seconds
        );
        assert_eq!(client_config.max_retries, config.max_retries);
        assert_eq!(
            client_config.retry_interval_seconds,
            config.retry_interval_seconds
        );
        assert_eq!(client_config.verify_signature, config.verify_signature);
    }
}
