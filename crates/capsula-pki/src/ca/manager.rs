//! CA管理器
//!
//! 提供CA生命周期管理和证书签发服务

use std::collections::HashMap;

use capsula_key::Curve25519;
use serde::{Deserialize, Serialize};

use crate::{
    error::{PkiError, Result as PkiResult},
    ra::{cert::CertificateSubject, Csr, Processor, ProcessingResult},
};

use super::{authority::Authority, config::Config};

/// CA管理器
/// 
/// 负责管理多个CA实例和证书签发流程
pub struct Manager {
    /// CA实例存储 (CA ID -> Authority)
    cas: HashMap<String, Authority>,
    /// 默认根CA ID
    default_root_ca: Option<String>,
    /// RA处理器
    ra_processor: Option<Processor>,
}

/// CA信息摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CAInfo {
    /// CA标识
    pub id: String,
    /// CA名称
    pub name: String,
    /// 是否为根CA
    pub is_root: bool,
    /// 证书链级别
    pub chain_level: u8,
    /// 已签发证书数量
    pub issued_count: u64,
    /// 剩余有效天数
    pub days_until_expiry: i64,
    /// 是否有效
    pub is_valid: bool,
}

/// 证书签发请求
pub struct IssuanceRequest {
    /// 证书主体信息
    pub subject: CertificateSubject,
    /// 公钥 (暂时用String占位)
    pub public_key_info: String,
    /// 有效期天数 (可选，使用CA默认值)
    pub validity_days: Option<u32>,
    /// 是否为CA证书
    pub is_ca: bool,
    /// 使用的CA ID
    pub ca_id: String,
}

/// 证书签发结果
#[derive(Debug, Clone)]
pub struct IssuanceResult {
    /// 签发的证书
    pub certificate: crate::ra::cert::X509Certificate,
    /// 签发CA的信息
    pub issuer_ca: CAInfo,
    /// 处理结果 (如果使用了RA处理器)
    pub processing_result: Option<ProcessingResult>,
}

impl Manager {
    /// 创建新的CA管理器
    pub fn new() -> Self {
        Self {
            cas: HashMap::new(),
            default_root_ca: None,
            ra_processor: None,
        }
    }

    /// 设置RA处理器
    pub fn with_ra_processor(mut self, processor: Processor) -> Self {
        self.ra_processor = Some(processor);
        self
    }

    /// 创建根CA
    pub fn create_root_ca(&mut self, ca_id: String, config: Config) -> PkiResult<String> {
        // 验证配置
        config.validate()
            .map_err(|e| PkiError::CAError(format!("Invalid CA config: {e}")))?;

        // 检查ID是否已存在
        if self.cas.contains_key(&ca_id) {
            return Err(PkiError::CAError(format!("CA with ID '{}' already exists", ca_id)));
        }

        // 创建根CA
        let authority = Authority::new_root(config)?;

        // 存储CA
        self.cas.insert(ca_id.clone(), authority);

        // 如果这是第一个根CA，设为默认
        if self.default_root_ca.is_none() {
            self.default_root_ca = Some(ca_id.clone());
        }

        Ok(ca_id)
    }

    /// 创建中间CA
    pub fn create_intermediate_ca(
        &mut self,
        parent_ca_id: &str,
        intermediate_ca_id: String,
        config: Config,
    ) -> PkiResult<String> {
        // 验证配置
        config.validate()
            .map_err(|e| PkiError::CAError(format!("Invalid CA config: {e}")))?;

        // 检查父CA是否存在
        if !self.cas.contains_key(parent_ca_id) {
            return Err(PkiError::CAError(format!(
                "Parent CA '{}' not found",
                parent_ca_id
            )));
        }

        // 检查新CA ID是否已存在
        if self.cas.contains_key(&intermediate_ca_id) {
            return Err(PkiError::CAError(format!(
                "CA with ID '{}' already exists",
                intermediate_ca_id
            )));
        }

        // 创建中间CA
        let intermediate_ca = {
            let parent_ca = self.cas.get_mut(parent_ca_id).unwrap();
            parent_ca.create_intermediate(config)?
        };

        // 存储中间CA
        self.cas.insert(intermediate_ca_id.clone(), intermediate_ca);

        Ok(intermediate_ca_id)
    }

    /// 获取CA信息
    pub fn get_ca_info(&self, ca_id: &str) -> PkiResult<CAInfo> {
        let ca = self.cas.get(ca_id)
            .ok_or_else(|| PkiError::CAError(format!("CA '{}' not found", ca_id)))?;

        Ok(CAInfo {
            id: ca_id.to_string(),
            name: ca.config().name.clone(),
            is_root: ca.is_root(),
            chain_level: ca.chain_level(),
            issued_count: ca.issued_count(),
            days_until_expiry: ca.days_until_expiry().unwrap_or(0),
            is_valid: ca.is_valid(),
        })
    }

    /// 列出所有CA
    pub fn list_cas(&self) -> Vec<CAInfo> {
        self.cas
            .iter()
            .map(|(id, ca)| CAInfo {
                id: id.clone(),
                name: ca.config().name.clone(),
                is_root: ca.is_root(),
                chain_level: ca.chain_level(),
                issued_count: ca.issued_count(),
                days_until_expiry: ca.days_until_expiry().unwrap_or(0),
                is_valid: ca.is_valid(),
            })
            .collect()
    }

    /// 签发证书 (直接签发，不经过RA)
    pub fn issue_certificate_direct(&mut self, request: IssuanceRequest) -> PkiResult<IssuanceResult> {
        let ca = self.cas.get_mut(&request.ca_id)
            .ok_or_else(|| PkiError::CAError(format!("CA '{}' not found", request.ca_id)))?;

        // TODO: Parse public_key_info string to create Curve25519 key
        // For now, create a temporary key - this needs to be properly implemented
        let temp_key = Curve25519::generate()
            .map_err(|e| PkiError::CAError(format!("Failed to parse public key: {e}")))?;
        
        let certificate = ca.issue_certificate(
            request.subject,
            &temp_key,
            request.validity_days,
            request.is_ca,
        )?;

        let issuer_ca = self.get_ca_info(&request.ca_id)?;

        Ok(IssuanceResult {
            certificate,
            issuer_ca,
            processing_result: None,
        })
    }

    /// 通过RA流程签发证书
    pub fn issue_certificate_via_ra(
        &mut self,
        csr: Csr,
        context: crate::ra::Context,
        ca_id: Option<String>,
    ) -> PkiResult<IssuanceResult> {
        let processor = self.ra_processor.as_ref()
            .ok_or_else(|| PkiError::CAError("RA processor not configured".to_string()))?;

        // RA处理
        let processing_result = processor.process_request(&csr, &context)?;

        if !processing_result.can_issue_certificate {
            return Err(PkiError::CAError(format!(
                "Certificate issuance denied: {}",
                processing_result.summary
            )));
        }

        // 确定使用的CA
        let ca_id = ca_id.or_else(|| self.default_root_ca.clone())
            .ok_or_else(|| PkiError::CAError("No CA specified and no default CA available".to_string()))?;

        // 签发证书
        let ca = self.cas.get_mut(&ca_id)
            .ok_or_else(|| PkiError::CAError(format!("CA '{}' not found", ca_id)))?;

        // 从CSR获取主体信息
        let csr_subject = csr.subject()
            .map_err(|e| PkiError::CAError(format!("Failed to get CSR subject: {e}")))?;
        
        // Convert CsrSubject to CertificateSubject
        let cert_subject = crate::ra::cert::CertificateSubject {
            common_name: csr_subject.common_name,
            organization: csr_subject.organization,
            organizational_unit: csr_subject.organizational_unit,
            country: csr_subject.country,
            state: csr_subject.state,
            locality: csr_subject.locality,
        };

        // TODO: Convert CSR public key to Curve25519
        // For now, create a temporary key - this needs to be properly implemented
        let temp_key = Curve25519::generate()
            .map_err(|e| PkiError::CAError(format!("Failed to parse CSR public key: {e}")))?;

        let certificate = ca.issue_certificate(
            cert_subject,
            &temp_key,
            None, // 使用CA默认有效期
            false, // 通过RA签发的通常不是CA证书
        )?;

        let issuer_ca = self.get_ca_info(&ca_id)?;

        Ok(IssuanceResult {
            certificate,
            issuer_ca,
            processing_result: Some(processing_result),
        })
    }

    /// 获取默认根CA
    pub fn default_root_ca(&self) -> Option<&str> {
        self.default_root_ca.as_deref()
    }

    /// 设置默认根CA
    pub fn set_default_root_ca(&mut self, ca_id: String) -> PkiResult<()> {
        if !self.cas.contains_key(&ca_id) {
            return Err(PkiError::CAError(format!("CA '{}' not found", ca_id)));
        }

        let ca = &self.cas[&ca_id];
        if !ca.is_root() {
            return Err(PkiError::CAError(format!("CA '{}' is not a root CA", ca_id)));
        }

        self.default_root_ca = Some(ca_id);
        Ok(())
    }

    /// 移除CA
    pub fn remove_ca(&mut self, ca_id: &str) -> PkiResult<()> {
        if !self.cas.contains_key(ca_id) {
            return Err(PkiError::CAError(format!("CA '{}' not found", ca_id)));
        }

        // 如果是默认CA，清除默认设置
        if self.default_root_ca.as_deref() == Some(ca_id) {
            self.default_root_ca = None;
        }

        self.cas.remove(ca_id);
        Ok(())
    }

    /// 获取CA证书
    pub fn get_ca_certificate(&self, ca_id: &str) -> PkiResult<&crate::ra::cert::X509Certificate> {
        let ca = self.cas.get(ca_id)
            .ok_or_else(|| PkiError::CAError(format!("CA '{}' not found", ca_id)))?;
        Ok(ca.certificate())
    }

    /// 批量签发证书
    pub fn batch_issue_certificates(
        &mut self,
        requests: Vec<IssuanceRequest>,
    ) -> Vec<PkiResult<IssuanceResult>> {
        requests
            .into_iter()
            .map(|request| self.issue_certificate_direct(request))
            .collect()
    }

    /// 获取管理器统计信息
    pub fn get_statistics(&self) -> ManagerStatistics {
        let total_cas = self.cas.len();
        let root_cas = self.cas.values().filter(|ca| ca.is_root()).count();
        let intermediate_cas = total_cas - root_cas;
        let total_issued = self.cas.values().map(|ca| ca.issued_count()).sum();
        
        let valid_cas = self.cas.values().filter(|ca| ca.is_valid()).count();

        ManagerStatistics {
            total_cas,
            root_cas,
            intermediate_cas,
            total_certificates_issued: total_issued,
            valid_cas,
            has_default_root_ca: self.default_root_ca.is_some(),
            has_ra_processor: self.ra_processor.is_some(),
        }
    }
}

impl Default for Manager {
    fn default() -> Self {
        Self::new()
    }
}

/// 管理器统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerStatistics {
    /// 总CA数量
    pub total_cas: usize,
    /// 根CA数量
    pub root_cas: usize,
    /// 中间CA数量
    pub intermediate_cas: usize,
    /// 总签发证书数
    pub total_certificates_issued: u64,
    /// 有效CA数量
    pub valid_cas: usize,
    /// 是否有默认根CA
    pub has_default_root_ca: bool,
    /// 是否配置了RA处理器
    pub has_ra_processor: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_manager_creation() {
        let manager = Manager::new();
        assert_eq!(manager.cas.len(), 0);
        assert!(manager.default_root_ca.is_none());
    }

    #[test]
    fn test_create_root_ca() {
        let mut manager = Manager::new();
        let config = Config::default();
        
        let result = manager.create_root_ca("root-ca-1".to_string(), config);
        assert!(result.is_ok());
        assert_eq!(manager.cas.len(), 1);
        assert_eq!(manager.default_root_ca(), Some("root-ca-1"));
    }

    #[test]
    fn test_create_intermediate_ca() {
        let mut manager = Manager::new();
        let root_config = Config::root_ca("Root CA", "Test Org");
        
        // 创建根CA
        manager.create_root_ca("root-ca".to_string(), root_config).unwrap();
        
        // 创建中间CA
        let intermediate_config = Config::intermediate_ca("Intermediate CA", "Test Org");
        let result = manager.create_intermediate_ca(
            "root-ca",
            "intermediate-ca".to_string(),
            intermediate_config,
        );
        
        assert!(result.is_ok());
        assert_eq!(manager.cas.len(), 2);
    }

    #[test]
    fn test_list_cas() {
        let mut manager = Manager::new();
        let config = Config::default();
        
        manager.create_root_ca("root-ca-1".to_string(), config.clone()).unwrap();
        manager.create_root_ca("root-ca-2".to_string(), config).unwrap();
        
        let cas = manager.list_cas();
        assert_eq!(cas.len(), 2);
        assert!(cas.iter().any(|ca| ca.id == "root-ca-1"));
        assert!(cas.iter().any(|ca| ca.id == "root-ca-2"));
    }

    #[test]
    fn test_ca_statistics() {
        let mut manager = Manager::new();
        let root_config = Config::root_ca("Root CA", "Test Org");
        let intermediate_config = Config::intermediate_ca("Intermediate CA", "Test Org");
        
        // 创建根CA
        manager.create_root_ca("root-ca".to_string(), root_config).unwrap();
        
        // 创建中间CA
        manager.create_intermediate_ca(
            "root-ca",
            "intermediate-ca".to_string(),
            intermediate_config,
        ).unwrap();
        
        let stats = manager.get_statistics();
        assert_eq!(stats.total_cas, 2);
        assert_eq!(stats.root_cas, 1);
        assert_eq!(stats.intermediate_cas, 1);
        assert!(stats.has_default_root_ca);
        assert!(!stats.has_ra_processor);
    }
}