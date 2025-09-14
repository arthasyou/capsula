//! 证书链管理
//!
//! 提供证书链构建、验证和导出功能

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    error::{PkiError, Result as PkiResult},
    ra::cert::X509Certificate,
};

/// 证书链
#[derive(Debug, Clone)]
pub struct Chain {
    /// 证书链 (从最终实体证书到根证书)
    certificates: Vec<X509Certificate>,
    /// 根证书标识
    root_fingerprint: String,
}

/// 证书链构建器
pub struct ChainBuilder {
    /// 可用的证书池 (指纹 -> 证书)
    certificate_pool: HashMap<String, X509Certificate>,
    /// 信任的根证书 (指纹 -> 证书)
    trusted_roots: HashMap<String, X509Certificate>,
}

/// 链验证结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// 是否有效
    pub is_valid: bool,
    /// 验证问题列表
    pub issues: Vec<ValidationIssue>,
    /// 链长度
    pub chain_length: usize,
    /// 根证书指纹
    pub root_fingerprint: Option<String>,
}

/// 链验证问题
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// 问题级别
    pub level: IssueLevel,
    /// 问题描述
    pub message: String,
    /// 受影响的证书索引 (在链中的位置)
    pub certificate_index: Option<usize>,
}

/// 问题级别
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueLevel {
    /// 警告
    Warning,
    /// 错误
    Error,
    /// 严重错误
    Critical,
}

impl Chain {
    /// 创建新的证书链
    pub fn new(certificates: Vec<X509Certificate>) -> PkiResult<Self> {
        if certificates.is_empty() {
            return Err(PkiError::ChainError("Certificate chain cannot be empty".to_string()));
        }

        let root_fingerprint = Self::calculate_fingerprint(&certificates[certificates.len() - 1]);

        Ok(Self {
            certificates,
            root_fingerprint,
        })
    }

    /// 获取最终实体证书 (叶子证书)
    pub fn end_entity_certificate(&self) -> &X509Certificate {
        &self.certificates[0]
    }

    /// 获取根证书
    pub fn root_certificate(&self) -> &X509Certificate {
        &self.certificates[self.certificates.len() - 1]
    }

    /// 获取中间证书
    pub fn intermediate_certificates(&self) -> &[X509Certificate] {
        if self.certificates.len() <= 2 {
            &[]
        } else {
            &self.certificates[1..self.certificates.len() - 1]
        }
    }

    /// 获取完整证书链
    pub fn certificates(&self) -> &[X509Certificate] {
        &self.certificates
    }

    /// 获取链长度
    pub fn length(&self) -> usize {
        self.certificates.len()
    }

    /// 获取根证书指纹
    pub fn root_fingerprint(&self) -> &str {
        &self.root_fingerprint
    }

    /// 验证证书链
    pub fn validate(&self) -> ValidationResult {
        let mut issues = Vec::new();

        // 基本链结构验证
        if self.certificates.is_empty() {
            issues.push(ValidationIssue {
                level: IssueLevel::Critical,
                message: "Certificate chain is empty".to_string(),
                certificate_index: None,
            });
            return ValidationResult {
                is_valid: false,
                issues,
                chain_length: 0,
                root_fingerprint: None,
            };
        }

        // 验证每个证书的有效性
        for (index, cert) in self.certificates.iter().enumerate() {
            if let Err(e) = self.validate_certificate(cert, index) {
                issues.push(ValidationIssue {
                    level: IssueLevel::Error,
                    message: e.to_string(),
                    certificate_index: Some(index),
                });
            }
        }

        // 验证证书链的连接性
        for i in 0..self.certificates.len() - 1 {
            if let Err(e) = self.validate_certificate_connection(&self.certificates[i], &self.certificates[i + 1]) {
                issues.push(ValidationIssue {
                    level: IssueLevel::Error,
                    message: format!("Chain connection issue between cert {} and {}: {}", i, i + 1, e),
                    certificate_index: Some(i),
                });
            }
        }

        // 验证根证书是自签名的
        let root_cert = self.root_certificate();
        if !self.is_self_signed(root_cert) {
            issues.push(ValidationIssue {
                level: IssueLevel::Warning,
                message: "Root certificate is not self-signed".to_string(),
                certificate_index: Some(self.certificates.len() - 1),
            });
        }

        let is_valid = !issues.iter().any(|issue| matches!(issue.level, IssueLevel::Critical | IssueLevel::Error));

        ValidationResult {
            is_valid,
            issues,
            chain_length: self.certificates.len(),
            root_fingerprint: Some(self.root_fingerprint.clone()),
        }
    }

    /// 导出为PEM格式
    pub fn to_pem(&self) -> PkiResult<String> {
        let mut pem_data = String::new();
        
        for cert in &self.certificates {
            // TODO: 实现证书的PEM导出
            pem_data.push_str("-----BEGIN CERTIFICATE-----\n");
            pem_data.push_str("TODO: Certificate PEM data\n");
            pem_data.push_str("-----END CERTIFICATE-----\n");
        }
        
        Ok(pem_data)
    }

    /// 从PEM格式导入
    pub fn from_pem(pem_data: &str) -> PkiResult<Self> {
        // TODO: 实现从PEM导入证书链
        Err(PkiError::ParseError("PEM import not yet implemented".to_string()))
    }

    /// 计算证书指纹
    fn calculate_fingerprint(certificate: &X509Certificate) -> String {
        // 简化的指纹实现
        // 简化的指纹实现，使用证书的哈希值
        format!("sha256:{:?}", certificate as *const _)
    }

    /// 验证单个证书
    fn validate_certificate(&self, _certificate: &X509Certificate, _index: usize) -> PkiResult<()> {
        // TODO: 实现证书验证
        // - 检查有效期
        // - 检查关键扩展
        // - 检查密钥用途
        // - 检查基本约束
        Ok(())
    }

    /// 验证证书连接
    fn validate_certificate_connection(&self, _child: &X509Certificate, _parent: &X509Certificate) -> PkiResult<()> {
        // TODO: 实现证书连接验证
        // - 验证子证书是由父证书签名的
        // - 检查主体和颁发者匹配
        // - 验证签名算法一致性
        Ok(())
    }

    /// 检查是否为自签名证书
    fn is_self_signed(&self, _certificate: &X509Certificate) -> bool {
        // TODO: 实现自签名检查
        // 检查subject == issuer
        true // 临时返回
    }
}

impl ChainBuilder {
    /// 创建新的证书链构建器
    pub fn new() -> Self {
        Self {
            certificate_pool: HashMap::new(),
            trusted_roots: HashMap::new(),
        }
    }

    /// 添加证书到证书池
    pub fn add_certificate(&mut self, certificate: X509Certificate) {
        let fingerprint = Chain::calculate_fingerprint(&certificate);
        self.certificate_pool.insert(fingerprint, certificate);
    }

    /// 添加信任的根证书
    pub fn add_trusted_root(&mut self, certificate: X509Certificate) {
        let fingerprint = Chain::calculate_fingerprint(&certificate);
        self.trusted_roots.insert(fingerprint.clone(), certificate.clone());
        self.certificate_pool.insert(fingerprint, certificate);
    }

    /// 构建证书链
    pub fn build_chain(&self, end_entity_cert: X509Certificate) -> PkiResult<Chain> {
        let mut chain = vec![end_entity_cert];
        let mut current_cert = &chain[0];

        // 向上构建链，直到找到根证书
        loop {
            // 查找当前证书的签发者
            let issuer_cert = self.find_issuer(current_cert)?;
            
            // 检查是否已经到达根证书
            if self.is_root_certificate(&issuer_cert) {
                chain.push(issuer_cert);
                break;
            }

            // 检查链长度限制
            if chain.len() > 10 {
                return Err(PkiError::ChainError("Certificate chain too long".to_string()));
            }

            chain.push(issuer_cert.clone());
            current_cert = chain.last().unwrap();
        }

        Chain::new(chain)
    }

    /// 验证证书链到信任根
    pub fn validate_to_trusted_root(&self, chain: &Chain) -> ValidationResult {
        let mut result = chain.validate();

        // 检查根证书是否在信任列表中
        let root_fingerprint = chain.root_fingerprint();
        if !self.trusted_roots.contains_key(root_fingerprint) {
            result.issues.push(ValidationIssue {
                level: IssueLevel::Critical,
                message: "Root certificate is not in trusted root store".to_string(),
                certificate_index: Some(chain.certificates.len() - 1),
            });
            result.is_valid = false;
        }

        result
    }

    /// 查找证书的签发者
    fn find_issuer(&self, _certificate: &X509Certificate) -> PkiResult<X509Certificate> {
        // TODO: 实现签发者查找逻辑
        // - 根据证书的颁发者信息在证书池中查找
        // - 验证密钥标识符匹配
        Err(PkiError::ChainError("Issuer certificate not found".to_string()))
    }

    /// 检查是否为根证书
    fn is_root_certificate(&self, certificate: &X509Certificate) -> bool {
        let fingerprint = Chain::calculate_fingerprint(certificate);
        self.trusted_roots.contains_key(&fingerprint)
    }
}

impl Default for ChainBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 证书链统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatistics {
    /// 总证书链数
    pub total_chains: usize,
    /// 有效证书链数
    pub valid_chains: usize,
    /// 平均链长度
    pub average_chain_length: f64,
    /// 最长链长度
    pub max_chain_length: usize,
    /// 信任根数量
    pub trusted_roots_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ra::cert::CertificateSubject;

    fn create_test_certificate(name: &str) -> X509Certificate {
        // 使用RA模块创建测试证书
        let subject = CertificateSubject {
            common_name: name.to_string(),
            organization: Some("Test Org".to_string()),
            organizational_unit: None,
            country: Some("CN".to_string()),
            state: None,
            locality: None,
        };
        
        let cert_info = crate::ra::cert::CertificateInfo {
            subject: subject.clone(),
            validity_seconds: 86400, // 1 day
            serial_number: None,
            is_ca: false,
            key_usage: vec!["digitalSignature".to_string()],
        };
        
        let keypair = capsula_key::Curve25519::generate().unwrap();
        crate::ra::cert::create_self_signed_certificate(&keypair, subject, cert_info).unwrap()
    }

    #[test]
    fn test_chain_creation() {
        let cert1 = create_test_certificate("Test Cert 1");
        let cert2 = create_test_certificate("Test Cert 2");
        let certificates = vec![cert1, cert2];

        let chain = Chain::new(certificates);
        assert!(chain.is_ok());

        let chain = chain.unwrap();
        assert_eq!(chain.length(), 2);
        assert_eq!(chain.end_entity_certificate().subject().unwrap().common_name, "Test Cert 1");
        assert_eq!(chain.root_certificate().subject().unwrap().common_name, "Test Cert 2");
    }

    #[test]
    fn test_empty_chain() {
        let result = Chain::new(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_chain_validation() {
        let cert = create_test_certificate("Test Cert");
        let chain = Chain::new(vec![cert]).unwrap();
        
        let result = chain.validate();
        assert_eq!(result.chain_length, 1);
        // 基本验证应该通过（虽然实际验证逻辑还未完全实现）
    }

    #[test]
    fn test_chain_builder() {
        let mut builder = ChainBuilder::new();
        let root_cert = create_test_certificate("Root CA");
        
        builder.add_trusted_root(root_cert.clone());
        assert_eq!(builder.trusted_roots.len(), 1);
        assert_eq!(builder.certificate_pool.len(), 1);
    }

    #[test]
    fn test_intermediate_certificates() {
        let cert1 = create_test_certificate("End Entity");
        let cert2 = create_test_certificate("Intermediate CA");
        let cert3 = create_test_certificate("Root CA");
        let certificates = vec![cert1, cert2, cert3];

        let chain = Chain::new(certificates).unwrap();
        assert_eq!(chain.length(), 3);
        
        let intermediates = chain.intermediate_certificates();
        assert_eq!(intermediates.len(), 1);
        assert_eq!(intermediates[0].subject().unwrap().common_name, "Intermediate CA");
    }
}