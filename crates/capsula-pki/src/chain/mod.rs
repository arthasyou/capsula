use time::OffsetDateTime;

use super::crl::CertificateRevocationList;
use crate::error::{PkiError, Result as PkiResult};
use capsula_crypto::X509Certificate;

/// 证书链验证结果
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// 是否有效
    pub is_valid: bool,
    /// 错误信息
    pub errors: Vec<String>,
    /// 警告信息
    pub warnings: Vec<String>,
    /// 证书链深度
    pub chain_depth: usize,
}

impl ValidationResult {
    fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            chain_depth: 0,
        }
    }

    fn add_error(&mut self, error: String) {
        self.errors.push(error);
        self.is_valid = false;
    }

    fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
}

/// 证书链验证器
pub struct ChainValidator {
    /// 信任的根证书列表
    trusted_roots: Vec<X509Certificate>,
    /// CRL列表
    crls: Vec<CertificateRevocationList>,
    /// 是否检查撤销状态
    check_revocation: bool,
    /// 是否允许过期的CRL
    allow_expired_crl: bool,
    /// 最大证书链深度
    max_chain_depth: usize,
}

impl ChainValidator {
    /// 创建新的验证器
    pub fn new() -> Self {
        Self {
            trusted_roots: Vec::new(),
            crls: Vec::new(),
            check_revocation: true,
            allow_expired_crl: false,
            max_chain_depth: 5,
        }
    }

    /// 添加信任的根证书
    pub fn add_trusted_root(&mut self, root_cert: X509Certificate) -> PkiResult<()> {
        // 验证是否为CA证书
        if !root_cert.info.is_ca {
            return Err(PkiError::ValidationError(
                "Root certificate must be a CA certificate".to_string(),
            ));
        }

        // 验证是否为自签名证书
        if root_cert.info.subject.common_name != root_cert.info.issuer.common_name {
            return Err(PkiError::ValidationError(
                "Root certificate must be self-signed".to_string(),
            ));
        }

        self.trusted_roots.push(root_cert);
        Ok(())
    }

    /// 添加CRL
    pub fn add_crl(&mut self, crl: CertificateRevocationList) {
        self.crls.push(crl);
    }

    /// 设置是否检查撤销状态
    pub fn set_check_revocation(&mut self, check: bool) {
        self.check_revocation = check;
    }

    /// 设置是否允许过期的CRL
    pub fn set_allow_expired_crl(&mut self, allow: bool) {
        self.allow_expired_crl = allow;
    }

    /// 设置最大证书链深度
    pub fn set_max_chain_depth(&mut self, depth: usize) {
        self.max_chain_depth = depth;
    }

    /// 验证证书链
    pub fn validate_chain(&self, chain: &[X509Certificate]) -> ValidationResult {
        let mut result = ValidationResult::new();

        if chain.is_empty() {
            result.add_error("Certificate chain is empty".to_string());
            return result;
        }

        result.chain_depth = chain.len();

        // 检查链深度
        if chain.len() > self.max_chain_depth {
            result.add_error(format!(
                "Certificate chain depth {} exceeds maximum allowed depth {}",
                chain.len(),
                self.max_chain_depth
            ));
            return result;
        }

        // 验证每个证书
        for (i, cert) in chain.iter().enumerate() {
            // 检查证书有效期
            if !cert.info.is_currently_valid() {
                if cert.info.not_after < OffsetDateTime::now_utc() {
                    result.add_error(format!("Certificate at position {i} has expired"));
                } else {
                    result.add_error(format!("Certificate at position {i} is not yet valid"));
                }
            }

            // 检查撤销状态
            if self.check_revocation {
                if let Some(revoked) = self.check_revocation_status(cert) {
                    result.add_error(format!("Certificate at position {i} is revoked: {revoked}"));
                }
            }

            // 验证证书签名（除了最后一个证书）
            if i < chain.len() - 1 {
                let issuer = &chain[i + 1];

                // 检查颁发者是否为CA
                if !issuer.info.is_ca {
                    result.add_error(format!(
                        "Certificate at position {} is not a CA certificate",
                        i + 1
                    ));
                }

                // 检查颁发者和主体的关系
                if cert.info.issuer.common_name != issuer.info.subject.common_name {
                    result.add_error(format!(
                        "Certificate at position {} issuer does not match certificate at position \
                         {} subject",
                        i,
                        i + 1
                    ));
                }

                // TODO: 实现真正的签名验证
                // 这里需要使用颁发者的公钥验证证书的签名
            }
        }

        // 验证根证书
        let root_cert = chain.last().unwrap();
        if !self.verify_root_certificate(root_cert) {
            result.add_error("Root certificate is not trusted".to_string());
        }

        // 添加警告信息
        for (i, cert) in chain.iter().enumerate() {
            let days_until_expiry = cert.info.days_until_expiry();
            if days_until_expiry < 30 && days_until_expiry > 0 {
                result.add_warning(format!(
                    "Certificate at position {i} will expire in {days_until_expiry} days"
                ));
            }
        }

        result
    }

    /// 验证单个证书
    pub fn validate_certificate(&self, cert: &X509Certificate) -> ValidationResult {
        let mut result = ValidationResult::new();
        result.chain_depth = 1;

        // 检查证书有效期
        if !cert.info.is_currently_valid() {
            if cert.info.not_after < OffsetDateTime::now_utc() {
                result.add_error("Certificate has expired".to_string());
            } else {
                result.add_error("Certificate is not yet valid".to_string());
            }
        }

        // 检查撤销状态
        if self.check_revocation {
            if let Some(revoked) = self.check_revocation_status(cert) {
                result.add_error(format!("Certificate is revoked: {revoked}"));
            }
        }

        // 如果是自签名证书，检查是否在信任列表中
        if cert.info.subject.common_name == cert.info.issuer.common_name
            && !self.verify_root_certificate(cert)
        {
            result.add_error("Self-signed certificate is not trusted".to_string());
        }

        // 添加警告
        let days_until_expiry = cert.info.days_until_expiry();
        if days_until_expiry < 30 && days_until_expiry > 0 {
            result.add_warning(format!(
                "Certificate will expire in {days_until_expiry} days"
            ));
        }

        result
    }

    /// 检查证书的撤销状态
    fn check_revocation_status(&self, cert: &X509Certificate) -> Option<String> {
        let serial = &cert.info.serial_number;

        for crl in &self.crls {
            // 检查CRL颁发者是否匹配证书颁发者
            if crl.issuer == cert.info.issuer.common_name {
                // 检查CRL是否过期
                if crl.is_expired() && !self.allow_expired_crl {
                    continue;
                }

                // 检查证书是否在CRL中
                if let Some(entry) = crl.get_revocation_info(serial) {
                    return Some(format!("{:?}", entry.reason));
                }
            }
        }

        None
    }

    /// 验证根证书是否可信
    fn verify_root_certificate(&self, cert: &X509Certificate) -> bool {
        self.trusted_roots.iter().any(|trusted| {
            trusted.info.subject.common_name == cert.info.subject.common_name
                && trusted.info.serial_number == cert.info.serial_number
        })
    }
}

impl Default for ChainValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// 构建证书链
pub fn build_certificate_chain(
    leaf_cert: &X509Certificate,
    available_certs: &[X509Certificate],
) -> PkiResult<Vec<X509Certificate>> {
    let mut chain = vec![leaf_cert.clone()];
    let mut current_cert = leaf_cert;
    let mut used_serials = vec![leaf_cert.info.serial_number.clone()];

    // 最大搜索深度
    const MAX_DEPTH: usize = 10;

    for _ in 0 .. MAX_DEPTH {
        // 如果当前证书是自签名的，链构建完成
        if current_cert.info.subject.common_name == current_cert.info.issuer.common_name {
            break;
        }

        // 查找颁发者
        let issuer_name = &current_cert.info.issuer.common_name;
        let mut found_issuer = None;

        for cert in available_certs {
            if cert.info.subject.common_name == *issuer_name
                && cert.info.is_ca
                && !used_serials.contains(&cert.info.serial_number)
            {
                found_issuer = Some(cert);
                break;
            }
        }

        if let Some(issuer) = found_issuer {
            chain.push(issuer.clone());
            used_serials.push(issuer.info.serial_number.clone());
            current_cert = issuer;
        } else {
            // 无法找到颁发者
            return Err(PkiError::InvalidChain);
        }
    }

    Ok(chain)
}

#[cfg(test)]
mod tests {
    use capsula_crypto::EccKeyPair;

    use super::*;
    use crate::ca::{CAConfig, CertificateAuthority};
    use capsula_crypto::{create_certificate, CertificateSubject};

    #[test]
    fn test_chain_validation() {
        // 创建根CA
        let root_config = CAConfig::default();
        let mut root_ca = CertificateAuthority::new_root_ca(root_config).unwrap();

        // 创建中间CA
        let intermediate_config = CAConfig {
            name: "Intermediate CA".to_string(),
            validity_days: 1825, // 5年
            ..CAConfig::default()
        };
        let mut intermediate_ca = root_ca.create_intermediate_ca(intermediate_config).unwrap();

        // 创建终端实体证书
        let end_entity_keypair = EccKeyPair::generate_keypair().unwrap();
        let end_entity_subject = CertificateSubject::new("End Entity".to_string());
        let end_entity_cert = intermediate_ca
            .issue_certificate(end_entity_subject, &end_entity_keypair, None, false)
            .unwrap();

        // 构建证书链
        let chain = vec![
            end_entity_cert,
            intermediate_ca.certificate().clone(),
            root_ca.certificate().clone(),
        ];

        // 创建验证器
        let mut validator = ChainValidator::new();
        validator
            .add_trusted_root(root_ca.certificate().clone())
            .unwrap();
        validator.set_check_revocation(false); // 暂时禁用撤销检查

        // 验证链
        let result = validator.validate_chain(&chain);
        assert!(result.is_valid);
        assert_eq!(result.chain_depth, 3);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_expired_certificate_validation() {
        let keypair = EccKeyPair::generate_keypair().unwrap();
        let subject = CertificateSubject::new("Test Certificate".to_string());

        // 创建一个即将过期的证书（有效期为20天，小于30天警告阈值）
        let cert = create_certificate(&keypair, subject, None, 20, false).unwrap();

        let validator = ChainValidator::new();
        let result = validator.validate_certificate(&cert);

        // 证书应该有警告（即将过期）
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_build_certificate_chain() {
        // 创建根CA
        let root_config = CAConfig::default();
        let mut root_ca = CertificateAuthority::new_root_ca(root_config).unwrap();

        // 创建中间CA
        let intermediate_config = CAConfig {
            name: "Intermediate CA".to_string(),
            validity_days: 1825, // 5年
            ..CAConfig::default()
        };
        let mut intermediate_ca = root_ca.create_intermediate_ca(intermediate_config).unwrap();

        // 创建终端实体证书
        let end_entity_keypair = EccKeyPair::generate_keypair().unwrap();
        let end_entity_subject = CertificateSubject::new("End Entity".to_string());
        let end_entity_cert = intermediate_ca
            .issue_certificate(end_entity_subject, &end_entity_keypair, None, false)
            .unwrap();

        // 可用证书列表
        let available_certs = vec![
            root_ca.certificate().clone(),
            intermediate_ca.certificate().clone(),
        ];

        // 构建链
        let chain = build_certificate_chain(&end_entity_cert, &available_certs).unwrap();

        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].info.subject.common_name, "End Entity");
        assert_eq!(chain[1].info.subject.common_name, "Intermediate CA");
        assert_eq!(chain[2].info.subject.common_name, "Root CA");
    }
}
