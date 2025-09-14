//! CA核心机构实现
//!
//! 提供证书颁发机构的核心功能

use capsula_key::Curve25519;
use serde::{Deserialize, Serialize};

use crate::{
    error::{PkiError, Result as PkiResult},
    ra::cert::{
        create_self_signed_certificate, CertificateInfo, CertificateSubject, X509Certificate,
    },
};

/// 证书颁发机构
pub struct Authority {
    /// CA密钥对
    keypair: Curve25519,
    /// CA证书
    certificate: X509Certificate,
    /// CA配置
    config: super::config::Config,
    /// 已签发证书计数
    issued_count: u64,
    /// CA类型
    ca_type: CAType,
}

/// CA类型
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CAType {
    /// 根CA
    Root,
    /// 中间CA
    Intermediate {
        /// 父CA的证书指纹
        parent_fingerprint: String,
        /// 证书链级别 (1=根CA的直接子级)
        level: u8,
    },
}

impl Authority {
    /// 创建新的根CA
    pub fn new_root(config: super::config::Config) -> PkiResult<Self> {
        let keypair = Curve25519::generate()
            .map_err(|e| PkiError::CAError(format!("Failed to generate root CA keypair: {e}")))?;

        let subject = CertificateSubject {
            country: Some(config.country.clone()),
            state: Some(config.state.clone()),
            locality: Some(config.locality.clone()),
            organization: Some(config.organization.clone()),
            organizational_unit: config.organizational_unit.clone(),
            common_name: config.name.clone(),
        };

        let cert_info = CertificateInfo {
            subject: subject.clone(),
            validity_seconds: (config.validity_days * 24 * 60 * 60) as u64,
            serial_number: None,
            is_ca: true,
            key_usage: vec![
                "digitalSignature".to_string(),
                "keyCertSign".to_string(),
                "cRLSign".to_string(),
            ],
        };

        let certificate = create_self_signed_certificate(&keypair, subject, cert_info)
            .map_err(|e| PkiError::CAError(format!("Failed to create root CA certificate: {e}")))?;

        Ok(Self {
            keypair,
            certificate,
            config,
            issued_count: 0,
            ca_type: CAType::Root,
        })
    }

    /// 从现有密钥和证书创建CA
    pub fn from_existing(
        keypair: Curve25519,
        certificate: X509Certificate,
        config: super::config::Config,
        ca_type: CAType,
    ) -> PkiResult<Self> {
        // 基本验证
        Self::validate_ca_certificate(&certificate)?;

        Ok(Self {
            keypair,
            certificate,
            config,
            issued_count: 0,
            ca_type,
        })
    }

    /// 创建中间CA
    pub fn create_intermediate(
        &mut self,
        config: super::config::Config,
    ) -> PkiResult<Authority> {
        // 只有根CA或中间CA可以创建下级CA
        let new_level = match &self.ca_type {
            CAType::Root => 1,
            CAType::Intermediate { level, .. } => {
                if *level >= self.config.max_path_length.unwrap_or(5) {
                    return Err(PkiError::CAError(
                        "Maximum CA chain depth exceeded".to_string(),
                    ));
                }
                level + 1
            }
        };

        let intermediate_keypair = Curve25519::generate()
            .map_err(|e| PkiError::CAError(format!("Failed to generate intermediate CA keypair: {e}")))?;

        let subject = CertificateSubject {
            country: Some(config.country.clone()),
            state: Some(config.state.clone()),
            locality: Some(config.locality.clone()),
            organization: Some(config.organization.clone()),
            organizational_unit: config.organizational_unit.clone(),
            common_name: config.name.clone(),
        };

        let cert_info = CertificateInfo {
            subject: subject.clone(),
            validity_seconds: (config.validity_days * 24 * 60 * 60) as u64,
            serial_number: None,
            is_ca: true,
            key_usage: vec![
                "digitalSignature".to_string(),
                "keyCertSign".to_string(),
                "cRLSign".to_string(),
            ],
        };

        // 使用父CA签发中间CA证书
        let intermediate_cert = self.sign_certificate(&intermediate_keypair, cert_info)?;

        let parent_fingerprint = self.certificate_fingerprint();
        let ca_type = CAType::Intermediate {
            parent_fingerprint,
            level: new_level,
        };

        let intermediate_ca = Authority::from_existing(
            intermediate_keypair,
            intermediate_cert,
            config,
            ca_type,
        )?;

        // Note: issued_count already incremented in sign_certificate
        Ok(intermediate_ca)
    }

    /// 签发证书 (使用CertificateInfo)
    pub fn sign_certificate(
        &mut self,
        _public_key: &Curve25519, // TODO: Use for actual certificate signing
        cert_info: CertificateInfo,
    ) -> PkiResult<X509Certificate> {
        // TODO: 实现真正的证书签发逻辑
        // 目前创建一个临时证书作为占位
        let cert = create_self_signed_certificate(&self.keypair, cert_info.subject.clone(), cert_info)
            .map_err(|e| PkiError::CAError(format!("Failed to sign certificate: {e}")))?;

        self.issued_count += 1;
        Ok(cert)
    }

    /// 简化的证书签发接口
    pub fn issue_certificate(
        &mut self,
        subject: CertificateSubject,
        public_key: &Curve25519,
        validity_days: Option<u32>,
        is_ca: bool,
    ) -> PkiResult<X509Certificate> {
        let validity_days = validity_days.unwrap_or(self.config.default_cert_validity_days);
        
        let key_usage = if is_ca {
            vec![
                "digitalSignature".to_string(),
                "keyCertSign".to_string(),
                "cRLSign".to_string(),
            ]
        } else {
            vec!["digitalSignature".to_string(), "keyEncipherment".to_string()]
        };

        let cert_info = CertificateInfo {
            subject,
            validity_seconds: (validity_days * 24 * 60 * 60) as u64,
            serial_number: None,
            is_ca,
            key_usage,
        };

        self.sign_certificate(public_key, cert_info)
    }

    /// 获取CA证书
    pub fn certificate(&self) -> &X509Certificate {
        &self.certificate
    }

    /// 获取CA配置
    pub fn config(&self) -> &super::config::Config {
        &self.config
    }

    /// 获取CA类型
    pub fn ca_type(&self) -> &CAType {
        &self.ca_type
    }

    /// 获取已签发证书数量
    pub fn issued_count(&self) -> u64 {
        self.issued_count
    }

    /// 是否为根CA
    pub fn is_root(&self) -> bool {
        matches!(self.ca_type, CAType::Root)
    }

    /// 获取证书链级别
    pub fn chain_level(&self) -> u8 {
        match &self.ca_type {
            CAType::Root => 0,
            CAType::Intermediate { level, .. } => *level,
        }
    }

    /// 获取证书指纹
    pub fn certificate_fingerprint(&self) -> String {
        // 简化的指纹实现，实际应该用SHA-1或SHA-256
        // TODO: 实现真正的证书指纹计算
        format!("fp:{}", self.config.name)
    }

    /// 验证CA证书
    fn validate_ca_certificate(_certificate: &X509Certificate) -> PkiResult<()> {
        // TODO: 实现更完整的CA证书验证
        // - 检查是否为CA证书 (Basic Constraints)
        // - 检查密钥用途 (Key Usage)
        // - 检查有效期
        Ok(())
    }

    /// 检查证书有效性
    pub fn is_valid(&self) -> bool {
        // TODO: 实现证书有效性检查
        // - 检查有效期
        // - 检查撤销状态
        true
    }

    /// 获取剩余有效天数
    pub fn days_until_expiry(&self) -> PkiResult<i64> {
        // TODO: 实现有效期计算
        Ok(365) // 临时返回
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_root_ca() {
        let config = super::super::config::Config::default();
        let ca = Authority::new_root(config);
        assert!(ca.is_ok());
        
        let ca = ca.unwrap();
        assert!(ca.is_root());
        assert_eq!(ca.chain_level(), 0);
        assert_eq!(ca.issued_count(), 0);
    }

    #[test]
    fn test_create_intermediate_ca() {
        let config = super::super::config::Config::default();
        let mut root_ca = Authority::new_root(config.clone()).unwrap();
        
        let mut intermediate_config = config.clone();
        intermediate_config.name = "Intermediate CA".to_string();
        
        let intermediate = root_ca.create_intermediate(intermediate_config);
        assert!(intermediate.is_ok());
        
        let intermediate = intermediate.unwrap();
        assert!(!intermediate.is_root());
        assert_eq!(intermediate.chain_level(), 1);
        assert_eq!(root_ca.issued_count(), 1);
    }

    #[test]
    fn test_ca_chain_depth_limit() {
        let config = super::super::config::Config {
            max_path_length: Some(1),
            ..Default::default()
        };
        
        let mut root_ca = Authority::new_root(config.clone()).unwrap();
        
        // 创建第一级中间CA应该成功
        let mut intermediate_config = config.clone();
        intermediate_config.name = "Intermediate CA L1".to_string();
        let mut intermediate_l1 = root_ca.create_intermediate(intermediate_config).unwrap();
        
        // 创建第二级中间CA应该失败
        let mut intermediate_l2_config = config.clone();
        intermediate_l2_config.name = "Intermediate CA L2".to_string();
        let result = intermediate_l1.create_intermediate(intermediate_l2_config);
        assert!(result.is_err());
    }
}