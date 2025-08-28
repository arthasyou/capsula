use crate::{
    cert::{create_certificate, export_certificate, sign_certificate, CertificateSubject, X509Certificate},
    key::KeyPair as EccKeyPair,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::error::{PkiError, Result as PkiResult};

/// CA 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CAConfig {
    /// CA 名称
    pub name: String,
    /// 国家
    pub country: String,
    /// 省/州
    pub state: String,
    /// 城市
    pub locality: String,
    /// 组织
    pub organization: String,
    /// 组织单位
    pub organizational_unit: Option<String>,
    /// 邮箱
    pub email: Option<String>,
    /// 证书有效期（天）
    pub validity_days: u32,
    /// 默认证书有效期（天）
    pub default_cert_validity_days: u32,
    /// 最大证书链深度
    pub max_path_length: Option<u8>,
}

impl Default for CAConfig {
    fn default() -> Self {
        Self {
            name: "Root CA".to_string(),
            country: "CN".to_string(),
            state: "Shanghai".to_string(),
            locality: "Shanghai".to_string(),
            organization: "Medical PKI".to_string(),
            organizational_unit: Some("Certificate Authority".to_string()),
            email: None,
            validity_days: 3650,             // 10年
            default_cert_validity_days: 365, // 1年
            max_path_length: Some(2),
        }
    }
}

/// 证书颁发机构
pub struct CertificateAuthority {
    /// CA 密钥对
    keypair: EccKeyPair,
    /// CA 证书
    certificate: X509Certificate,
    /// CA 配置
    config: CAConfig,
    /// 已签发证书计数
    issued_count: u64,
}

impl CertificateAuthority {
    /// 创建新的根CA
    pub fn new_root_ca(config: CAConfig) -> PkiResult<Self> {
        // 生成密钥对
        let keypair = EccKeyPair::generate()
            .map_err(|e| PkiError::CAError(format!("Failed to generate keypair: {e}")))?;

        // 创建CA证书主体
        let subject = CertificateSubject {
            country: Some(config.country.clone()),
            state: Some(config.state.clone()),
            locality: Some(config.locality.clone()),
            organization: Some(config.organization.clone()),
            organizational_unit: config.organizational_unit.clone(),
            common_name: config.name.clone(),
            email: config.email.clone(),
        };

        // 创建自签名CA证书
        let certificate = create_certificate(
            &keypair,
            subject,
            None, // 自签名
            config.validity_days,
            true, // 是CA证书
        )
        .map_err(|e| PkiError::CAError(format!("Failed to create CA certificate: {e}")))?;

        Ok(Self {
            keypair,
            certificate,
            config,
            issued_count: 0,
        })
    }

    /// 从现有密钥和证书创建CA
    pub fn from_existing(
        keypair: EccKeyPair,
        certificate: X509Certificate,
        config: CAConfig,
    ) -> PkiResult<Self> {
        // 验证证书是CA证书
        if !certificate.info.is_ca {
            return Err(PkiError::CAError(
                "Certificate is not a CA certificate".to_string(),
            ));
        }

        // 验证证书有效期
        if !certificate.info.is_currently_valid() {
            return Err(PkiError::CAError("CA certificate is not valid".to_string()));
        }

        Ok(Self {
            keypair,
            certificate,
            config,
            issued_count: 0,
        })
    }

    /// 签发证书
    pub fn issue_certificate(
        &mut self,
        subject: CertificateSubject,
        public_key: &EccKeyPair,
        validity_days: Option<u32>,
        is_ca: bool,
    ) -> PkiResult<X509Certificate> {
        // 检查CA证书是否有效
        if !self.certificate.info.is_currently_valid() {
            return Err(PkiError::CAError("CA certificate has expired".to_string()));
        }

        // 使用配置的默认有效期或指定的有效期
        let validity_days = validity_days.unwrap_or(self.config.default_cert_validity_days);

        // 确保签发的证书不会超过CA证书的有效期
        let now = OffsetDateTime::now_utc();
        let cert_expiry = now + Duration::days(validity_days as i64);
        if cert_expiry > self.certificate.info.not_after {
            return Err(PkiError::CAError(
                "Certificate would expire after CA certificate".to_string(),
            ));
        }

        // 创建证书
        let cert = create_certificate(
            public_key,
            subject,
            Some(self.certificate.info.subject.clone()),
            validity_days,
            is_ca,
        )
        .map_err(|e| PkiError::CAError(format!("Failed to create certificate: {e}")))?;

        // 使用CA签名证书
        let signed_cert = sign_certificate(&self.keypair, &self.certificate, &cert)
            .map_err(|e| PkiError::CAError(format!("Failed to sign certificate: {e}")))?;

        self.issued_count += 1;

        Ok(signed_cert)
    }

    /// 创建中间CA
    pub fn create_intermediate_ca(&mut self, config: CAConfig) -> PkiResult<CertificateAuthority> {
        // 生成中间CA的密钥对
        let intermediate_keypair = EccKeyPair::generate()
            .map_err(|e| PkiError::CAError(format!("Failed to generate keypair: {e}")))?;

        // 创建中间CA的证书主体
        let subject = CertificateSubject {
            country: Some(config.country.clone()),
            state: Some(config.state.clone()),
            locality: Some(config.locality.clone()),
            organization: Some(config.organization.clone()),
            organizational_unit: config.organizational_unit.clone(),
            common_name: config.name.clone(),
            email: config.email.clone(),
        };

        // 签发中间CA证书
        let intermediate_cert = self.issue_certificate(
            subject,
            &intermediate_keypair,
            Some(config.validity_days),
            true, // 是CA证书
        )?;

        // 创建中间CA实例
        CertificateAuthority::from_existing(intermediate_keypair, intermediate_cert, config)
    }

    /// 获取CA证书
    pub fn certificate(&self) -> &X509Certificate {
        &self.certificate
    }

    /// 获取CA配置
    pub fn config(&self) -> &CAConfig {
        &self.config
    }

    /// 获取已签发证书数量
    pub fn issued_count(&self) -> u64 {
        self.issued_count
    }

    /// 获取CA证书的剩余有效天数
    pub fn days_until_expiry(&self) -> i64 {
        self.certificate.info.days_until_expiry()
    }

    /// 导出CA证书和私钥
    pub fn export(&self) -> PkiResult<CAExport> {
        let private_key_pem = self
            .keypair
            .export_private_key()
            .map_err(|e| PkiError::CAError(format!("Failed to export private key: {e}")))?;

        let certificate_pem = export_certificate(&self.certificate, "PEM")
            .map_err(|e| PkiError::CAError(format!("Failed to export certificate: {e}")))?;

        Ok(CAExport {
            private_key_pem: private_key_pem.into_bytes(),
            certificate_pem,
            config: self.config.clone(),
            issued_count: self.issued_count,
        })
    }

    /// 从导出的数据恢复CA
    pub fn import(export: CAExport) -> PkiResult<Self> {
        // 导入私钥
        let keypair =
            EccKeyPair::import_private_key(&String::from_utf8_lossy(&export.private_key_pem))
                .map_err(|e| PkiError::CAError(format!("Failed to import private key: {e}")))?;

        // 导入证书
        let certificate = crate::cert::import_certificate(&export.certificate_pem)
            .map_err(|e| PkiError::CAError(format!("Failed to import certificate: {e}")))?;

        let mut ca = Self::from_existing(keypair, certificate, export.config)?;
        ca.issued_count = export.issued_count;

        Ok(ca)
    }
}

/// CA导出数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CAExport {
    /// 私钥PEM格式
    pub private_key_pem: Vec<u8>,
    /// 证书PEM格式
    pub certificate_pem: Vec<u8>,
    /// CA配置
    pub config: CAConfig,
    /// 已签发证书数量
    pub issued_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_root_ca() {
        let config = CAConfig::default();
        let ca = CertificateAuthority::new_root_ca(config).unwrap();

        assert!(ca.certificate().info.is_ca);
        assert!(ca.certificate().info.is_currently_valid());
        assert_eq!(ca.issued_count(), 0);
    }

    #[test]
    fn test_issue_certificate() {
        let config = CAConfig::default();
        let mut ca = CertificateAuthority::new_root_ca(config).unwrap();

        // 为终端实体创建密钥对
        let end_entity_keypair = EccKeyPair::generate().unwrap();

        // 创建证书主体
        let subject = CertificateSubject {
            country: Some("CN".to_string()),
            state: Some("Shanghai".to_string()),
            locality: Some("Shanghai".to_string()),
            organization: Some("Test Hospital".to_string()),
            organizational_unit: Some("IT Department".to_string()),
            common_name: "test.hospital.com".to_string(),
            email: Some("admin@hospital.com".to_string()),
        };

        // 签发证书
        let cert = ca
            .issue_certificate(
                subject,
                &end_entity_keypair,
                None,  // 使用默认有效期
                false, // 不是CA证书
            )
            .unwrap();

        assert!(!cert.info.is_ca);
        assert!(cert.info.is_currently_valid());
        assert_eq!(ca.issued_count(), 1);
    }

    #[test]
    fn test_create_intermediate_ca() {
        let root_config = CAConfig::default();
        let mut root_ca = CertificateAuthority::new_root_ca(root_config).unwrap();

        let intermediate_config = CAConfig {
            name: "Intermediate CA".to_string(),
            organization: "Medical PKI Intermediate".to_string(),
            validity_days: 1825, // 5年，确保不超过根CA的有效期
            ..CAConfig::default()
        };

        let intermediate_ca = root_ca.create_intermediate_ca(intermediate_config).unwrap();

        assert!(intermediate_ca.certificate().info.is_ca);
        assert!(intermediate_ca.certificate().info.is_currently_valid());
        assert_eq!(root_ca.issued_count(), 1);
    }

    #[test]
    #[ignore = "Certificate parsing is not fully implemented yet"]
    fn test_export_import_ca() {
        let config = CAConfig::default();
        let ca = CertificateAuthority::new_root_ca(config).unwrap();

        // 验证原始CA证书是CA证书
        assert!(ca.certificate().info.is_ca);

        // 导出CA
        let export = ca.export().unwrap();

        // 导入CA
        let imported_ca = CertificateAuthority::import(export).unwrap();

        assert_eq!(
            ca.certificate().info.serial_number,
            imported_ca.certificate().info.serial_number
        );
        assert_eq!(ca.config().name, imported_ca.config().name);
    }
}
