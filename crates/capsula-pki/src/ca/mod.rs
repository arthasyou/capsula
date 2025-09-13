use capsula_key::{Curve25519, Key};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::{
    error::{PkiError, Result as PkiResult},
    ra::cert::{
        create_certificate, create_self_signed_certificate, export_certificate, sign_certificate,
        CertificateInfo, CertificateSubject, X509Certificate,
    },
};

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
    keypair: Curve25519,
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
        let keypair = Curve25519::generate()
            .map_err(|e| PkiError::CAError(format!("Failed to generate keypair: {e}")))?;

        // 创建CA证书主体
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
            key_usage: vec!["digitalSignature".to_string(), "keyCertSign".to_string()],
        };

        // 创建自签名CA证书
        let certificate = create_self_signed_certificate(&keypair, subject, cert_info)
            .map_err(|e| PkiError::CAError(format!("Failed to create CA certificate: {}", e)))?;

        Ok(Self {
            keypair,
            certificate,
            config,
            issued_count: 0,
        })
    }

    /// 从现有密钥和证书创建CA
    pub fn from_existing(
        keypair: Curve25519,
        certificate: X509Certificate,
        config: CAConfig,
    ) -> PkiResult<Self> {
        // TODO: 验证证书是CA证书
        // if !certificate.info.is_ca {
        //     return Err(PkiError::CAError(
        //         "Certificate is not a CA certificate".to_string(),
        //     ));
        // }

        // TODO: 验证证书有效期
        // if !certificate.info.is_currently_valid() {
        //     return Err(PkiError::CAError("CA certificate is not valid".to_string()));
        // }

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
        _public_key: &Curve25519,
        _validity_days: Option<u32>,
        _is_ca: bool,
    ) -> PkiResult<X509Certificate> {
        // TODO: 实现证书签发逻辑
        // 目前返回一个占位实现

        // 创建自签名证书作为临时占位
        let cert_info = CertificateInfo {
            subject: subject.clone(),
            validity_seconds: 365 * 24 * 60 * 60, // 1年
            serial_number: None,
            is_ca: false,
            key_usage: vec!["digitalSignature".to_string()],
        };

        let cert = create_self_signed_certificate(&self.keypair, subject, cert_info)
            .map_err(|e| PkiError::CAError(format!("Failed to create certificate: {e}")))?;

        self.issued_count += 1;
        Ok(cert)
    }

    /// 创建中间CA
    pub fn create_intermediate_ca(&mut self, config: CAConfig) -> PkiResult<CertificateAuthority> {
        // 生成中间CA的密钥对
        let intermediate_keypair = Curve25519::generate()
            .map_err(|e| PkiError::CAError(format!("Failed to generate keypair: {e}")))?;

        // 创建中间CA的证书主体
        let subject = CertificateSubject {
            country: Some(config.country.clone()),
            state: Some(config.state.clone()),
            locality: Some(config.locality.clone()),
            organization: Some(config.organization.clone()),
            organizational_unit: config.organizational_unit.clone(),
            common_name: config.name.clone(),
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
        // TODO: 实现有效期检查
        365 // 临时返回
    }

    /// 导出CA证书和私钥
    pub fn export(&self) -> PkiResult<CAExport> {
        // TODO: 实现导出逻辑
        let private_key_pem = b"TODO: private key export".to_vec();
        let certificate_pem = b"TODO: certificate export".to_vec();

        Ok(CAExport {
            private_key_pem,
            certificate_pem,
            config: self.config.clone(),
            issued_count: self.issued_count,
        })
    }

    /// 从导出的数据恢复CA
    pub fn import(export: CAExport) -> PkiResult<Self> {
        // TODO: 实现导入逻辑
        let keypair = Curve25519::generate()
            .map_err(|e| PkiError::CAError(format!("Failed to generate keypair: {e}")))?;

        // 创建临时证书
        let subject = CertificateSubject {
            common_name: "Imported CA".to_string(),
            organization: Some("Imported".to_string()),
            organizational_unit: None,
            country: Some("CN".to_string()),
            state: None,
            locality: None,
        };

        let cert_info = CertificateInfo {
            subject: subject.clone(),
            validity_seconds: 365 * 24 * 60 * 60,
            serial_number: None,
            is_ca: true,
            key_usage: vec!["digitalSignature".to_string(), "keyCertSign".to_string()],
        };

        let certificate = create_self_signed_certificate(&keypair, subject, cert_info)
            .map_err(|e| PkiError::CAError(format!("Failed to create certificate: {e}")))?;

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
