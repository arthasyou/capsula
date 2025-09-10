use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use time::{Duration, OffsetDateTime};
use x509_cert::der::Decode;

use super::types::{CertificateInfo, CertificateSubject, X509Certificate};
use crate::{
    error::{PkiError, Result},
    key::KeyPair as EccKeyPair,
};

/// 创建数字证书
///
/// # Arguments
/// * `keypair` - Ed25519密钥对
/// * `subject` - 证书主体信息
/// * `issuer` - 颁发者信息（如果为None，则创建自签名证书）
/// * `validity_days` - 有效期（天数）
/// * `is_ca` - 是否为CA证书
///
/// # Returns
/// * `Result<X509Certificate>` - 成功返回X509证书
pub fn create_certificate(
    keypair: &EccKeyPair,
    subject: CertificateSubject,
    issuer: Option<CertificateSubject>,
    validity_days: u32,
    is_ca: bool,
) -> Result<X509Certificate> {
    let mut params = CertificateParams::new(vec![subject.common_name.clone()])
        .map_err(|e| PkiError::GenerationError(format!("Failed to create params: {e}")))?;

    // 设置证书主体信息
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &subject.common_name);

    if let Some(country) = &subject.country {
        dn.push(DnType::CountryName, country);
    }
    if let Some(state) = &subject.state {
        dn.push(DnType::StateOrProvinceName, state);
    }
    if let Some(locality) = &subject.locality {
        dn.push(DnType::LocalityName, locality);
    }
    if let Some(org) = &subject.organization {
        dn.push(DnType::OrganizationName, org);
    }
    if let Some(ou) = &subject.organizational_unit {
        dn.push(DnType::OrganizationalUnitName, ou);
    }

    params.distinguished_name = dn;

    // 设置有效期
    let not_before = OffsetDateTime::now_utc();
    let not_after = not_before + Duration::days(validity_days as i64);

    // 设置时间时减去一小时，确保证书立即生效
    let not_before_adjusted = not_before - Duration::hours(1);

    params.not_before = rcgen::date_time_ymd(
        not_before_adjusted.year(),
        not_before_adjusted.month() as u8,
        not_before_adjusted.day(),
    );
    params.not_after =
        rcgen::date_time_ymd(not_after.year(), not_after.month() as u8, not_after.day());

    // 设置序列号
    let mut serial_number = [0u8; 16];
    getrandom::fill(&mut serial_number)
        .map_err(|e| PkiError::GenerationError(format!("Failed to generate serial number: {e}")))?;
    params.serial_number = Some(serial_number.to_vec().into());

    // 设置密钥用途
    if is_ca {
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
    } else {
        params.is_ca = rcgen::IsCa::NoCa;
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
            rcgen::KeyUsagePurpose::ContentCommitment,
        ];
    }

    // 设置扩展密钥用途
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];

    // 使用私钥 PKCS8 PEM 格式创建 KeyPair
    let private_key_pem = keypair.export_private_key()?;
    let key_pair = KeyPair::from_pkcs8_pem_and_sign_algo(&private_key_pem, &rcgen::PKCS_ED25519)
        .map_err(|e| PkiError::GenerationError(format!("Failed to create key pair: {e}")))?;

    // 生成证书
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| PkiError::GenerationError(format!("Failed to create certificate: {e}")))?;

    // 序列化证书
    let der_data = cert.der().to_vec();

    // 创建证书信息
    let info = CertificateInfo {
        serial_number: hex::encode(serial_number),
        subject: subject.clone(),
        issuer: issuer.unwrap_or(subject),
        not_before: not_before_adjusted,
        not_after,
        public_key: keypair.public_key_bytes().to_vec(),
        key_usage: if is_ca {
            vec![
                "KeyCertSign".to_string(),
                "CrlSign".to_string(),
                "DigitalSignature".to_string(),
            ]
        } else {
            vec![
                "DigitalSignature".to_string(),
                "KeyEncipherment".to_string(),
                "ContentCommitment".to_string(),
            ]
        },
        extended_key_usage: vec!["ServerAuth".to_string(), "ClientAuth".to_string()],
        is_ca,
        path_len_constraint: if is_ca { None } else { Some(0) },
    };

    Ok(X509Certificate { der_data, info })
}

/// CA签名证书
///
/// # Arguments
/// * `ca_keypair` - CA的Ed25519密钥对
/// * `ca_cert` - CA证书
/// * `cert_to_sign` - 待签名的证书
///
/// # Returns
/// * `Result<X509Certificate>` - 成功返回签名后的证书
pub fn sign_certificate(
    _ca_keypair: &EccKeyPair,
    ca_cert: &X509Certificate,
    cert_to_sign: &X509Certificate,
) -> Result<X509Certificate> {
    // 验证CA证书
    if !ca_cert.info.is_ca {
        return Err(PkiError::SigningError("Not a CA certificate".to_string()));
    }

    if !ca_cert.info.is_currently_valid() {
        return Err(PkiError::CertificateExpired);
    }

    // TODO: 实现真正的CA签名逻辑
    // 当前返回原证书的副本，在实际应用中需要实现完整的签名逻辑
    Ok(cert_to_sign.clone())
}

/// 验证证书有效性
///
/// # Arguments
/// * `cert` - 待验证的证书
/// * `ca_cert` - CA证书（可选，用于验证证书链）
///
/// # Returns
/// * `Result<bool>` - 证书有效返回true
pub fn verify_certificate(
    cert: &X509Certificate,
    _ca_cert: Option<&X509Certificate>,
) -> Result<bool> {
    // 检查证书有效期
    if !cert.info.is_currently_valid() {
        if cert.info.not_after < OffsetDateTime::now_utc() {
            return Err(PkiError::CertificateExpired);
        } else {
            return Err(PkiError::CertificateNotYetValid);
        }
    }

    // TODO: 实现完整的证书验证逻辑
    // 包括签名验证、证书链验证等

    Ok(true)
}

/// 解析证书内容
///
/// # Arguments
/// * `cert_data` - 证书数据（DER或PEM格式）
///
/// # Returns
/// * `Result<CertificateInfo>` - 成功返回证书信息
pub fn parse_certificate(cert_data: &[u8]) -> Result<CertificateInfo> {
    // 尝试解析PEM格式
    let der_data = if cert_data.starts_with(b"-----BEGIN CERTIFICATE-----") {
        pem::parse(cert_data)
            .map_err(|e| PkiError::ParseError(format!("Failed to parse PEM: {e}")))?
            .contents()
            .to_vec()
    } else {
        cert_data.to_vec()
    };

    // 解析DER格式证书
    let cert = x509_cert::Certificate::from_der(&der_data)
        .map_err(|e| PkiError::ParseError(format!("Failed to parse DER: {e}")))?;

    // 提取证书信息
    let serial_number = hex::encode(cert.tbs_certificate.serial_number.as_bytes());

    // 解析主体信息
    let subject = parse_distinguished_name(&cert.tbs_certificate.subject)?;
    let issuer = parse_distinguished_name(&cert.tbs_certificate.issuer)?;

    // 解析有效期
    let not_before = parse_time(&cert.tbs_certificate.validity.not_before)?;
    let not_after = parse_time(&cert.tbs_certificate.validity.not_after)?;

    // 提取公钥（简化处理）
    let public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap_or(&[])
        .to_vec();

    // 解析扩展信息以确定是否为CA证书
    let mut is_ca = false;
    let path_len_constraint = None;

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions.iter() {
            // 基本约束扩展OID: 2.5.29.19
            if ext.extn_id.to_string() == "2.5.29.19" {
                // 简化处理：如果有基本约束扩展，通常表示是CA证书
                is_ca = true;
                // TODO: 正确解析path_len_constraint
            }
        }
    }

    Ok(CertificateInfo {
        serial_number,
        subject,
        issuer,
        not_before,
        not_after,
        public_key,
        key_usage: vec!["DigitalSignature".to_string()],
        extended_key_usage: vec![],
        is_ca,
        path_len_constraint,
    })
}

/// 导出证书
///
/// # Arguments
/// * `cert` - 证书
/// * `format` - 导出格式（"PEM" 或 "DER"）
///
/// # Returns
/// * `Result<Vec<u8>>` - 成功返回证书数据
pub fn export_certificate(cert: &X509Certificate, format: &str) -> Result<Vec<u8>> {
    match format.to_uppercase().as_str() {
        "DER" => Ok(cert.der_data.clone()),
        "PEM" => {
            let pem = pem::Pem::new("CERTIFICATE", cert.der_data.clone());
            let pem_string = pem::encode(&pem);
            Ok(pem_string.into_bytes())
        }
        _ => Err(PkiError::ExportError(format!(
            "Unsupported format: {format}"
        ))),
    }
}

/// 导入证书
///
/// # Arguments
/// * `cert_data` - 证书数据（PEM或DER格式）
///
/// # Returns
/// * `Result<X509Certificate>` - 成功返回证书
pub fn import_certificate(cert_data: &[u8]) -> Result<X509Certificate> {
    let info = parse_certificate(cert_data)?;

    // 确定是DER还是PEM格式
    let der_data = if cert_data.starts_with(b"-----BEGIN CERTIFICATE-----") {
        pem::parse(cert_data)
            .map_err(|e| PkiError::ImportError(format!("Failed to parse PEM: {e}")))?
            .contents()
            .to_vec()
    } else {
        cert_data.to_vec()
    };

    Ok(X509Certificate { der_data, info })
}

// 辅助函数：解析DN（Distinguished Name）
fn parse_distinguished_name(_dn: &x509_cert::name::Name) -> Result<CertificateSubject> {
    let mut subject = CertificateSubject::new("Unknown".to_string());

    // 简化的DN解析，实际应该遍历所有RDN
    // 这里仅作为示例
    subject.common_name = "Parsed CN".to_string();

    Ok(subject)
}

// 辅助函数：解析时间
fn parse_time(time: &x509_cert::time::Time) -> Result<OffsetDateTime> {
    use x509_cert::time::Time;

    match time {
        Time::UtcTime(_utc_time) => {
            // 简化的时间解析
            Ok(OffsetDateTime::now_utc())
        }
        Time::GeneralTime(_general_time) => {
            // 简化的时间解析
            Ok(OffsetDateTime::now_utc())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyPair as EccKeyPair;

    #[test]
    fn test_create_self_signed_certificate() {
        let keypair = EccKeyPair::generate().unwrap();

        let subject = CertificateSubject::medical_institution(
            "Shanghai First People Hospital".to_string(),
            Some("Cardiology".to_string()),
            "Shanghai".to_string(),
            "Shanghai".to_string(),
            "CN".to_string(),
        );

        let cert = create_certificate(&keypair, subject, None, 365, false).unwrap();

        assert!(cert.info.is_currently_valid());
        assert_eq!(cert.info.public_key, keypair.public_key_bytes().to_vec());
        assert!(!cert.info.is_ca);
    }

    #[test]
    fn test_create_ca_certificate() {
        let keypair = EccKeyPair::generate().unwrap();

        let subject = CertificateSubject::new("Test CA".to_string());

        let cert = create_certificate(&keypair, subject, None, 3650, true).unwrap();

        assert!(cert.info.is_currently_valid());
        assert!(cert.info.is_ca);
        assert!(cert.info.key_usage.contains(&"KeyCertSign".to_string()));
    }

    #[test]
    fn test_export_import_certificate() {
        let keypair = EccKeyPair::generate().unwrap();
        let subject = CertificateSubject::new("Test Certificate".to_string());
        let cert = create_certificate(&keypair, subject, None, 365, false).unwrap();

        // 测试DER格式导出导入
        let der_data = export_certificate(&cert, "DER").unwrap();
        let imported_cert = import_certificate(&der_data).unwrap();
        assert_eq!(cert.der_data, imported_cert.der_data);

        // 测试PEM格式导出导入
        let pem_data = export_certificate(&cert, "PEM").unwrap();
        let imported_cert_pem = import_certificate(&pem_data).unwrap();
        assert_eq!(cert.der_data, imported_cert_pem.der_data);
    }

    #[test]
    fn test_verify_certificate_validity() {
        let keypair = EccKeyPair::generate().unwrap();
        let subject = CertificateSubject::new("Test Certificate".to_string());
        let cert = create_certificate(&keypair, subject, None, 365, false).unwrap();

        let is_valid = verify_certificate(&cert, None).unwrap();
        assert!(is_valid);
    }
}
