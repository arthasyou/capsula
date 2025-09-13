use std::collections::HashMap;

use crate::ra::cert::X509Certificate;
use capsula_key::{Key, Curve25519};
use capsula_key::{DigitalSignature, LocationInfo};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    error::{PkiError, Result as PkiResult},
    types::RevocationReason,
};

/// 撤销条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// 证书序列号
    pub serial_number: String,
    /// 撤销时间
    #[serde(with = "time::serde::rfc3339")]
    pub revocation_date: OffsetDateTime,
    /// 撤销原因
    pub reason: RevocationReason,
    /// 失效时间（可选）
    #[serde(with = "time::serde::rfc3339::option")]
    pub invalidity_date: Option<OffsetDateTime>,
}

/// 证书撤销列表
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    /// CRL版本
    pub version: u32,
    /// 颁发者
    pub issuer: String,
    /// 此次更新时间
    #[serde(with = "time::serde::rfc3339")]
    pub this_update: OffsetDateTime,
    /// 下次更新时间
    #[serde(with = "time::serde::rfc3339")]
    pub next_update: OffsetDateTime,
    /// 撤销的证书列表
    pub revoked_certificates: HashMap<String, RevocationEntry>,
    /// CRL序列号
    pub crl_number: u64,
    /// 数字签名
    pub signature: Option<DigitalSignature>,
}

impl CertificateRevocationList {
    /// 创建新的CRL
    pub fn new(issuer: String, update_interval_days: i64) -> Self {
        let now = OffsetDateTime::now_utc();
        let next_update = now + time::Duration::days(update_interval_days);

        Self {
            version: 2,
            issuer,
            this_update: now,
            next_update,
            revoked_certificates: HashMap::new(),
            crl_number: 1,
            signature: None,
        }
    }

    /// 撤销证书
    pub fn revoke_certificate(
        &mut self,
        serial_number: String,
        reason: RevocationReason,
        invalidity_date: Option<OffsetDateTime>,
    ) -> PkiResult<()> {
        if self.revoked_certificates.contains_key(&serial_number) {
            return Err(PkiError::CRLError(format!(
                "Certificate {serial_number} is already revoked"
            )));
        }

        let entry = RevocationEntry {
            serial_number: serial_number.clone(),
            revocation_date: OffsetDateTime::now_utc(),
            reason,
            invalidity_date,
        };

        self.revoked_certificates.insert(serial_number, entry);
        Ok(())
    }

    /// 移除证书撤销（用于撤销原因为CertificateHold的情况）
    pub fn remove_revocation(&mut self, serial_number: &str) -> PkiResult<()> {
        if let Some(entry) = self.revoked_certificates.get(serial_number) {
            if entry.reason != RevocationReason::CertificateHold {
                return Err(PkiError::CRLError(
                    "Only certificates revoked with CertificateHold can be removed".to_string(),
                ));
            }
        }

        self.revoked_certificates
            .remove(serial_number)
            .ok_or_else(|| {
                PkiError::CRLError(format!("Certificate {serial_number} is not in the CRL"))
            })?;

        Ok(())
    }

    /// 检查证书是否被撤销
    pub fn is_revoked(&self, serial_number: &str) -> bool {
        self.revoked_certificates.contains_key(serial_number)
    }

    /// 获取撤销信息
    pub fn get_revocation_info(&self, serial_number: &str) -> Option<&RevocationEntry> {
        self.revoked_certificates.get(serial_number)
    }

    /// 更新CRL
    pub fn update(&mut self, update_interval_days: i64) {
        self.this_update = OffsetDateTime::now_utc();
        self.next_update = self.this_update + time::Duration::days(update_interval_days);
        self.crl_number += 1;
        self.signature = None; // 需要重新签名
    }

    /// 签名CRL
    pub fn sign(&mut self, ca_keypair: &Curve25519) -> PkiResult<()> {
        // 序列化CRL数据（不包括签名）
        let mut crl_data = self.clone();
        crl_data.signature = None;

        let data = serde_json::to_vec(&crl_data)?;

        // 创建签名
        let location_info = LocationInfo::default();
        let signature = ca_keypair
            .sign_data(
                &data,
                location_info,
                Some(format!("CRL Issuer: {}", self.issuer)),
                Some("CRL Signature".to_string()),
            )
            .map_err(|e| PkiError::CRLError(format!("Failed to sign CRL: {e}")))?;

        self.signature = Some(signature);
        Ok(())
    }

    /// 验证CRL签名
    pub fn verify(&self, ca_cert: &X509Certificate) -> PkiResult<bool> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| PkiError::CRLError("CRL is not signed".to_string()))?;

        // 序列化CRL数据（不包括签名）
        let mut crl_data = self.clone();
        crl_data.signature = None;
        let data = serde_json::to_vec(&crl_data)?;

        // 从CA证书提取公钥
        // TODO: 修复证书公钥提取
        // let _ca_public_key = ca_cert.public_key_bytes()
            .map_err(|e| PkiError::CRLError(format!("Failed to extract CA public key: {e}")))?;

        // 验证签名
        let is_valid =
            capsula_key::verify_signature_standalone(&data, signature)
                .map_err(|e| PkiError::CRLError(format!("Failed to verify CRL signature: {e}")))?;

        Ok(is_valid)
    }

    /// 检查CRL是否过期
    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() > self.next_update
    }

    /// 获取撤销证书的数量
    pub fn revoked_count(&self) -> usize {
        self.revoked_certificates.len()
    }

    /// 导出CRL为JSON
    pub fn to_json(&self) -> PkiResult<String> {
        serde_json::to_string_pretty(self).map_err(PkiError::SerializationError)
    }

    /// 从JSON导入CRL
    pub fn from_json(json: &str) -> PkiResult<Self> {
        serde_json::from_str(json).map_err(PkiError::SerializationError)
    }
}

/// CRL管理器
pub struct CRLManager {
    crl: CertificateRevocationList,
    ca_keypair: Curve25519,
    auto_sign: bool,
}

impl CRLManager {
    /// 创建新的CRL管理器
    pub fn new(
        issuer: String,
        ca_keypair: Curve25519,
        update_interval_days: i64,
        auto_sign: bool,
    ) -> Self {
        let crl = CertificateRevocationList::new(issuer, update_interval_days);

        Self {
            crl,
            ca_keypair,
            auto_sign,
        }
    }

    /// 撤销证书
    pub fn revoke_certificate(
        &mut self,
        serial_number: String,
        reason: RevocationReason,
        invalidity_date: Option<OffsetDateTime>,
    ) -> PkiResult<()> {
        self.crl
            .revoke_certificate(serial_number, reason, invalidity_date)?;

        if self.auto_sign {
            self.crl.sign(&self.ca_keypair)?;
        }

        Ok(())
    }

    /// 批量撤销证书
    pub fn revoke_certificates(
        &mut self,
        certificates: Vec<(String, RevocationReason, Option<OffsetDateTime>)>,
    ) -> PkiResult<()> {
        for (serial, reason, invalidity_date) in certificates {
            self.crl
                .revoke_certificate(serial, reason, invalidity_date)?;
        }

        if self.auto_sign {
            self.crl.sign(&self.ca_keypair)?;
        }

        Ok(())
    }

    /// 更新CRL
    pub fn update(&mut self, update_interval_days: i64) -> PkiResult<()> {
        self.crl.update(update_interval_days);

        if self.auto_sign {
            self.crl.sign(&self.ca_keypair)?;
        }

        Ok(())
    }

    /// 获取当前CRL
    pub fn get_crl(&self) -> &CertificateRevocationList {
        &self.crl
    }

    /// 手动签名CRL
    pub fn sign_crl(&mut self) -> PkiResult<()> {
        self.crl.sign(&self.ca_keypair)
    }

    /// 导出签名后的CRL
    pub fn export(&self) -> PkiResult<String> {
        if self.crl.signature.is_none() {
            return Err(PkiError::CRLError("CRL is not signed".to_string()));
        }

        self.crl.to_json()
    }
}

#[cfg(test)]
mod tests {
    use capsula_key::Key as EccKeyPair;

    use super::*;
    use crate::ra::cert::{create_certificate, CertificateSubject};

    #[test]
    fn test_crl_basic_operations() {
        let mut crl = CertificateRevocationList::new("Test CA".to_string(), 7);

        // 撤销证书
        crl.revoke_certificate("12345".to_string(), RevocationReason::KeyCompromise, None)
            .unwrap();

        assert!(crl.is_revoked("12345"));
        assert!(!crl.is_revoked("67890"));
        assert_eq!(crl.revoked_count(), 1);

        // 获取撤销信息
        let info = crl.get_revocation_info("12345").unwrap();
        assert_eq!(info.reason, RevocationReason::KeyCompromise);
    }

    #[test]
    fn test_crl_certificate_hold() {
        let mut crl = CertificateRevocationList::new("Test CA".to_string(), 7);

        // 使用CertificateHold撤销
        crl.revoke_certificate("12345".to_string(), RevocationReason::CertificateHold, None)
            .unwrap();

        assert!(crl.is_revoked("12345"));

        // 可以移除CertificateHold撤销
        crl.remove_revocation("12345").unwrap();
        assert!(!crl.is_revoked("12345"));
    }

    #[test]
    fn test_crl_signing() {
        let ca_keypair = EccKeyPair::generate().unwrap();
        let ca_subject = CertificateSubject::new("Test CA".to_string());
        let ca_cert = create_certificate(&ca_keypair, ca_subject, None, 3650, true).unwrap();

        let mut crl = CertificateRevocationList::new("Test CA".to_string(), 7);

        // 撤销一个证书
        crl.revoke_certificate("12345".to_string(), RevocationReason::KeyCompromise, None)
            .unwrap();

        // 签名CRL
        crl.sign(&ca_keypair).unwrap();
        assert!(crl.signature.is_some());

        // 验证签名
        let is_valid = crl.verify(&ca_cert).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_crl_manager() {
        let ca_keypair = EccKeyPair::generate().unwrap();
        let mut manager = CRLManager::new(
            "Test CA".to_string(),
            ca_keypair,
            7,
            true, // 自动签名
        );

        // 撤销证书
        manager
            .revoke_certificate("12345".to_string(), RevocationReason::KeyCompromise, None)
            .unwrap();

        // 批量撤销
        manager
            .revoke_certificates(vec![
                ("67890".to_string(), RevocationReason::Superseded, None),
                (
                    "ABCDE".to_string(),
                    RevocationReason::CessationOfOperation,
                    None,
                ),
            ])
            .unwrap();

        let crl = manager.get_crl();
        assert_eq!(crl.revoked_count(), 3);
        assert!(crl.signature.is_some()); // 自动签名

        // 导出CRL
        let exported = manager.export().unwrap();
        assert!(!exported.is_empty());
    }
}
