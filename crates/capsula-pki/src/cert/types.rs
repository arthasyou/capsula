use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// 证书主体信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSubject {
    /// 国家 (C)
    pub country: Option<String>,
    /// 省/州 (ST)
    pub state: Option<String>,
    /// 城市 (L)
    pub locality: Option<String>,
    /// 组织 (O)
    pub organization: Option<String>,
    /// 组织单位 (OU)
    pub organizational_unit: Option<String>,
    /// 通用名称 (CN)
    pub common_name: String,
    /// 邮箱地址
    pub email: Option<String>,
}

impl CertificateSubject {
    /// 创建一个新的证书主体
    pub fn new(common_name: String) -> Self {
        Self {
            country: None,
            state: None,
            locality: None,
            organization: None,
            organizational_unit: None,
            common_name,
            email: None,
        }
    }

    /// 创建医疗机构证书主体
    pub fn medical_institution(
        institution_name: String,
        department: Option<String>,
        city: String,
        state: String,
        country: String,
    ) -> Self {
        Self {
            country: Some(country),
            state: Some(state),
            locality: Some(city),
            organization: Some(institution_name.clone()),
            organizational_unit: department,
            common_name: institution_name,
            email: None,
        }
    }

    /// 创建医生证书主体
    pub fn doctor(
        doctor_name: String,
        license_number: String,
        institution: String,
        department: String,
        email: Option<String>,
    ) -> Self {
        Self {
            country: Some("CN".to_string()),
            state: None,
            locality: None,
            organization: Some(institution),
            organizational_unit: Some(department),
            common_name: format!("{doctor_name} (License: {license_number})"),
            email,
        }
    }
}

/// 证书信息结构体
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// 序列号
    pub serial_number: String,
    /// 证书主体
    pub subject: CertificateSubject,
    /// 颁发者
    pub issuer: CertificateSubject,
    /// 生效时间
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    /// 过期时间
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    /// 公钥 (Ed25519)
    pub public_key: Vec<u8>,
    /// 证书用途
    pub key_usage: Vec<String>,
    /// 扩展密钥用途
    pub extended_key_usage: Vec<String>,
    /// 是否为CA证书
    pub is_ca: bool,
    /// 证书链深度限制
    pub path_len_constraint: Option<u8>,
}

impl CertificateInfo {
    /// 检查证书是否在有效期内
    pub fn is_valid_at(&self, time: OffsetDateTime) -> bool {
        time >= self.not_before && time <= self.not_after
    }

    /// 检查证书当前是否有效
    pub fn is_currently_valid(&self) -> bool {
        self.is_valid_at(OffsetDateTime::now_utc())
    }

    /// 获取证书剩余有效天数
    pub fn days_until_expiry(&self) -> i64 {
        let now = OffsetDateTime::now_utc();
        (self.not_after - now).whole_days()
    }
}

/// 证书签名请求 (CSR)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSigningRequest {
    /// 请求主体
    pub subject: CertificateSubject,
    /// 公钥
    pub public_key: Vec<u8>,
    /// 签名算法
    pub signature_algorithm: String,
    /// 扩展属性
    pub extensions: Vec<String>,
}

/// X.509 证书包装结构
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// 证书DER格式数据
    pub der_data: Vec<u8>,
    /// 证书信息
    pub info: CertificateInfo,
}
