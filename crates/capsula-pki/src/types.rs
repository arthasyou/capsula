use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// 证书状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertificateStatus {
    /// 有效
    Valid,
    /// 已撤销
    Revoked {
        reason: RevocationReason,
        #[serde(with = "time::serde::rfc3339")]
        revoked_at: OffsetDateTime,
    },
    /// 已过期
    Expired,
    /// 未生效
    NotYetValid,
}

/// 撤销原因
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RevocationReason {
    /// 未指定
    Unspecified,
    /// 密钥泄露
    KeyCompromise,
    /// CA密钥泄露
    CACompromise,
    /// 从属关系改变
    AffiliationChanged,
    /// 被取代
    Superseded,
    /// 停止操作
    CessationOfOperation,
    /// 证书暂停
    CertificateHold,
    /// 从CRL中移除
    RemoveFromCRL,
    /// 特权撤销
    PrivilegeWithdrawn,
    /// AA泄露
    AACompromise,
}

/// 证书元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    /// 证书序列号
    pub serial_number: String,
    /// 证书主体
    pub subject: String,
    /// 颁发者
    pub issuer: String,
    /// 生效时间
    #[serde(with = "time::serde::rfc3339")]
    pub not_before: OffsetDateTime,
    /// 过期时间
    #[serde(with = "time::serde::rfc3339")]
    pub not_after: OffsetDateTime,
    /// 证书状态
    pub status: CertificateStatus,
    /// 创建时间
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// 最后更新时间
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}
