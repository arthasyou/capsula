//! Certificate related data models

use serde::{Deserialize, Serialize};
use utoipa::{ToSchema, IntoParams};
use uuid::Uuid;
use validator::Validate;
use chrono::{DateTime, Utc};
use surrealdb::sql::Thing;

/// Simplified certificate signing request for test PKI server
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct CertificateRequest {
    /// Username for certificate identification
    #[validate(length(min = 1, max = 255))]
    pub username: String,
}

/// Certificate response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CertificateResponse {
    /// Certificate ID
    pub certificate_id: Uuid,
    
    /// Certificate chain in PEM format (end entity + intermediate CA)
    pub certificate_pem: String,
    
    /// Private key in PEM format (only returned when generating new cert)
    pub private_key_pem: Option<String>,
    
    /// Certificate serial number
    pub serial_number: String,
    
    /// Certificate subject
    pub subject: String,
    
    /// Certificate issuer
    pub issuer: String,
    
    /// Not valid before
    pub not_before: DateTime<Utc>,
    
    /// Not valid after
    pub not_after: DateTime<Utc>,
    
    /// Certificate status
    pub status: CertificateStatus,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Certificate status
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    Active,
    Revoked,
    Expired,
}

/// Certificate renewal request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct RenewalRequest {
    /// Certificate ID to renew
    pub certificate_id: Uuid,
    
    /// Optional comment for renewal
    pub comment: Option<String>,
    
    /// Custom validity duration in days (default: 365)
    #[validate(range(min = 1, max = 7300))] // Max 20 years
    pub validity_days: Option<u32>,
}

/// Certificate revocation request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct RevocationRequest {
    /// Reason for revocation
    pub reason: RevocationReason,
    
    /// Optional comment
    pub comment: Option<String>,
}

/// Revocation reasons
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    PrivilegeWithdrawn,
    AaCompromise,
}

/// Certificate list query parameters
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, IntoParams, Validate)]
pub struct CertificateListQuery {
    /// Filter by status
    pub status: Option<CertificateStatus>,
    
    /// Filter by common name (partial match)
    pub common_name: Option<String>,
    
    /// Page number (starts from 1)
    #[validate(range(min = 1))]
    pub page: Option<u32>,
    
    /// Items per page
    #[validate(range(min = 1, max = 100))]
    pub limit: Option<u32>,
}

/// Certificate list response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CertificateListResponse {
    pub certificates: Vec<CertificateResponse>,
    pub total_count: u32,
    pub page: u32,
    pub limit: u32,
    pub has_more: bool,
}

/// Database certificate record for storage and persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    pub id: Option<Thing>,
    pub certificate_id: String,
    pub user_id: String,
    pub serial_number: String,
    pub common_name: String,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub email: Option<String>,
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub key_algorithm: String,
    pub key_size: Option<u32>,
    pub subject_dn: String,
    pub issuer_dn: String,
    pub not_before: i64, // Unix timestamp
    pub not_after: i64,  // Unix timestamp
    pub status: CertificateStatus,
    pub created_at: i64, // Unix timestamp
    pub revoked_at: Option<i64>, // Unix timestamp
    pub revocation_reason: Option<RevocationReason>,
    pub revocation_comment: Option<String>,
}

/// User certificate query parameters
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, IntoParams, Validate)]
pub struct UserCertificateQuery {
    /// User ID to query certificates for (optional when used with path parameter)
    pub user_id: Option<String>,
    
    /// Filter by certificate status
    pub status: Option<CertificateStatus>,
    
    /// Page number (starts from 1)
    #[validate(range(min = 1))]
    pub page: Option<u32>,
    
    /// Items per page
    #[validate(range(min = 1, max = 100))]
    pub limit: Option<u32>,
}

/// User certificate list response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserCertificateListResponse {
    pub user_id: String,
    pub certificates: Vec<CertificateResponse>,
    pub total_count: u32,
    pub page: u32,
    pub limit: u32,
    pub has_more: bool,
}