//! Certificate related data models

use serde::{Deserialize, Serialize};
use utoipa::{ToSchema, IntoParams};
use uuid::Uuid;
use validator::Validate;
use chrono::{DateTime, Utc};

/// Certificate signing request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct CertificateRequest {
    /// Common name for the certificate
    #[validate(length(min = 1, max = 255))]
    pub common_name: String,
    
    /// Organization name
    pub organization: Option<String>,
    
    /// Organization unit
    pub organizational_unit: Option<String>,
    
    /// Country code (2 letters)
    #[validate(length(equal = 2))]
    pub country: Option<String>,
    
    /// State or province
    pub state: Option<String>,
    
    /// City or locality
    pub locality: Option<String>,
    
    /// Email address
    #[validate(email)]
    pub email: Option<String>,
    
    /// Certificate validity in days
    #[validate(range(min = 1, max = 3650))]
    pub validity_days: u32,
    
    /// Key algorithm (RSA, P256, Ed25519)
    pub key_algorithm: String,
    
    /// Key size for RSA (2048, 3072, 4096)
    pub key_size: Option<u32>,
}

/// Certificate response
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CertificateResponse {
    /// Certificate ID
    pub certificate_id: Uuid,
    
    /// Certificate in PEM format
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