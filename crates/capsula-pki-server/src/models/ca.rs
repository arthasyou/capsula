//! Certificate Authority related data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// CA Information
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CaInfo {
    /// CA certificate in PEM format
    pub ca_certificate_pem: String,

    /// CA subject
    pub subject: String,

    /// CA serial number
    pub serial_number: String,

    /// Not valid before
    pub not_before: DateTime<Utc>,

    /// Not valid after
    pub not_after: DateTime<Utc>,

    /// Key algorithm used
    pub key_algorithm: String,

    /// Key size (for RSA)
    pub key_size: Option<u32>,

    /// CA creation timestamp
    pub created_at: DateTime<Utc>,
}

/// CA status
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CaStatus {
    /// Whether CA is initialized
    pub initialized: bool,

    /// CA information (if initialized)
    pub ca_info: Option<CaInfo>,

    /// Number of certificates issued
    pub certificates_issued: u32,

    /// Number of active certificates
    pub active_certificates: u32,

    /// Number of revoked certificates
    pub revoked_certificates: u32,
}
