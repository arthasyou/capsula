//! Certificate Authority related data models

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use chrono::{DateTime, Utc};

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

/// CA initialization request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CaInitRequest {
    /// CA common name
    pub common_name: String,
    
    /// Organization name
    pub organization: String,
    
    /// Organization unit
    pub organizational_unit: Option<String>,
    
    /// Country code (2 letters)
    pub country: String,
    
    /// State or province
    pub state: String,
    
    /// City or locality
    pub locality: String,
    
    /// CA validity in days
    pub validity_days: u32,
    
    /// Key algorithm (RSA, P256, Ed25519)
    pub key_algorithm: String,
    
    /// Key size for RSA (2048, 3072, 4096)
    pub key_size: Option<u32>,
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