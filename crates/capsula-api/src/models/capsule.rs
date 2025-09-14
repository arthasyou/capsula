//! Data capsule API models

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

/// Request to encapsulate data
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct EncapsulateRequest {
    /// Base64 encoded raw data to encapsulate
    #[validate(length(min = 1, message = "Data cannot be empty"))]
    pub data: String,
    
    /// Type of data (e.g., "medical.blood_test", "document.pdf")
    #[validate(length(min = 1, max = 100, message = "Data type must be 1-100 characters"))]
    pub data_type: String,
    
    /// Data producer/creator
    #[validate(length(min = 1, max = 100, message = "Producer must be 1-100 characters"))]
    pub producer: String,
    
    /// Data owner
    #[validate(length(min = 1, max = 100, message = "Owner must be 1-100 characters"))]
    pub owner: String,
    
    /// Recipient user ID who can decrypt the capsule
    #[validate(length(min = 1, max = 100, message = "Recipient ID must be 1-100 characters"))]
    pub recipient_id: String,
    
    /// Key algorithm to use for encryption ("RSA" or "P256")
    pub key_algorithm: String,
    
    /// Optional expiration time in days from now
    pub expires_in_days: Option<u64>,
}

/// Response from data encapsulation
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EncapsulateResponse {
    /// Generated unique capsule ID
    pub capsule_id: String,
    
    /// Base64 encoded capsule data
    pub capsule_data: String,
    
    /// Data type that was encapsulated
    pub data_type: String,
    
    /// Data producer
    pub producer: String,
    
    /// Data owner
    pub owner: String,
    
    /// When the capsule was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    /// Base64 encoded private key for decryption (demo only - would be managed securely in production)
    pub recipient_private_key: String,
}

/// Request to decapsulate data
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct DecapsulateRequest {
    /// Base64 encoded capsule data
    #[validate(length(min = 1, message = "Capsule data cannot be empty"))]
    pub capsule_data: String,
    
    /// User ID requesting decapsulation
    #[validate(length(min = 1, max = 100, message = "User ID must be 1-100 characters"))]
    pub user_id: String,
    
    /// Base64 encoded private key for decryption
    #[validate(length(min = 1, message = "Private key cannot be empty"))]
    pub private_key: String,
}

/// Response from data decapsulation
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DecapsulateResponse {
    /// Base64 encoded decrypted data
    pub data: String,
    
    /// Type of the decrypted data
    pub data_type: String,
    
    /// Original data producer
    pub producer: String,
    
    /// Original data owner
    pub owner: String,
    
    /// Whether verification (signature, policy, time) passed
    pub verification_passed: bool,
    
    /// When the data was decrypted
    pub decrypted_at: chrono::DateTime<chrono::Utc>,
}

/// Request to verify capsule without decryption
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct CapsuleVerifyRequest {
    /// Base64 encoded capsule data
    #[validate(length(min = 1, message = "Capsule data cannot be empty"))]
    pub capsule_data: String,
    
    /// Optional user ID for verification
    pub user_id: Option<String>,
}

/// Response from capsule verification
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CapsuleVerifyResponse {
    /// Whether the capsule is valid
    pub valid: bool,
    
    /// Type of data in the capsule
    pub data_type: String,
    
    /// Data producer
    pub producer: String,
    
    /// Data owner
    pub owner: String,
    
    /// When the capsule was originally created
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    /// When the capsule expires (if any)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    
    /// When the verification was performed
    pub verified_at: chrono::DateTime<chrono::Utc>,
}