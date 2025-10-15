use axum::{extract::Query, http::StatusCode, response::Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as Sha2Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::{
    db::token as db_token,
    error::{AppError, Result},
    models::token::{Token, TokenType},
};

/// Request to grant permission to a capsule
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GrantPermissionRequest {
    /// The ID of the capsule to grant access to
    pub capsule_id: String,
    /// The grantee who will receive the permission
    pub grantee: String,
    /// The permissions to grant (e.g., "read", "write", "admin")
    pub permissions: Vec<String>,
    /// Optional expiration time (ISO 8601 format)
    pub expires_at: Option<String>,
    /// Optional metadata for the grant
    pub metadata: Option<Value>,
}

/// Request to use a permission token
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UsePermissionRequest {
    /// The token string to use
    pub token: String,
    /// The operation to perform (e.g., "read", "write")
    pub operation: String,
    /// Optional capsule ID (if not embedded in token)
    pub capsule_id: Option<String>,
}

/// Request to revoke a permission
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RevokePermissionRequest {
    /// The token ID to revoke
    pub token_id: String,
    /// Optional reason for revocation
    pub reason: Option<String>,
}

/// Response for permission operations
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PermissionResponse {
    pub success: bool,
    pub message: String,
    /// The generated or validated token
    pub token: Option<Token>,
    /// For use operations, whether the operation is allowed
    pub allowed: Option<bool>,
}

/// Response for listing tokens
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TokenListResponse {
    pub tokens: Vec<Token>,
    pub total: usize,
}

/// Query parameters for listing permissions
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListPermissionsParams {
    pub capsule_id: Option<String>,
    pub grantee: Option<String>,
    pub active_only: Option<bool>,
}

/// Grant permission to access a capsule
#[utoipa::path(
    post,
    path = "/grant",
    request_body = GrantPermissionRequest,
    responses(
        (status = 201, description = "Permission granted successfully", body = PermissionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Capsule not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authorization"
)]
pub async fn grant_permission(
    Json(request): Json<GrantPermissionRequest>,
) -> Result<(StatusCode, Json<PermissionResponse>)> {
    // Validate the request
    if request.capsule_id.is_empty() || request.grantee.is_empty() {
        return Err(AppError::BadRequest(
            "Capsule ID and grantee are required".to_string(),
        ));
    }

    if request.permissions.is_empty() {
        return Err(AppError::BadRequest(
            "At least one permission must be specified".to_string(),
        ));
    }

    // Generate token ID and raw token
    let token_id = Uuid::new_v4().to_string();
    let raw_token = generate_secure_token();
    let token_hash = hash_token(&raw_token);

    // Calculate expiration time (default to 30 days if not specified)
    let expires_at = if let Some(exp_str) = request.expires_at {
        // Parse ISO 8601 datetime
        chrono::DateTime::parse_from_rfc3339(&exp_str)
            .map_err(|e| AppError::BadRequest(format!("Invalid datetime: {}", e)))?
            .timestamp()
    } else {
        // Default to 30 days from now
        Utc::now().timestamp() + (30 * 24 * 60 * 60)
    };

    // Create grant ID (this would normally link to a molecular permission)
    let grant_id = format!("grant_{}", Uuid::new_v4());

    // Create the token
    let mut token = Token::new(
        token_id.clone(),
        token_hash,
        TokenType::Access,
        request.capsule_id.clone(),
        grant_id,
        request.grantee.clone(),
        "capsula-bank".to_string(),
        expires_at,
    );

    // Set permissions as scopes
    token = token.with_scopes(request.permissions.clone());

    // Add metadata if provided
    if let Some(metadata) = request.metadata {
        token.metadata = Some(metadata);
    }

    // Store the token in the database
    match db_token::create_token(token.clone()).await {
        Ok(created_token) => {
            // Return the token with the raw token value in metadata for the user
            let mut return_token = created_token;
            return_token.metadata = Some(serde_json::json!({
                "raw_token": raw_token,
                "original_metadata": token.metadata
            }));

            let response = PermissionResponse {
                success: true,
                message: format!(
                    "Permission granted for capsule {} to {}",
                    request.capsule_id, request.grantee
                ),
                token: Some(return_token),
                allowed: None,
            };
            Ok((StatusCode::CREATED, Json(response)))
        }
        Err(e) => Err(e),
    }
}

/// Use a permission token to access a capsule
#[utoipa::path(
    post,
    path = "/use",
    request_body = UsePermissionRequest,
    responses(
        (status = 200, description = "Token validated successfully", body = PermissionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Invalid or expired token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authorization"
)]
pub async fn use_token(
    Json(request): Json<UsePermissionRequest>,
) -> Result<(StatusCode, Json<PermissionResponse>)> {
    // Validate the request
    if request.token.is_empty() {
        return Err(AppError::BadRequest("Token is required".to_string()));
    }

    if request.operation.is_empty() {
        return Err(AppError::BadRequest("Operation is required".to_string()));
    }

    // Hash the provided token to compare with stored hash
    let token_hash = hash_token(&request.token);

    // Find the token by hash
    let mut token = match db_token::get_token_by_hash(&token_hash).await? {
        Some(t) => t,
        None => return Err(AppError::NotFound("Token not found".to_string())),
    };

    // Check if token is valid
    if !token.is_valid() {
        if token.is_expired() {
            return Err(AppError::Unauthorized("Token has expired".to_string()));
        }
        return Err(AppError::Unauthorized("Token is not valid".to_string()));
    }

    // Check if capsule_id matches (if provided)
    if let Some(capsule_id) = &request.capsule_id {
        if &token.capsule_id != capsule_id {
            return Err(AppError::Forbidden(
                "Token does not grant access to this capsule".to_string(),
            ));
        }
    }

    // Check if the operation is allowed by the token's scopes
    let operation_allowed = token.scopes.iter().any(|scope| {
        scope == &request.operation
            || scope == "admin"
            || scope == "*"
            || (scope == "read" && request.operation.starts_with("read"))
            || (scope == "write"
                && (request.operation.starts_with("write")
                    || request.operation.starts_with("create")))
    });

    // Use the token (decrement remaining uses if applicable)
    if operation_allowed && token.use_token() {
        // Update the token in the database
        db_token::update_token(&token).await?;
    }

    let response = PermissionResponse {
        success: operation_allowed,
        message: if operation_allowed {
            format!("Token is valid for operation: {}", request.operation)
        } else {
            format!("Token does not allow operation: {}", request.operation)
        },
        token: Some(token),
        allowed: Some(operation_allowed),
    };
    Ok((StatusCode::OK, Json(response)))
}

/// Revoke a permission token
#[utoipa::path(
    post,
    path = "/revoke",
    request_body = RevokePermissionRequest,
    responses(
        (status = 200, description = "Permission revoked successfully", body = PermissionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Token not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authorization"
)]
pub async fn revoke_permission(
    Json(request): Json<RevokePermissionRequest>,
) -> Result<(StatusCode, Json<PermissionResponse>)> {
    // Validate the request
    if request.token_id.is_empty() {
        return Err(AppError::BadRequest("Token ID is required".to_string()));
    }

    // Revoke the token
    match db_token::revoke_token(&request.token_id).await {
        Ok(_) => {
            let response = PermissionResponse {
                success: true,
                message: format!("Token {} has been revoked", request.token_id),
                token: None,
                allowed: None,
            };
            Ok((StatusCode::OK, Json(response)))
        }
        Err(e) => Err(e),
    }
}

/// Generate a secure random token
fn generate_secure_token() -> String {
    use base64::Engine;
    let token_bytes: [u8; 32] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes)
}

/// Hash a token using SHA-256
fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// List all permissions for a capsule or grantee
#[utoipa::path(
    get,
    path = "/list",
    params(ListPermissionsParams),
    responses(
        (status = 200, description = "Tokens retrieved successfully", body = TokenListResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Authorization"
)]
pub async fn list_permissions(
    Query(params): Query<ListPermissionsParams>,
) -> Result<(StatusCode, Json<TokenListResponse>)> {
    // Get tokens based on query parameters
    let tokens = if let Some(capsule_id) = params.capsule_id {
        db_token::get_tokens_by_capsule(&capsule_id).await?
    } else if let Some(grantee) = params.grantee {
        if params.active_only.unwrap_or(true) {
            db_token::get_active_tokens_by_subject(&grantee).await?
        } else {
            // Get all tokens for this subject (not just active)
            // Note: token.rs doesn't have this function, so we use get_active_tokens_by_subject for now
            db_token::get_active_tokens_by_subject(&grantee).await?
        }
    } else {
        // No filters provided, return empty list or error
        return Err(AppError::BadRequest(
            "Please provide either capsule_id or grantee filter".to_string(),
        ));
    };

    let total = tokens.len();
    let response = TokenListResponse { tokens, total };
    Ok((StatusCode::OK, Json(response)))
}
