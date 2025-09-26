use axum::{extract::Query, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    db::operations::{
        grant_permission as db_grant_permission, list_tokens as db_list_tokens,
        revoke_token as db_revoke_token, use_token as db_use_token, GrantRequest, RevokeRequest,
        UseTokenRequest,
    },
    error::{AppError, Result},
    models::token::Token,
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
    pub metadata: Option<serde_json::Value>,
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

    // Create the grant request for database
    let grant_request = GrantRequest {
        capsule_id: request.capsule_id.clone(),
        grantee: request.grantee.clone(),
        permissions: request.permissions.clone(),
        expires_at: request.expires_at.clone(),
        metadata: request.metadata.clone(),
    };

    // Store the token in the database
    match db_grant_permission(grant_request).await {
        Ok(token) => {
            let response = PermissionResponse {
                success: true,
                message: format!(
                    "Permission granted for capsule {} to {}",
                    request.capsule_id, request.grantee
                ),
                token: Some(token),
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

    // Create the use token request for database
    let use_request = UseTokenRequest {
        token: request.token.clone(),
        operation: request.operation.clone(),
        capsule_id: request.capsule_id.clone(),
    };

    // Validate and use the token
    match db_use_token(use_request).await {
        Ok((allowed, token)) => {
            let response = PermissionResponse {
                success: allowed,
                message: if allowed {
                    format!("Token is valid for operation: {}", request.operation)
                } else {
                    format!("Token does not allow operation: {}", request.operation)
                },
                token: Some(token),
                allowed: Some(allowed),
            };
            Ok((StatusCode::OK, Json(response)))
        }
        Err(e) => Err(e),
    }
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

    // Create the revoke request for database
    let revoke_request = RevokeRequest {
        token_id: request.token_id.clone(),
        reason: request.reason.clone(),
    };

    // Revoke the token
    match db_revoke_token(revoke_request).await {
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
    match db_list_tokens(
        params.capsule_id,
        params.grantee,
        params.active_only.unwrap_or(true),
    )
    .await
    {
        Ok(tokens) => {
            let total = tokens.len();
            let response = TokenListResponse { tokens, total };
            Ok((StatusCode::OK, Json(response)))
        }
        Err(e) => Err(e),
    }
}
