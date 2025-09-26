use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    db::get_db,
    error::Result,
    models::token::{Token, TokenStatus, TokenType},
};

/// Request to grant permission to a capsule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRequest {
    pub capsule_id: String,
    pub grantee: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Request to use a token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseTokenRequest {
    pub token: String,
    pub operation: String,
    pub capsule_id: Option<String>,
}

/// Request to revoke a token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub token_id: String,
    pub reason: Option<String>,
}

/// Grant permission by creating a new token
pub async fn grant_permission(request: GrantRequest) -> Result<Token> {
    let db = get_db();
    
    // Generate token ID and raw token
    let token_id = Uuid::new_v4().to_string();
    let raw_token = generate_secure_token();
    let token_hash = hash_token(&raw_token);
    
    // Calculate expiration time (default to 30 days if not specified)
    let expires_at = if let Some(exp_str) = request.expires_at {
        // Parse ISO 8601 datetime
        chrono::DateTime::parse_from_rfc3339(&exp_str)
            .map_err(|e| crate::error::AppError::BadRequest(format!("Invalid datetime: {}", e)))?
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
    
    // Insert into database
    let query = r#"
        CREATE token SET
            token_id = $token_id,
            token_hash = $token_hash,
            token_type = $token_type,
            capsule_id = $capsule_id,
            grant_id = $grant_id,
            subject_id = $subject_id,
            issuer = $issuer,
            bind_pubkey_fpr = $bind_pubkey_fpr,
            created_at = $created_at,
            expires_at = $expires_at,
            last_used_at = $last_used_at,
            remaining_uses = $remaining_uses,
            status = $status,
            metadata = $metadata,
            scopes = $scopes
    "#;
    
    db.query(query)
        .bind(("token_id", token.token_id.clone()))
        .bind(("token_hash", token.token_hash.clone()))
        .bind(("token_type", serde_json::to_value(&token.token_type)?))
        .bind(("capsule_id", token.capsule_id.clone()))
        .bind(("grant_id", token.grant_id.clone()))
        .bind(("subject_id", token.subject_id.clone()))
        .bind(("issuer", token.issuer.clone()))
        .bind(("bind_pubkey_fpr", token.bind_pubkey_fpr.clone()))
        .bind(("created_at", token.created_at))
        .bind(("expires_at", token.expires_at))
        .bind(("last_used_at", token.last_used_at))
        .bind(("remaining_uses", token.remaining_uses))
        .bind(("status", serde_json::to_value(&token.status)?))
        .bind(("metadata", token.metadata.clone()))
        .bind(("scopes", token.scopes.clone()))
        .await?;
    
    // Return the token with the raw token value in metadata for the user
    // In production, you would return the raw_token separately and securely
    let mut return_token = token.clone();
    return_token.metadata = Some(serde_json::json!({
        "raw_token": raw_token,
        "original_metadata": token.metadata
    }));
    
    Ok(return_token)
}

/// Use a token and validate permissions
pub async fn use_token(request: UseTokenRequest) -> Result<(bool, Token)> {
    let db = get_db();
    
    // Hash the provided token to compare with stored hash
    let token_hash = hash_token(&request.token);
    
    // Find the token by hash
    let query = r#"
        SELECT * FROM token 
        WHERE token_hash = $token_hash
        LIMIT 1
    "#;
    
    let mut response = db.query(query)
        .bind(("token_hash", token_hash.clone()))
        .await?;
    
    let tokens: Vec<Token> = response.take(0)?;
    
    if tokens.is_empty() {
        return Err(crate::error::AppError::NotFound("Token not found".to_string()));
    }
    
    let mut token = tokens.into_iter().next().unwrap();
    
    // Check if token is valid
    if !token.is_valid() {
        if token.is_expired() {
            return Err(crate::error::AppError::Unauthorized("Token has expired".to_string()));
        }
        return Err(crate::error::AppError::Unauthorized("Token is not valid".to_string()));
    }
    
    // Check if capsule_id matches (if provided)
    if let Some(capsule_id) = &request.capsule_id {
        if &token.capsule_id != capsule_id {
            return Err(crate::error::AppError::Forbidden(
                "Token does not grant access to this capsule".to_string()
            ));
        }
    }
    
    // Check if the operation is allowed by the token's scopes
    let operation_allowed = token.scopes.iter().any(|scope| {
        scope == &request.operation || 
        scope == "admin" || 
        scope == "*" ||
        (scope == "read" && request.operation.starts_with("read")) ||
        (scope == "write" && (request.operation.starts_with("write") || request.operation.starts_with("create")))
    });
    
    if !operation_allowed {
        return Ok((false, token));
    }
    
    // Use the token (decrement remaining uses if applicable)
    if token.use_token() {
        // Update the token in the database
        let update_query = r#"
            UPDATE token SET
                last_used_at = $last_used_at,
                remaining_uses = $remaining_uses,
                status = $status
            WHERE token_id = $token_id
        "#;
        
        db.query(update_query)
            .bind(("last_used_at", token.last_used_at))
            .bind(("remaining_uses", token.remaining_uses))
            .bind(("status", serde_json::to_value(&token.status)?))
            .bind(("token_id", token.token_id.clone()))
            .await?;
    }
    
    Ok((operation_allowed, token))
}

/// Revoke a token
pub async fn revoke_token(request: RevokeRequest) -> Result<()> {
    let db = get_db();
    
    // Find the token
    let query = r#"
        SELECT * FROM token 
        WHERE token_id = $token_id
        LIMIT 1
    "#;
    
    let mut response = db.query(query)
        .bind(("token_id", request.token_id.clone()))
        .await?;
    
    let tokens: Vec<Token> = response.take(0)?;
    
    if tokens.is_empty() {
        return Err(crate::error::AppError::NotFound("Token not found".to_string()));
    }
    
    // Update token status to revoked
    let update_query = r#"
        UPDATE token SET
            status = $status,
            metadata = $metadata
        WHERE token_id = $token_id
    "#;
    
    let mut metadata = serde_json::json!({
        "revoked_at": Utc::now().to_rfc3339(),
    });
    
    if let Some(reason) = request.reason {
        metadata["revocation_reason"] = serde_json::Value::String(reason);
    }
    
    db.query(update_query)
        .bind(("status", serde_json::to_value(&TokenStatus::Revoked)?))
        .bind(("metadata", metadata))
        .bind(("token_id", request.token_id.clone()))
        .await?;
    
    Ok(())
}

/// List tokens based on filters
pub async fn list_tokens(
    capsule_id: Option<String>,
    grantee: Option<String>,
    active_only: bool,
) -> Result<Vec<Token>> {
    let db = get_db();
    
    let mut query = String::from("SELECT * FROM token WHERE 1=1");
    let mut bindings = Vec::new();
    
    if let Some(cid) = capsule_id {
        query.push_str(" AND capsule_id = $capsule_id");
        bindings.push(("capsule_id", cid));
    }
    
    if let Some(g) = grantee {
        query.push_str(" AND subject_id = $grantee");
        bindings.push(("grantee", g));
    }
    
    if active_only {
        query.push_str(" AND status = 'active'");
    }
    
    query.push_str(" ORDER BY created_at DESC");
    
    let mut db_query = db.query(&query);
    
    for (key, value) in bindings {
        db_query = db_query.bind((key, value));
    }
    
    let mut response = db_query.await?;
    let tokens: Vec<Token> = response.take(0)?;
    
    Ok(tokens)
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