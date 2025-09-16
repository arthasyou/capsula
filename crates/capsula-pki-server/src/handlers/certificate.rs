//! Certificate management handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use uuid::Uuid;

use crate::{
    db::{certificate::CertificateService, get_db},
    error::{AppError, Result},
    models::certificate::{
        CertificateListQuery, CertificateListResponse, CertificateRecord, CertificateRequest,
        CertificateResponse, RenewalRequest, RevocationRequest, UserCertificateQuery,
        UserCertificateListResponse,
    },
    state::AppState,
};

/// Sign a new certificate
#[utoipa::path(
    post,
    path = "/create",
    request_body = CertificateRequest,
    responses(
        (status = 201, description = "Certificate signed successfully", body = CertificateResponse),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Certificate"
)]
pub async fn create_certificate(
    State(app_state): State<AppState>,
    Json(request): Json<CertificateRequest>,
) -> Result<(StatusCode, Json<CertificateResponse>)> {
    use crate::certificate::{CertificateSigner, CertificateRequest as SignerRequest};
    use uuid::Uuid;
    
    // Get PKI configuration from app state
    let pki_manager = app_state.pki_manager.read().await;
    let config = pki_manager.config.clone();
    drop(pki_manager);
    
    // Create certificate signer
    let signer = CertificateSigner::new(config);
    
    // Convert API request to signer request
    let signer_request = SignerRequest {
        username: request.username.clone(),
    };
    
    // Sign the certificate
    let issued_cert = signer.sign_certificate(&signer_request, None).await?;
    
    // Store certificate in database
    let db = get_db();
    let cert_service = CertificateService::new(db.clone());
    
    let cert_uuid = Uuid::new_v4();
    let cert_record = CertificateRecord {
        id: None,
        certificate_id: cert_uuid.to_string(),
        user_id: request.username.clone(),
        serial_number: issued_cert.serial_number.clone(),
        common_name: request.username.clone(),
        organization: Some("Capsula Test PKI".to_string()),
        organizational_unit: Some("Test Users".to_string()),
        country: None,
        state: None,
        locality: None,
        email: None,
        certificate_pem: issued_cert.certificate_pem.clone(),
        private_key_pem: None, // Don't store private key in test environment
        key_algorithm: issued_cert.key_algorithm.clone(),
        key_size: issued_cert.key_size,
        subject_dn: issued_cert.subject.clone(),
        issuer_dn: issued_cert.issuer.clone(),
        not_before: issued_cert.not_before.timestamp(),
        not_after: issued_cert.not_after.timestamp(),
        status: crate::models::certificate::CertificateStatus::Active,
        created_at: issued_cert.issued_at.timestamp(),
        revoked_at: None,
        revocation_reason: None,
        revocation_comment: None,
    };
    
    let stored_cert = cert_service.store_certificate(cert_record).await?;
    
    // Convert to response, build certificate chain dynamically, and include private key
    let pki_manager = app_state.pki_manager.read().await;
    let intermediate_ca_path = &pki_manager.config.intermediate_ca_path;
    let mut response = convert_record_to_response(stored_cert, intermediate_ca_path);
    response.private_key_pem = Some(issued_cert.private_key_pem);
    
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get certificate by ID
#[utoipa::path(
    get,
    path = "/get/{certificate_id}",
    params(
        ("certificate_id" = Uuid, Path, description = "Certificate ID")
    ),
    responses(
        (status = 200, description = "Certificate found", body = CertificateResponse),
        (status = 404, description = "Certificate not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Certificate"
)]
pub async fn get_certificate(
    State(app_state): State<AppState>,
    Path(certificate_id): Path<String>,
) -> Result<Json<CertificateResponse>> {
    let db = get_db();
    let cert_service = CertificateService::new(db.clone());
    
    if let Some(cert_record) = cert_service.get_certificate(&certificate_id).await? {
        let pki_manager = app_state.pki_manager.read().await;
        let intermediate_ca_path = &pki_manager.config.intermediate_ca_path;
        let response = convert_record_to_response(cert_record, intermediate_ca_path);
        Ok(Json(response))
    } else {
        Err(AppError::NotFound("Certificate not found".to_string()))
    }
}

/// List all certificates (admin endpoint)  
#[utoipa::path(
    get,
    path = "/list",
    params(CertificateListQuery),
    responses(
        (status = 200, description = "Certificate list", body = CertificateListResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Certificate"
)]
pub async fn list_certificates(
    State(app_state): State<AppState>,
    Query(query): Query<CertificateListQuery>,
) -> Result<Json<CertificateListResponse>> {
    let db = get_db();
    let cert_service = CertificateService::new(db.clone());
    
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    
    let (certificates, total_count) = cert_service
        .list_certificates(query.status, Some(page), Some(limit))
        .await?;
    
    let pki_manager = app_state.pki_manager.read().await;
    let intermediate_ca_path = &pki_manager.config.intermediate_ca_path;
    let cert_responses: Vec<CertificateResponse> = certificates
        .into_iter()
        .map(|cert| convert_record_to_response(cert, intermediate_ca_path))
        .collect();
    
    let has_more = (page * limit) < total_count;
    
    let response = CertificateListResponse {
        certificates: cert_responses,
        total_count,
        page,
        limit,
        has_more,
    };
    
    Ok(Json(response))
}

/// Revoke a certificate
#[utoipa::path(
    post,
    path = "/revoke/{certificate_id}",
    params(
        ("certificate_id" = Uuid, Path, description = "Certificate ID")
    ),
    request_body = RevocationRequest,
    responses(
        (status = 200, description = "Certificate revoked successfully"),
        (status = 404, description = "Certificate not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Certificate"
)]
pub async fn revoke_certificate(
    Path(certificate_id): Path<String>,
    Json(request): Json<RevocationRequest>,
) -> Result<StatusCode> {
    let db = get_db();
    let cert_service = CertificateService::new(db.clone());
    
    // Check if certificate exists
    if cert_service.get_certificate(&certificate_id).await?.is_none() {
        return Err(AppError::NotFound("Certificate not found".to_string()));
    }
    
    // Revoke the certificate with properly serialized reason
    let reason_str = serde_json::to_string(&request.reason)
        .map_err(|e| AppError::Internal(format!("Failed to serialize revocation reason: {}", e)))?
        .trim_matches('"').to_string(); // Remove quotes from JSON string
        
    cert_service
        .revoke_certificate(
            &certificate_id,
            Some(reason_str),
            request.comment,
        )
        .await?;
    
    Ok(StatusCode::OK)
}

/// Get certificates for a specific user
#[utoipa::path(
    get,
    path = "/users/{user_id}/certificates",
    params(
        ("user_id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User certificates", body = UserCertificateListResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Certificate"
)]
pub async fn get_user_certificates(
    State(app_state): State<AppState>,
    Path(user_id): Path<String>,
    Query(query_params): Query<UserCertificateQuery>,
) -> Result<Json<UserCertificateListResponse>> {
    let db = get_db();
    let cert_service = CertificateService::new(db.clone());
    
    let mut query = query_params;
    query.user_id = Some(user_id.clone());
    
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    
    let (certificates, total_count) = cert_service.get_user_certificates(&query).await?;
    
    let pki_manager = app_state.pki_manager.read().await;
    let intermediate_ca_path = &pki_manager.config.intermediate_ca_path;
    let cert_responses: Vec<CertificateResponse> = certificates
        .into_iter()
        .map(|cert| convert_record_to_response(cert, intermediate_ca_path))
        .collect();
    
    let has_more = (page * limit) < total_count;
    
    let response = UserCertificateListResponse {
        user_id,
        certificates: cert_responses,
        total_count,
        page,
        limit,
        has_more,
    };
    
    Ok(Json(response))
}

/// Build certificate chain by combining end entity cert with intermediate CA cert
fn build_certificate_chain(end_entity_cert_pem: &str, intermediate_ca_path: &str) -> String {
    use std::{fs, path::Path};
    
    // Build path to intermediate CA certificate
    let intermediate_cert_path = format!("{}/certs/intermediate.cert.pem", intermediate_ca_path);
    
    if !Path::new(&intermediate_cert_path).exists() {
        tracing::warn!("Intermediate CA certificate not found at {}, returning single certificate", intermediate_cert_path);
        return end_entity_cert_pem.to_string();
    }
    
    // Read intermediate CA certificate
    let intermediate_cert_pem = match fs::read_to_string(&intermediate_cert_path) {
        Ok(content) => content,
        Err(e) => {
            tracing::error!("Failed to read intermediate CA certificate: {}", e);
            return end_entity_cert_pem.to_string();
        }
    };
    
    // Build certificate chain: end entity certificate first, then intermediate CA certificate
    let mut chain = String::new();
    chain.push_str(end_entity_cert_pem);
    
    // Ensure there's a newline between certificates
    if !end_entity_cert_pem.ends_with('\n') {
        chain.push('\n');
    }
    
    chain.push_str(&intermediate_cert_pem);
    
    tracing::debug!("Built certificate chain with 2 certificates (end entity + intermediate CA)");
    
    chain
}

/// Convert database record to API response with certificate chain
fn convert_record_to_response(record: CertificateRecord, intermediate_ca_path: &str) -> CertificateResponse {
    // Build certificate chain dynamically from stored end entity certificate
    let certificate_chain = build_certificate_chain(&record.certificate_pem, intermediate_ca_path);
    
    CertificateResponse {
        certificate_id: Uuid::parse_str(&record.certificate_id).unwrap_or_else(|_| Uuid::new_v4()),
        certificate_pem: certificate_chain,
        private_key_pem: record.private_key_pem,
        serial_number: record.serial_number,
        subject: record.subject_dn,
        issuer: record.issuer_dn,
        not_before: chrono::DateTime::<chrono::Utc>::from_timestamp(record.not_before, 0).unwrap_or_default(),
        not_after: chrono::DateTime::<chrono::Utc>::from_timestamp(record.not_after, 0).unwrap_or_default(),
        status: record.status,
        created_at: chrono::DateTime::<chrono::Utc>::from_timestamp(record.created_at, 0).unwrap_or_default(),
    }
}

/// Renew an existing certificate
#[utoipa::path(
    post,
    path = "/renew",
    request_body = RenewalRequest,
    responses(
        (status = 200, description = "Certificate renewed successfully", body = CertificateResponse),
        (status = 404, description = "Original certificate not found"),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Certificate"
)]
pub async fn renew_certificate(
    State(app_state): State<AppState>,
    Json(request): Json<RenewalRequest>,
) -> Result<Json<CertificateResponse>> {
    use crate::certificate::{CertificateSigner, CertificateRequest as SignerRequest};
    
    tracing::info!("Certificate renewal requested for ID: {}", request.certificate_id);
    
    // Get the original certificate from database
    let db = get_db();
    let cert_service = CertificateService::new(db.clone());
    
    let original_cert = cert_service
        .get_certificate(&request.certificate_id.to_string())
        .await?
        .ok_or_else(|| AppError::NotFound("Original certificate not found".to_string()))?;
    
    // Check if the certificate is active (cannot renew revoked certificates)
    if !matches!(original_cert.status, crate::models::certificate::CertificateStatus::Active) {
        return Err(AppError::BadRequest("Cannot renew revoked or expired certificate".to_string()));
    }
    
    // Get PKI configuration
    let pki_manager = app_state.pki_manager.read().await;
    let config = pki_manager.config.clone();
    drop(pki_manager);
    
    // Create certificate signer
    let signer = CertificateSigner::new(config);
    
    // Extract username from the original certificate's common name
    let username = original_cert.common_name;
    
    // Sign the renewed certificate
    let issued_cert = signer.renew_certificate(&username, request.validity_days).await?;
    
    // Mark the old certificate as superseded
    cert_service.supersede_certificate(&original_cert.certificate_id).await?;
    
    // Store the new certificate in database
    let certificate_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp();
    
    let new_cert_record = CertificateRecord {
        id: None,
        certificate_id: certificate_id.to_string(),
        user_id: original_cert.user_id, // Keep same user ID
        serial_number: issued_cert.serial_number.clone(),
        common_name: username.clone(),
        organization: original_cert.organization,
        organizational_unit: original_cert.organizational_unit,
        country: original_cert.country,
        state: original_cert.state,
        locality: original_cert.locality,
        email: original_cert.email,
        certificate_pem: issued_cert.certificate_pem.clone(),
        private_key_pem: None, // Don't return private key for renewal
        key_algorithm: issued_cert.key_algorithm.clone(),
        key_size: issued_cert.key_size,
        subject_dn: issued_cert.subject.clone(),
        issuer_dn: issued_cert.issuer.clone(),
        not_before: issued_cert.not_before.timestamp(),
        not_after: issued_cert.not_after.timestamp(),
        status: crate::models::certificate::CertificateStatus::Active,
        created_at: now,
        revoked_at: None,
        revocation_reason: None,
        revocation_comment: None,
    };
    
    let stored_cert = cert_service.store_certificate(new_cert_record).await?;
    
    tracing::info!("Certificate renewed successfully for user: {}, new ID: {}", username, certificate_id);
    
    // Convert to response and include the private key from renewed certificate
    let pki_manager = app_state.pki_manager.read().await;
    let intermediate_ca_path = &pki_manager.config.intermediate_ca_path;
    let mut response = convert_record_to_response(stored_cert, intermediate_ca_path);
    response.private_key_pem = Some(issued_cert.private_key_pem);
    
    Ok(Json(response))
}
