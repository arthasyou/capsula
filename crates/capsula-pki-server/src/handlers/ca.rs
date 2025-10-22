//! Certificate Authority management handlers

use axum::{extract::State, response::Json};

use crate::{
    error::AppError,
    models::ca::{CaInfo, CaStatus},
    state::AppState,
};

/// Get CA status and information
#[utoipa::path(
    get,
    path = "/status",
    responses(
        (status = 200, description = "CA status retrieved successfully", body = CaStatus),
        (status = 500, description = "Internal server error")
    ),
    tag = "CA"
)]
pub async fn get_ca_status(State(app_state): State<AppState>) -> Result<Json<CaStatus>, AppError> {
    tracing::info!("Getting CA status");

    let pki_manager = app_state.pki_manager.read().await;
    let pki_status = pki_manager.get_ca_status();

    let ca_info = if pki_status.pki_ready {
        if let Some(root_cert) = pki_manager.get_root_ca_cert() {
            Some(CaInfo {
                ca_certificate_pem: root_cert.clone(),
                subject: "CN=Capsula Root CA, O=Capsula PKI, OU=Root CA, L=San Francisco, \
                          ST=California, C=US"
                    .to_string(),
                serial_number: "1".to_string(),
                not_before: chrono::Utc::now() - chrono::Duration::days(1),
                not_after: chrono::Utc::now() + chrono::Duration::days(7300), // 20 years
                key_algorithm: "RSA".to_string(),
                key_size: Some(2048),
                created_at: chrono::Utc::now() - chrono::Duration::days(1),
            })
        } else {
            None
        }
    } else {
        None
    };

    let status = CaStatus {
        initialized: pki_status.pki_ready,
        ca_info,
        certificates_issued: 0,  // TODO: Get from database
        active_certificates: 0,  // TODO: Get from database
        revoked_certificates: 0, // TODO: Get from database
    };

    Ok(Json(status))
}

/// Get CA certificate
#[utoipa::path(
    get,
    path = "/certificate",
    responses(
        (status = 200, description = "CA certificate retrieved successfully", body = CaInfo),
        (status = 404, description = "CA not initialized"),
        (status = 500, description = "Internal server error")
    ),
    tag = "CA"
)]
pub async fn get_ca_certificate(
    State(app_state): State<AppState>,
) -> Result<Json<CaInfo>, AppError> {
    tracing::info!("Getting CA certificate");

    let pki_manager = app_state.pki_manager.read().await;

    if let Some(root_cert) = pki_manager.get_root_ca_cert() {
        let ca_info = CaInfo {
            ca_certificate_pem: root_cert.clone(),
            subject: "CN=Capsula Root CA, O=Capsula PKI, OU=Root CA, L=San Francisco, \
                      ST=California, C=US"
                .to_string(),
            serial_number: "1".to_string(),
            not_before: chrono::Utc::now() - chrono::Duration::days(1),
            not_after: chrono::Utc::now() + chrono::Duration::days(7300), // 20 years
            key_algorithm: "RSA".to_string(),
            key_size: Some(2048),
            created_at: chrono::Utc::now() - chrono::Duration::days(1),
        };

        Ok(Json(ca_info))
    } else {
        Err(AppError::NotFound(
            "CA not initialized or certificate not found".to_string(),
        ))
    }
}

/// Get Root CA certificate
#[utoipa::path(
    get,
    path = "/root",
    responses(
        (status = 200, description = "Root CA certificate retrieved successfully", body = CaInfo),
        (status = 404, description = "Root CA not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "CA"
)]
pub async fn get_root_ca(State(app_state): State<AppState>) -> Result<Json<CaInfo>, AppError> {
    tracing::info!("Getting Root CA certificate");

    let pki_manager = app_state.pki_manager.read().await;

    if let Some(root_cert) = pki_manager.get_root_ca_cert() {
        let ca_info = CaInfo {
            ca_certificate_pem: root_cert.clone(),
            subject: "CN=Capsula Root CA, O=Capsula PKI, OU=Root CA, L=San Francisco, \
                      ST=California, C=US"
                .to_string(),
            serial_number: "1".to_string(),
            not_before: chrono::Utc::now() - chrono::Duration::days(1),
            not_after: chrono::Utc::now() + chrono::Duration::days(7300), // 20 years
            key_algorithm: "RSA".to_string(),
            key_size: Some(2048),
            created_at: chrono::Utc::now() - chrono::Duration::days(1),
        };

        Ok(Json(ca_info))
    } else {
        Err(AppError::NotFound(
            "Root CA not found or PKI not initialized".to_string(),
        ))
    }
}

/// Get Intermediate CA certificate
#[utoipa::path(
    get,
    path = "/intermediate",
    responses(
        (status = 200, description = "Intermediate CA certificate retrieved successfully", body = CaInfo),
        (status = 404, description = "Intermediate CA not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "CA"
)]
pub async fn get_intermediate_ca(
    State(app_state): State<AppState>,
) -> Result<Json<CaInfo>, AppError> {
    tracing::info!("Getting Intermediate CA certificate");

    let pki_manager = app_state.pki_manager.read().await;

    if let Some(intermediate_cert) = pki_manager.get_intermediate_ca_cert() {
        let ca_info = CaInfo {
            ca_certificate_pem: intermediate_cert.clone(),
            subject: "CN=Capsula Intermediate CA, O=Capsula PKI, OU=Intermediate CA, L=San \
                      Francisco, ST=California, C=US"
                .to_string(),
            serial_number: "2".to_string(),
            not_before: chrono::Utc::now() - chrono::Duration::days(1),
            not_after: chrono::Utc::now() + chrono::Duration::days(3650), // 10 years
            key_algorithm: "RSA".to_string(),
            key_size: Some(2048),
            created_at: chrono::Utc::now() - chrono::Duration::days(1),
        };

        Ok(Json(ca_info))
    } else {
        Err(AppError::NotFound(
            "Intermediate CA not found or PKI not initialized".to_string(),
        ))
    }
}
