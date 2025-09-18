//! Data capsule encapsulation and decapsulation handlers

use axum::{http::StatusCode, response::Json};
use base64::{engine::general_purpose, Engine as _};
use capsula_core::Capsula1;
use capsula_key::{ExportablePrivateKey, Key, P256Key, RsaKey};
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    error::AppError,
    models::capsule::{
        CapsuleVerifyRequest, CapsuleVerifyResponse, DecapsulateRequest, DecapsulateResponse,
        EncapsulateRequest, EncapsulateResponse,
    },
};

/// Encapsulate data into a capsule
#[utoipa::path(
    post,
    path = "/api/v1/capsule/encapsulate",
    request_body = EncapsulateRequest,
    responses(
        (status = 201, description = "Data encapsulated successfully", body = EncapsulateResponse),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "capsule"
)]
pub async fn encapsulate_data(
    Json(request): Json<EncapsulateRequest>,
) -> Result<(StatusCode, Json<EncapsulateResponse>), AppError> {
    tracing::info!("Encapsulating data of type: {}", request.data_type);

    match simple_encapsulate_data(&request).await {
        Ok(response) => Ok((StatusCode::CREATED, Json(response))),
        Err(e) => {
            tracing::error!("Encapsulation failed: {}", e);
            Err(AppError::Internal("Data encapsulation failed".to_string()))
        }
    }
}

/// Simple data encapsulation implementation
async fn simple_encapsulate_data(
    request: &EncapsulateRequest,
) -> Result<EncapsulateResponse, Box<dyn std::error::Error>> {
    tracing::info!("Starting data encapsulation process");

    // 1. Decode base64 data
    let data = general_purpose::STANDARD.decode(&request.data)?;

    // 2. Generate producer key (in real scenario, this would be loaded from keystore)
    let producer_key = RsaKey::generate_2048()?; // Simplified to just use RSA for now

    // 3. Generate recipient keys (simplified - in real scenario, these would be provided)
    let recipient_key = RsaKey::generate_2048()?;
    let recipients = vec![(request.recipient_id.clone(), &recipient_key as &dyn Key)];

    // 4. Create capsule using CapsulaApi
    let capsule = CapsulaApi::encapsulate_simple(
        data,
        request.data_type.clone(),
        request.producer.clone(),
        request.owner.clone(),
        &producer_key,
        &recipients,
    )?;

    // 5. Serialize capsule to JSON
    let capsule_json = serde_json::to_string(&capsule)?;
    let capsule_base64 = general_purpose::STANDARD.encode(capsule_json);

    // For demo purposes, serialize the private key using PKCS#8 DER format
    let recipient_key_der = recipient_key.to_pkcs8_der()?;
    let recipient_key_b64 = general_purpose::STANDARD.encode(recipient_key_der);

    tracing::info!("Data encapsulation completed successfully");
    Ok(EncapsulateResponse {
        capsule_id: uuid::Uuid::new_v4().to_string(),
        capsule_data: capsule_base64,
        data_type: request.data_type.clone(),
        producer: request.producer.clone(),
        owner: request.owner.clone(),
        created_at: chrono::Utc::now(),
        // Store private key for demo purposes (in real scenario, this would be managed securely)
        recipient_private_key: recipient_key_b64,
    })
}

/// Decapsulate data from a capsule
#[utoipa::path(
    post,
    path = "/api/v1/capsule/decapsulate",
    request_body = DecapsulateRequest,
    responses(
        (status = 200, description = "Data decapsulated successfully", body = DecapsulateResponse),
        (status = 400, description = "Bad request or invalid capsule"),
        (status = 500, description = "Internal server error")
    ),
    tag = "capsule"
)]
pub async fn decapsulate_data(
    Json(request): Json<DecapsulateRequest>,
) -> Result<Json<DecapsulateResponse>, AppError> {
    tracing::info!("Decapsulating data for user: {}", request.user_id);

    match simple_decapsulate_data(&request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            tracing::error!("Decapsulation failed: {}", e);
            Err(AppError::Internal("Data decapsulation failed".to_string()))
        }
    }
}

/// Simple data decapsulation implementation
async fn simple_decapsulate_data(
    request: &DecapsulateRequest,
) -> Result<DecapsulateResponse, Box<dyn std::error::Error>> {
    tracing::info!("Starting data decapsulation process");

    // 1. Decode capsule data
    tracing::debug!("Step 1: Decoding capsule data");
    let capsule_json = general_purpose::STANDARD
        .decode(&request.capsule_data)
        .map_err(|e| {
            tracing::error!("Failed to decode base64 capsule data: {}", e);
            e
        })?;
    let capsule_str = String::from_utf8(capsule_json).map_err(|e| {
        tracing::error!("Failed to convert capsule data to UTF8: {}", e);
        e
    })?;
    let capsule: Capsula1 = serde_json::from_str(&capsule_str).map_err(|e| {
        tracing::error!("Failed to parse capsule JSON: {}", e);
        e
    })?;

    // 2. Decode private key (in real scenario, this would be loaded from secure storage)
    tracing::debug!("Step 2: Decoding private key");
    let private_key_der = general_purpose::STANDARD
        .decode(&request.private_key)
        .map_err(|e| {
            tracing::error!("Failed to decode base64 private key: {}", e);
            e
        })?;
    let private_key = RsaKey::from_pkcs8_der(&private_key_der).map_err(|e| {
        tracing::error!("Failed to parse RSA private key: {}", e);
        e
    })?;

    // 3. Decapsulate using CapsulaApi
    tracing::debug!("Step 3: Calling CapsulaApi::decapsulate_simple_rsa");
    let result = CapsulaApi::decapsulate_simple_rsa(
        &capsule,
        private_key,
        request.user_id.clone(),
        None, // No producer public key for now
    )
    .map_err(|e| {
        tracing::error!("Failed to decapsulate data: {}", e);
        e
    })?;

    // 4. Encode decrypted data
    tracing::debug!("Step 4: Encoding decrypted data");
    let data_base64 = general_purpose::STANDARD.encode(&result.data);

    tracing::info!("Data decapsulation completed successfully");
    Ok(DecapsulateResponse {
        data: data_base64,
        data_type: capsule.header.type_,
        producer: capsule.meta.producer,
        owner: capsule.meta.owner,
        verification_passed: result.verification.signature_valid
            && result.verification.policy_valid
            && result.verification.time_valid,
        decrypted_at: chrono::Utc::now(),
    })
}

/// Verify capsule without decapsulating
#[utoipa::path(
    post,
    path = "/api/v1/capsule/verify",
    request_body = CapsuleVerifyRequest,
    responses(
        (status = 200, description = "Capsule verified", body = CapsuleVerifyResponse),
        (status = 400, description = "Bad request or invalid capsule"),
        (status = 500, description = "Internal server error")
    ),
    tag = "capsule"
)]
pub async fn verify_capsule(
    Json(request): Json<CapsuleVerifyRequest>,
) -> Result<Json<CapsuleVerifyResponse>, AppError> {
    tracing::info!("Verifying capsule");

    match simple_verify_capsule(&request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            tracing::error!("Capsule verification failed: {}", e);
            Err(AppError::Internal(
                "Capsule verification failed".to_string(),
            ))
        }
    }
}

/// Simple capsule verification implementation
async fn simple_verify_capsule(
    request: &CapsuleVerifyRequest,
) -> Result<CapsuleVerifyResponse, Box<dyn std::error::Error>> {
    tracing::info!("Starting capsule verification");

    // 1. Decode capsule data
    let capsule_json = general_purpose::STANDARD.decode(&request.capsule_data)?;
    let capsule_str = String::from_utf8(capsule_json)?;
    let capsule: Capsula1 = serde_json::from_str(&capsule_str)?;

    // 2. Verify capsule structure and basic validation
    let verification_result = CapsulaApi::verify_capsule(
        &capsule,
        None, // No producer public key for now
        request.user_id.clone(),
    )?;

    tracing::info!("Capsule verification completed");
    Ok(CapsuleVerifyResponse {
        valid: verification_result,
        data_type: capsule.header.type_,
        producer: capsule.meta.producer,
        owner: capsule.meta.owner,
        created_at: chrono::Utc::now(), /* Placeholder - actual creation time would be from
                                         * capsule metadata */
        expires_at: None, // Simplified for now
        verified_at: chrono::Utc::now(),
    })
}

pub fn create_router() -> OpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(encapsulate_data))
        .routes(routes!(decapsulate_data))
        .routes(routes!(verify_capsule))
}
