use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

use crate::{
    db::capsule,
    error::{AppError, Result},
    models::capsule::CapsuleRecord,
};

/// Request body for creating a capsule
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CreateCapsuleRequest {
    pub owner_id: String,
    pub capsule_data: Value,
}

/// Response for capsule operations
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CapsuleResponse {
    pub success: bool,
    pub data: Option<CapsuleRecord>,
    pub message: Option<String>,
}

/// Response for multiple capsules
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct CapsulesListResponse {
    pub success: bool,
    pub data: Vec<CapsuleRecord>,
    pub total: usize,
    pub message: Option<String>,
}

/// Query parameters for searching capsules
#[derive(Debug, Deserialize, IntoParams)]
pub struct SearchParams {
    pub owner_id: Option<String>,
    pub content_type: Option<String>,
    pub stage: Option<String>,
}

/// Create a new capsule
#[utoipa::path(
    post,
    path = "/capsule",
    request_body = CreateCapsuleRequest,
    responses(
        (status = 201, description = "Capsule created successfully", body = CapsuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error"),
    ),
    tag = "Capsule"
)]
pub async fn create_capsule(
    Json(payload): Json<CreateCapsuleRequest>,
) -> Result<(StatusCode, Json<CapsuleResponse>)> {
    // Extract capsule information from the provided JSON data
    let capsule_record = CapsuleRecord::from_json(payload.capsule_data.clone(), payload.owner_id)
        .ok_or_else(|| AppError::BadRequest("Invalid capsule data format".into()))?;

    // Create the capsule in the database
    match capsule::create_capsule(capsule_record).await {
        Ok(created_capsule) => Ok((
            StatusCode::CREATED,
            Json(CapsuleResponse {
                success: true,
                data: Some(created_capsule),
                message: Some("Capsule created successfully".to_string()),
            }),
        )),
        Err(e) => {
            tracing::error!("Failed to create capsule: {:?}", e);
            Err(AppError::Internal(format!("Failed to create capsule: {}", e)))
        }
    }
}

/// Get a capsule by ID
#[utoipa::path(
    get,
    path = "/capsule/{id}",
    params(
        ("id" = String, Path, description = "Capsule ID")
    ),
    responses(
        (status = 200, description = "Capsule found", body = CapsuleResponse),
        (status = 404, description = "Capsule not found"),
        (status = 500, description = "Internal server error"),
    ),
    tag = "Capsule"
)]
pub async fn get_capsule_by_id(Path(id): Path<String>) -> Result<Json<CapsuleResponse>> {
    match capsule::get_capsule_by_id(&id).await {
        Ok(Some(capsule_data)) => Ok(Json(CapsuleResponse {
            success: true,
            data: Some(capsule_data),
            message: None,
        })),
        Ok(None) => Ok(Json(CapsuleResponse {
            success: false,
            data: None,
            message: Some(format!("Capsule with ID {} not found", id)),
        })),
        Err(e) => {
            tracing::error!("Failed to get capsule: {:?}", e);
            Err(AppError::Internal(format!("Failed to get capsule: {}", e)))
        }
    }
}

/// Get capsules by owner ID
#[utoipa::path(
    get,
    path = "/capsule/owner/{owner_id}",
    params(
        ("owner_id" = String, Path, description = "Owner ID")
    ),
    responses(
        (status = 200, description = "Capsules found", body = CapsulesListResponse),
        (status = 500, description = "Internal server error"),
    ),
    tag = "Capsule"
)]
pub async fn get_capsules_by_owner(
    Path(owner_id): Path<String>,
) -> Result<Json<CapsulesListResponse>> {
    match capsule::get_capsules_by_owner(&owner_id).await {
        Ok(capsules) => {
            let total = capsules.len();
            Ok(Json(CapsulesListResponse {
                success: true,
                data: capsules,
                total,
                message: None,
            }))
        }
        Err(e) => {
            tracing::error!("Failed to get capsules by owner: {:?}", e);
            Err(AppError::Internal(format!(
                "Failed to get capsules by owner: {}",
                e
            )))
        }
    }
}

/// Search capsules with filters
#[utoipa::path(
    get,
    path = "/capsule/search",
    params(
        SearchParams
    ),
    responses(
        (status = 200, description = "Search results", body = CapsulesListResponse),
        (status = 500, description = "Internal server error"),
    ),
    tag = "Capsule"
)]
pub async fn search_capsules(
    Query(params): Query<SearchParams>,
) -> Result<Json<CapsulesListResponse>> {
    match capsule::search_capsules(
        params.owner_id.as_deref(),
        params.content_type.as_deref(),
        params.stage.as_deref(),
    )
    .await
    {
        Ok(capsules) => {
            let total = capsules.len();
            Ok(Json(CapsulesListResponse {
                success: true,
                data: capsules,
                total,
                message: None,
            }))
        }
        Err(e) => {
            tracing::error!("Failed to search capsules: {:?}", e);
            Err(AppError::Internal(format!("Failed to search capsules: {}", e)))
        }
    }
}