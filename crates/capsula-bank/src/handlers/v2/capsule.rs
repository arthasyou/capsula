use axum::{http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::Result;

/// Request body for uploading and creating a complete capsule (Cap0 + Cap1)
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UploadCapsuleRequest {
    /// Owner ID
    pub owner_id: String,

    /// Content type (e.g., "medical.blood_test")
    pub content_type: String,

    /// Optional creator information
    pub creator: Option<String>,

    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Response for capsule upload operations
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UploadCapsuleResponse {
    pub success: bool,
    pub capsule_id: Option<String>,
    pub cap0_id: Option<String>,
    pub message: Option<String>,
}

/// Upload a file and create a complete capsule (Cap0 + Cap1)
///
/// This endpoint accepts a file upload and automatically:
/// 1. Extracts text from the file (origin_text)
/// 2. Creates Cap0 with origin and origin_text
/// 3. Parses structured data (BNF extraction)
/// 4. Generates metadata
/// 5. Creates Cap1 with meta and bnf_extract
/// 6. Returns the complete Capsule
#[utoipa::path(
    post,
    path = "/upload",
    request_body(content = UploadCapsuleRequest, content_type = "multipart/form-data"),
    responses(
        (status = 201, description = "Capsule created successfully", body = UploadCapsuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error"),
    ),
    tag = "Capsule V2"
)]
pub async fn upload_and_create_capsule(
    // TODO: 实现文件上传和封装逻辑
    // 需要添加 multipart 处理
) -> Result<(StatusCode, Json<UploadCapsuleResponse>)> {
    // Placeholder implementation
    Ok((
        StatusCode::NOT_IMPLEMENTED,
        Json(UploadCapsuleResponse {
            success: false,
            capsule_id: None,
            cap0_id: None,
            message: Some("Not implemented yet".to_string()),
        }),
    ))
}
