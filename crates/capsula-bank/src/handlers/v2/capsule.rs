use axum::{extract::Multipart, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::{
    error::{AppError, Result},
    services::{
        CapsuleSealer, LocalStorage, MetadataGenerator, SealRequest, SimpleBnfParser,
        SimpleTextExtractor, StorageProvider, TempFileGuard,
    },
};

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
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadCapsuleResponse>)> {
    // TODO: 从配置文件加载这些设置
    let temp_dir = "storage/temp";
    let storage_root_dir = "storage/files";
    let storage_url_prefix = "http://localhost:16022/files";
    let max_file_size = 100 * 1024 * 1024; // 100 MB
    let allowed_mime_types: Vec<String> = vec![]; // 空表示允许所有
    // 解析 multipart 表单数据
    let mut file_data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut mime_type: Option<String> = None;
    let mut owner_id: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut creator: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Failed to read multipart field: {}", e)))?
    {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "file" => {
                filename = field.file_name().map(|s| s.to_string());
                mime_type = field.content_type().map(|s| s.to_string());
                file_data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("Failed to read file: {}", e)))?
                        .to_vec(),
                );
            }
            "owner_id" => {
                owner_id = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("Failed to read owner_id: {}", e)))?,
                );
            }
            "content_type" => {
                content_type = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("Failed to read content_type: {}", e)))?,
                );
            }
            "creator" => {
                creator = Some(
                    field
                        .text()
                        .await
                        .map_err(|e| AppError::BadRequest(format!("Failed to read creator: {}", e)))?,
                );
            }
            _ => {
                // 忽略未知字段
            }
        }
    }

    // 验证必需字段
    let file_data = file_data.ok_or_else(|| AppError::BadRequest("Missing file".to_string()))?;
    let filename = filename.ok_or_else(|| AppError::BadRequest("Missing filename".to_string()))?;
    let owner_id =
        owner_id.ok_or_else(|| AppError::BadRequest("Missing owner_id".to_string()))?;
    let content_type =
        content_type.ok_or_else(|| AppError::BadRequest("Missing content_type".to_string()))?;

    // 验证文件大小
    if file_data.len() > max_file_size {
        return Err(AppError::BadRequest(format!(
            "File size exceeds limit of {} bytes",
            max_file_size
        )));
    }

    // 验证 MIME 类型（如果配置了允许列表）
    if !allowed_mime_types.is_empty() {
        if let Some(ref mime) = mime_type {
            if !allowed_mime_types.contains(mime) {
                return Err(AppError::BadRequest(format!(
                    "MIME type {} is not allowed",
                    mime
                )));
            }
        }
    }

    // 保存文件到临时目录
    tokio::fs::create_dir_all(temp_dir)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create temp dir: {}", e)))?;

    let temp_file_path = format!("{}/{}", temp_dir, filename);
    let _temp_guard = TempFileGuard::new(&temp_file_path);

    tokio::fs::write(&temp_file_path, &file_data)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to write temp file: {}", e)))?;

    // 创建服务实例
    let text_extractor = Arc::new(SimpleTextExtractor::new());
    let bnf_parser = Arc::new(SimpleBnfParser::new());
    let metadata_generator = Arc::new(MetadataGenerator::new());
    let storage_provider: Arc<dyn StorageProvider> = Arc::new(
        LocalStorage::new(storage_root_dir, storage_url_prefix.to_string())
            .map_err(|e| AppError::Internal(format!("Failed to create storage: {}", e)))?,
    );

    let sealer = CapsuleSealer::new(
        text_extractor,
        bnf_parser,
        metadata_generator,
        storage_provider,
    );

    // 创建封装请求
    let seal_request = SealRequest {
        file_path: temp_file_path.clone(),
        mime_type,
        owner_id: owner_id.clone(),
        content_type: content_type.clone(),
        policy_uri: "https://example.com/policy".to_string(), // TODO: 从配置或请求中获取
        permissions: vec!["read".to_string()], // TODO: 从请求中获取
        creator,
    };

    // 执行封装
    let seal_response = sealer
        .seal(seal_request)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to seal capsule: {}", e)))?;

    // TODO: 将 Cap0 和 Cap1 保存到数据库
    tracing::info!(
        "Created capsules: cap0_id={}, cap1_id={}",
        seal_response.cap0_id,
        seal_response.cap1_id
    );

    Ok((
        StatusCode::CREATED,
        Json(UploadCapsuleResponse {
            success: true,
            capsule_id: Some(seal_response.cap1_id.clone()),
            cap0_id: Some(seal_response.cap0_id),
            message: Some("Capsule created successfully".to_string()),
        }),
    ))
}
