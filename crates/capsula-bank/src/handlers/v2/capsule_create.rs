//! V2 胶囊创建 API（外部化方案）
//!
//! 客户端负责：
//! 1. 上传文件到 S3
//! 2. 使用 LLM 提取结构化数据
//! 3. 调用此 API 创建胶囊
//!
//! Bank 负责：
//! 1. 验证数据完整性
//! 2. 封装 Cap0 + Cap1
//! 3. 保存到数据库

use axum::{http::StatusCode, response::Json};
use chrono::Utc;

use crate::{
    error::{AppError, Result},
    models::capsule_request::{CreateCapsuleRequest, CreateCapsuleResponse},
    utils::capsula_util,
};

/// 创建胶囊（外部化方案）
///
/// # 流程
/// 1. 验证请求数据
/// 2. （可选）验证文件哈希
/// 3. 创建 Cap1 胶囊（内联元数据和结构化数据）
/// 4. 保存到数据库
/// 5. 返回胶囊 ID
///
/// # 注意
/// - 客户端需要先上传文件到 S3
/// - 客户端需要提供元数据和结构化数据
/// - Bank 只负责封装和存储
#[utoipa::path(
    post,
    path = "/create",
    request_body = CreateCapsuleRequest,
    responses(
        (status = 201, description = "Capsule created successfully", body = CreateCapsuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error"),
    ),
    tag = "Capsule V2"
)]
pub async fn create_capsule(
    Json(request): Json<CreateCapsuleRequest>,
) -> Result<(StatusCode, Json<CreateCapsuleResponse>)> {
    // 验证必需字段
    if request.cap0.external_url.is_empty() {
        return Err(AppError::BadRequest("Missing external_url".to_string()));
    }

    if request.cap1.metadata.filename.is_empty() {
        return Err(AppError::BadRequest("Missing filename".to_string()));
    }

    if request.owner_id.is_empty() {
        return Err(AppError::BadRequest("Missing owner_id".to_string()));
    }

    if request.content_type.is_empty() {
        return Err(AppError::BadRequest("Missing content_type".to_string()));
    }

    // TODO: 验证文件哈希（如果提供）
    // if let Some(ref expected_hash) = request.cap1.metadata.hash {
    //     verify_file_hash(&request.cap0.external_url, expected_hash).await?;
    // }

    // 生成 Cap0 ID（占位，实际应该从 Cap0 封装中获取）
    let cap0_id = capsula_crypto::generate_id("cid");

    // 序列化元数据
    let metadata_bytes = serde_json::to_vec(&request.cap1.metadata)
        .map_err(|e| AppError::Internal(format!("Failed to serialize metadata: {}", e)))?;

    // 序列化结构化数据
    let structured_data_bytes = serde_json::to_vec(&request.cap1.structured_data)
        .map_err(|e| AppError::Internal(format!("Failed to serialize structured data: {}", e)))?;

    // 创建 Cap1 胶囊
    let cap1_capsule = capsula_util::create_cap1_capsule(
        cap0_id.clone(),
        &metadata_bytes,
        &structured_data_bytes,
        request.content_type.clone(),
        request.policy_uri.clone(),
        request.permissions.clone(),
        request.creator.clone(),
    )
    .map_err(|e| AppError::Internal(format!("Failed to create Cap1 capsule: {}", e)))?;

    let cap1_id = cap1_capsule.header.id.clone();

    // TODO: 保存到数据库
    // - Cap0 引用（external_url）
    // - Cap1 胶囊（完整数据）
    // - 索引（owner_id, content_type, created_at）

    tracing::info!(
        "Created capsule: cap0_id={}, cap1_id={}, owner={}",
        cap0_id,
        cap1_id,
        request.owner_id
    );

    let now = Utc::now().timestamp();

    Ok((
        StatusCode::CREATED,
        Json(CreateCapsuleResponse {
            success: true,
            cap0_id,
            cap1_id,
            storage_url: request.cap0.external_url,
            created_at: now,
            message: Some("Capsule created successfully".to_string()),
        }),
    ))
}

/// TODO: 验证文件哈希
///
/// 从 S3 下载文件头部，计算哈希值并验证
#[allow(dead_code)]
async fn verify_file_hash(_url: &str, _expected_hash: &str) -> Result<()> {
    // 实现：
    // 1. 从 URL 下载文件（或只下载头部用于快速验证）
    // 2. 计算 SHA-256 哈希
    // 3. 与期望值比较
    Ok(())
}

// TODO: 添加集成测试
// 当前测试被移除，因为：
// 1. 需要数据库集成才能完整测试
// 2. Cap0Data 结构已更新，包含加密字段
// 3. 需要真实的 PKI 服务器来测试完整流程
//
// 建议在 tests/ 目录下创建集成测试，使用：
// - 真实的 S3 或 MinIO
// - 模拟的 PKI 服务器
// - 测试数据库
