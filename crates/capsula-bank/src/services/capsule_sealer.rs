//! 胶囊封装编排服务
//!
//! 协调文件上传、文本提取、元数据生成、BNF 解析和胶囊封装的完整流程

use std::{path::Path, sync::Arc};

use capsula_core::Capsule;

use super::{
    BnfParser, MetadataGenerator, ServiceError, ServiceResult, StorageProvider, TextExtractor,
};

/// 封装请求参数
#[derive(Debug, Clone)]
pub struct SealRequest {
    /// 文件路径
    pub file_path: String,
    /// MIME 类型（可选）
    pub mime_type: Option<String>,
    /// 所有者 ID
    pub owner_id: String,
    /// 内容类型（如 "medical.blood_test"）
    pub content_type: String,
    /// 策略 URI
    pub policy_uri: String,
    /// 权限列表
    pub permissions: Vec<String>,
    /// 创建者（可选）
    pub creator: Option<String>,
}

/// 封装响应
#[derive(Debug, Clone)]
pub struct SealResponse {
    /// Cap0 胶囊 ID（外部存储）
    pub cap0_id: String,
    /// Cap1 胶囊 ID（内联存储）
    pub cap1_id: String,
    /// Cap0 胶囊（包含外部存储引用）
    pub cap0_capsule: Capsule,
    /// Cap1 胶囊（包含元数据和 BNF）
    pub cap1_capsule: Capsule,
    /// 外部存储 URL
    pub storage_url: String,
}

/// 胶囊封装编排器
///
/// 协调多个服务完成从文件上传到胶囊创建的完整流程
pub struct CapsuleSealer {
    /// 文本提取器
    text_extractor: Arc<dyn TextExtractor>,
    /// BNF 解析器
    bnf_parser: Arc<dyn BnfParser>,
    /// 元数据生成器
    metadata_generator: Arc<MetadataGenerator>,
    /// 存储提供者
    storage_provider: Arc<dyn StorageProvider>,
}

impl CapsuleSealer {
    /// 创建新的胶囊封装编排器
    pub fn new(
        text_extractor: Arc<dyn TextExtractor>,
        bnf_parser: Arc<dyn BnfParser>,
        metadata_generator: Arc<MetadataGenerator>,
        storage_provider: Arc<dyn StorageProvider>,
    ) -> Self {
        Self {
            text_extractor,
            bnf_parser,
            metadata_generator,
            storage_provider,
        }
    }

    /// 封装胶囊的完整流程
    ///
    /// # 流程
    /// 1. 提取文本内容
    /// 2. 解析 BNF 结构
    /// 3. 生成元数据
    /// 4. 上传原始文件到存储
    /// 5. 创建 Cap0（外部存储引用）
    /// 6. 创建 Cap1（内联元数据和 BNF）
    ///
    /// # 参数
    /// - `request`: 封装请求参数
    ///
    /// # 返回
    /// 封装响应，包含 Cap0 和 Cap1
    pub async fn seal(&self, request: SealRequest) -> ServiceResult<SealResponse> {
        let file_path = Path::new(&request.file_path);

        // 验证文件存在
        if !file_path.exists() {
            return Err(ServiceError::Validation(format!(
                "File not found: {}",
                request.file_path
            )));
        }

        // 1. 提取文本内容
        tracing::info!("Extracting text from file: {}", request.file_path);
        let text_content = self
            .text_extractor
            .extract(file_path, request.mime_type.as_deref())
            .await
            .map_err(|e| ServiceError::TextExtraction(e.to_string()))?;

        // 2. 解析 BNF 结构
        tracing::info!("Parsing BNF structure");
        let bnf_data = self
            .bnf_parser
            .parse(&text_content)
            .await
            .map_err(|e| ServiceError::BnfParse(e.to_string()))?;

        // 3. 生成元数据
        tracing::info!("Generating metadata");
        let metadata = self
            .metadata_generator
            .generate(file_path, request.mime_type.clone())
            .await
            .map_err(|e| ServiceError::MetadataGeneration(e.to_string()))?;

        // 4. 上传原始文件到存储
        tracing::info!("Uploading file to storage");
        let file_content = tokio::fs::read(file_path)
            .await
            .map_err(|e| ServiceError::Io(e))?;

        // 生成存储键（使用所有者 ID 和文件名）
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ServiceError::Validation("Invalid filename".to_string()))?;

        let storage_key = format!("{}/{}", request.owner_id, filename);
        let storage_url = self
            .storage_provider
            .store(&storage_key, &file_content)
            .await
            .map_err(|e| ServiceError::Storage(e.to_string()))?;

        // 5. 创建 Cap0（外部存储引用）
        tracing::info!("Creating Cap0 capsule with external storage reference");
        let cap0_capsule = self.create_cap0(
            &storage_url,
            &request.content_type,
            &request.policy_uri,
            &request.permissions,
            request.creator.as_deref(),
        )?;

        let cap0_id = cap0_capsule.header.id.clone();

        // 6. 创建 Cap1（内联元数据和 BNF）
        tracing::info!("Creating Cap1 capsule with metadata and BNF");
        let metadata_bytes = self
            .metadata_generator
            .to_bytes(&metadata)
            .map_err(|e| ServiceError::MetadataGeneration(e.to_string()))?;

        let bnf_bytes = bnf_data
            .to_bytes()
            .map_err(|e| ServiceError::BnfParse(e.to_string()))?;

        let cap1_capsule = self.create_cap1(
            &cap0_id,
            &metadata_bytes,
            &bnf_bytes,
            &request.content_type,
            &request.policy_uri,
            &request.permissions,
            request.creator.as_deref(),
        )?;

        let cap1_id = cap1_capsule.header.id.clone();

        tracing::info!(
            "Successfully sealed capsules: cap0={}, cap1={}",
            cap0_id,
            cap1_id
        );

        Ok(SealResponse {
            cap0_id,
            cap1_id,
            cap0_capsule,
            cap1_capsule,
            storage_url,
        })
    }

    /// 创建 Cap0 胶囊（外部存储）
    ///
    /// TODO: 实现完整的 Cap0 创建逻辑
    /// 目前返回一个占位实现
    fn create_cap0(
        &self,
        _external_url: &str,
        _content_type: &str,
        _policy_uri: &str,
        _permissions: &[String],
        _creator: Option<&str>,
    ) -> ServiceResult<Capsule> {
        // TODO: 实现完整的 Cap0 创建
        // Cap0::seal 需要实际的文件路径和加密输出路径
        // 目前先返回一个错误，因为需要重新设计这部分逻辑

        Err(ServiceError::Unsupported(
            "Cap0 creation not yet implemented - requires file path based sealing".to_string(),
        ))
    }

    /// 创建 Cap1 胶囊（内联存储）
    fn create_cap1(
        &self,
        cap0_id: &str,
        meta_data: &[u8],
        bnf_extract_data: &[u8],
        content_type: &str,
        policy_uri: &str,
        permissions: &[String],
        creator: Option<&str>,
    ) -> ServiceResult<Capsule> {
        use crate::utils::capsula_util;

        capsula_util::create_cap1_capsule(
            cap0_id.to_string(),
            meta_data,
            bnf_extract_data,
            content_type.to_string(),
            policy_uri.to_string(),
            permissions.to_vec(),
            creator.map(|s| s.to_string()),
        )
        .map_err(|e| ServiceError::CapsuleSealing(format!("Failed to create Cap1: {}", e)))
    }
}

// TODO: 添加集成测试
// 当前测试被移除，因为：
// 1. create_cap0 方法尚未完全实现（需要重新设计文件路径处理）
// 2. 需要完整的 Cap0 封装逻辑
// 3. 需要真实的存储后端来测试
//
// 建议在 tests/ 目录下创建集成测试，使用：
// - 真实的文件系统或临时存储
// - 模拟的 S3 存储
// - 测试用的系统密钥
