use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;

use crate::integrity::digest::Digest;

/// 数据胶囊的状态，支持异步封装和上传流程
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapsuleState {
    /// 待上传状态：已完成加密，等待上传到存储后端
    Pending {
        /// 占位符URI，包含模板变量如 {hash}
        placeholder_uri: String,
        /// 加密后的密文数据，准备上传
        ciphertext_data: Vec<u8>,
        /// 内容哈希，用于验证和生成最终URI
        content_hash: String,
        /// 密文长度
        ciphertext_len: u64,
        /// 创建时间
        created_at: String, // RFC3339 格式
    },
    /// 上传中状态：正在上传到存储后端
    Uploading {
        /// 上传任务ID，用于跟踪上传进度
        upload_id: String,
        /// 目标URI（真实存储路径）
        target_uri: String,
        /// 上传进度 (0.0 - 1.0)
        progress: f64,
        /// 开始上传时间
        started_at: String, // RFC3339 格式
        /// 额外的上传元数据
        upload_meta: Option<UploadMeta>,
    },
    /// 完成状态：上传成功，胶囊完整可用
    Completed {
        /// 最终的存储URI
        final_uri: String,
        /// 上传完成时间
        uploaded_at: String, // RFC3339 格式
        /// 验证信息
        verification: Option<UploadVerification>,
    },
    /// 失败状态：上传失败，可重试
    Failed {
        /// 错误信息
        error: String,
        /// 错误代码
        error_code: Option<String>,
        /// 重试次数
        retry_count: u32,
        /// 最后一次失败时间
        last_attempt: String, // RFC3339 格式
        /// 是否可重试
        retryable: bool,
    },
}

/// 上传相关元数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadMeta {
    /// 存储后端类型 (S3, Local, IPFS等)
    pub backend_type: String,
    /// 存储桶或容器名称
    pub bucket: Option<String>,
    /// 额外的存储配置
    pub config: HashMap<String, String>,
}

/// 上传验证信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadVerification {
    /// 上传后的文件大小
    pub uploaded_size: u64,
    /// 存储后端返回的ETag或校验值
    pub etag: Option<String>,
    /// 完整性校验摘要
    pub integrity_digest: Option<Digest>,
}

/// 状态转换错误
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateTransitionError {
    InvalidTransition {
        from: String,
        to: String,
        reason: String,
    },
    MissingData {
        field: String,
    },
    ValidationFailed {
        reason: String,
    },
}

impl std::fmt::Display for StateTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateTransitionError::InvalidTransition { from, to, reason } => {
                write!(f, "Invalid state transition from {} to {}: {}", from, to, reason)
            }
            StateTransitionError::MissingData { field } => {
                write!(f, "Missing required data for state transition: {}", field)
            }
            StateTransitionError::ValidationFailed { reason } => {
                write!(f, "State validation failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for StateTransitionError {}

impl CapsuleState {
    /// 创建新的Pending状态
    pub fn new_pending(
        placeholder_uri: String,
        ciphertext_data: Vec<u8>,
        content_hash: String,
    ) -> Self {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();

        CapsuleState::Pending {
            placeholder_uri,
            ciphertext_len: ciphertext_data.len() as u64,
            ciphertext_data,
            content_hash,
            created_at: now,
        }
    }

    /// 转换为Uploading状态
    pub fn start_upload(
        self,
        upload_id: String,
        target_uri: String,
        upload_meta: Option<UploadMeta>,
    ) -> std::result::Result<Self, StateTransitionError> {
        match self {
            CapsuleState::Pending { .. } => {
                let now = OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap();

                Ok(CapsuleState::Uploading {
                    upload_id,
                    target_uri,
                    progress: 0.0,
                    started_at: now,
                    upload_meta,
                })
            }
            _ => Err(StateTransitionError::InvalidTransition {
                from: self.state_name(),
                to: "Uploading".to_string(),
                reason: "Can only start upload from Pending state".to_string(),
            }),
        }
    }

    /// 更新上传进度
    pub fn update_progress(&mut self, progress: f64) -> std::result::Result<(), StateTransitionError> {
        if !(0.0..=1.0).contains(&progress) {
            return Err(StateTransitionError::ValidationFailed {
                reason: format!("Progress must be between 0.0 and 1.0, got {}", progress),
            });
        }

        match self {
            CapsuleState::Uploading { progress: ref mut p, .. } => {
                *p = progress;
                Ok(())
            }
            _ => Err(StateTransitionError::InvalidTransition {
                from: self.state_name(),
                to: "Uploading (progress update)".to_string(),
                reason: "Can only update progress in Uploading state".to_string(),
            }),
        }
    }

    /// 标记为完成状态
    pub fn mark_completed(
        self,
        final_uri: String,
        verification: Option<UploadVerification>,
    ) -> std::result::Result<Self, StateTransitionError> {
        match self {
            CapsuleState::Uploading { .. } => {
                let now = OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap();

                Ok(CapsuleState::Completed {
                    final_uri,
                    uploaded_at: now,
                    verification,
                })
            }
            _ => Err(StateTransitionError::InvalidTransition {
                from: self.state_name(),
                to: "Completed".to_string(),
                reason: "Can only complete from Uploading state".to_string(),
            }),
        }
    }

    /// 标记为失败状态
    pub fn mark_failed(
        self,
        error: String,
        error_code: Option<String>,
        retryable: bool,
    ) -> std::result::Result<Self, StateTransitionError> {
        let retry_count = match &self {
            CapsuleState::Failed { retry_count, .. } => retry_count + 1,
            _ => 0,
        };

        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();

        match self {
            CapsuleState::Pending { .. } | CapsuleState::Uploading { .. } | CapsuleState::Failed { .. } => {
                Ok(CapsuleState::Failed {
                    error,
                    error_code,
                    retry_count,
                    last_attempt: now,
                    retryable,
                })
            }
            CapsuleState::Completed { .. } => Err(StateTransitionError::InvalidTransition {
                from: self.state_name(),
                to: "Failed".to_string(),
                reason: "Cannot mark completed capsule as failed".to_string(),
            }),
        }
    }

    /// 重试失败的任务，重置为Pending状态
    pub fn retry(self) -> std::result::Result<Self, StateTransitionError> {
        match self {
            CapsuleState::Failed { retryable: true, .. } => {
                // 注意：这里需要重新提供Pending状态所需的数据
                // 实际使用中，应该保存原始数据以便重试
                Err(StateTransitionError::MissingData {
                    field: "original pending data for retry".to_string(),
                })
            }
            CapsuleState::Failed { retryable: false, .. } => {
                Err(StateTransitionError::InvalidTransition {
                    from: self.state_name(),
                    to: "Pending".to_string(),
                    reason: "Failed task is not retryable".to_string(),
                })
            }
            _ => Err(StateTransitionError::InvalidTransition {
                from: self.state_name(),
                to: "Pending".to_string(),
                reason: "Can only retry from Failed state".to_string(),
            }),
        }
    }

    /// 获取当前状态名称
    pub fn state_name(&self) -> String {
        match self {
            CapsuleState::Pending { .. } => "Pending".to_string(),
            CapsuleState::Uploading { .. } => "Uploading".to_string(),
            CapsuleState::Completed { .. } => "Completed".to_string(),
            CapsuleState::Failed { .. } => "Failed".to_string(),
        }
    }

    /// 检查是否为终态（Completed或Failed且不可重试）
    pub fn is_final(&self) -> bool {
        match self {
            CapsuleState::Completed { .. } => true,
            CapsuleState::Failed { retryable: false, .. } => true,
            _ => false,
        }
    }

    /// 检查是否可以进行上传操作
    pub fn can_upload(&self) -> bool {
        matches!(self, CapsuleState::Pending { .. })
    }

    /// 获取进度百分比（如果适用）
    pub fn get_progress(&self) -> Option<f64> {
        match self {
            CapsuleState::Pending { .. } => Some(0.0),
            CapsuleState::Uploading { progress, .. } => Some(*progress),
            CapsuleState::Completed { .. } => Some(1.0),
            CapsuleState::Failed { .. } => None,
        }
    }

    /// 生成最终URI，替换占位符变量
    pub fn resolve_final_uri(&self, template_vars: &HashMap<String, String>) -> Option<String> {
        match self {
            CapsuleState::Pending { placeholder_uri, content_hash, .. } => {
                let mut uri = placeholder_uri.clone();
                // 替换 {hash} 占位符
                uri = uri.replace("{hash}", content_hash);
                // 替换其他模板变量
                for (key, value) in template_vars {
                    uri = uri.replace(&format!("{{{}}}", key), value);
                }
                Some(uri)
            }
            CapsuleState::Completed { final_uri, .. } => Some(final_uri.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_transitions() {
        // 创建Pending状态
        let pending = CapsuleState::new_pending(
            "s3://bucket/data-{hash}".to_string(),
            vec![1, 2, 3, 4],
            "abcd1234".to_string(),
        );

        assert!(pending.can_upload());
        assert_eq!(pending.get_progress(), Some(0.0));

        // 转换为Uploading
        let uploading = pending
            .start_upload(
                "upload-123".to_string(),
                "s3://bucket/data-abcd1234".to_string(),
                None,
            )
            .unwrap();

        assert_eq!(uploading.get_progress(), Some(0.0));

        // 更新进度
        let mut uploading = uploading;
        uploading.update_progress(0.5).unwrap();
        assert_eq!(uploading.get_progress(), Some(0.5));

        // 标记完成
        let completed = uploading
            .mark_completed(
                "s3://bucket/data-abcd1234".to_string(),
                None,
            )
            .unwrap();

        assert!(completed.is_final());
        assert_eq!(completed.get_progress(), Some(1.0));
    }

    #[test]
    fn test_invalid_transitions() {
        let completed = CapsuleState::Completed {
            final_uri: "s3://bucket/file".to_string(),
            uploaded_at: "2025-01-01T00:00:00Z".to_string(),
            verification: None,
        };

        // 不能从Completed转换为Failed
        let result = completed.mark_failed(
            "error".to_string(),
            None,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_uri_resolution() {
        let pending = CapsuleState::new_pending(
            "s3://{bucket}/data-{hash}".to_string(),
            vec![1, 2, 3, 4],
            "abcd1234".to_string(),
        );

        let mut vars = HashMap::new();
        vars.insert("bucket".to_string(), "my-bucket".to_string());

        let resolved = pending.resolve_final_uri(&vars).unwrap();
        assert_eq!(resolved, "s3://my-bucket/data-abcd1234");
    }

    #[test]
    fn test_progress_validation() {
        let pending = CapsuleState::new_pending(
            "s3://bucket/file".to_string(),
            vec![1, 2, 3],
            "hash123".to_string(),
        );

        let mut uploading = pending
            .start_upload("id".to_string(), "uri".to_string(), None)
            .unwrap();

        // 有效进度
        assert!(uploading.update_progress(0.5).is_ok());
        assert!(uploading.update_progress(1.0).is_ok());

        // 无效进度
        assert!(uploading.update_progress(-0.1).is_err());
        assert!(uploading.update_progress(1.1).is_err());
    }
}