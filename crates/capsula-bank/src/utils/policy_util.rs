use model_gateway_rs::{
    model::llm::{LlmInput, LlmOutput},
    traits::ModelClient,
};
use serde_json::Value;

use super::{cap1_util, capsula_util::DecryptedCapsule};
use crate::error::{AppError, Result};

pub use cap1_util::Level1LlmOptions;

/// 根据权限级别投影解密后的胶囊列表。
///
/// 当前仅支持 1 阶胶囊（Cap1），并实现：
/// - Level 0：原始数据视图（不需要 LLM）
/// - Level 1：聚合后交由 LLM 生成总结，需要提供 LLM 客户端
pub async fn project_capsules_by_level<C>(
    capsules: &[DecryptedCapsule],
    level: u8,
    llm_client: Option<&C>,
    llm_options: Option<Level1LlmOptions>,
) -> Result<Value>
where
    C: ModelClient<LlmInput, LlmOutput> + Sync + Send,
{
    match level {
        0 => Ok(cap1_util::project_cap1_level0(capsules)),
        1 => {
            let client = llm_client.ok_or_else(|| {
                AppError::Internal("LLM client is required for Level 1 projection".to_string())
            })?;
            let options = llm_options.unwrap_or_default();
            cap1_util::summarize_cap1_level1_with_llm(capsules, client, options).await
        }
        _ => Err(AppError::BadRequest(format!(
            "Unsupported disclosure level: {}",
            level
        ))),
    }
}
