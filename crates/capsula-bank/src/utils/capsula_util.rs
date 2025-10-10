use capsula_core::{Capsule, CapsuleContent};
use capsula_key::{Key, KeyEncDec};

use crate::{
    db::capsule as db_capsule,
    error::{AppError, Result},
    models::recipe::Recipe,
};

/// 根据 Recipe 查询并解密胶囊数据
///
/// # 参数
/// - `recipe`: Recipe 结构，包含要查询的胶囊 ID 列表和其他过滤条件
/// - `owner_id`: 胶囊所有者 ID（用于权限验证）
///
/// # 返回
/// 返回解密后的胶囊内容列表
///
/// # 流程
/// 1. 从数据库查询私钥（owner_id = "system"）
/// 2. 根据 Recipe 中的 IDs 和 owner_id 查询胶囊
/// 3. 使用私钥解密每个胶囊
/// 4. 返回解密后的内容
pub async fn fetch_and_decrypt_capsules<T>(
    recipe: &Recipe,
    owner_id: &str,
    decryption_key: &T,
) -> Result<Vec<DecryptedCapsule>>
where
    T: Key + KeyEncDec,
{
    // 2. 根据 Recipe 中的 IDs 查询胶囊
    let capsule_records = db_capsule::get_capsules_by_owner_and_ids(owner_id, &recipe.ids).await?;

    // 3. 解密每个胶囊
    let mut decrypted_capsules = Vec::new();

    for record in capsule_records {
        // 将 capsule_data (JSON Value) 反序列化为 Capsule
        tracing::debug!("Deserializing capsule: {}", record.capsule_id);
        tracing::debug!("capsule_data type: {:?}", record.capsule_data);

        let capsule: Capsule = serde_json::from_value(record.capsule_data.clone())
            .map_err(|e| {
                tracing::error!("Failed to deserialize capsule {}: {}", record.capsule_id, e);
                tracing::error!("capsule_data: {:?}", record.capsule_data);
                AppError::Internal(format!("Failed to deserialize capsule: {}", e))
            })?;

        // 解密胶囊载荷
        match capsule.unseal_payload(decryption_key) {
            Ok(content) => {
                decrypted_capsules.push(DecryptedCapsule {
                    capsule_id: record.capsule_id,
                    owner_id: record.owner_id,
                    content_type: record.content_type,
                    created_at: record.created_at,
                    content,
                });
            }
            Err(e) => {
                // 记录错误但继续处理其他胶囊
                tracing::warn!("Failed to decrypt capsule {}: {}", record.capsule_id, e);
            }
        }
    }

    Ok(decrypted_capsules)
}

/// 解密后的胶囊数据
#[derive(Debug, Clone)]
pub struct DecryptedCapsule {
    /// 胶囊 ID
    pub capsule_id: String,

    /// 所有者 ID
    pub owner_id: String,

    /// 内容类型
    pub content_type: String,

    /// 创建时间
    pub created_at: i64,

    /// 解密后的内容
    pub content: CapsuleContent,
}

impl DecryptedCapsule {
    /// 提取 Cap1 内容
    pub fn as_cap1_content(&self) -> Option<(&str, &[u8], &[u8])> {
        match &self.content {
            CapsuleContent::Cap1Content {
                cap0_id,
                meta_data,
                bnf_extract_data,
            } => Some((
                cap0_id.as_str(),
                meta_data.as_slice(),
                bnf_extract_data.as_slice(),
            )),
            _ => None,
        }
    }

    /// 提取 Cap2 内容
    pub fn as_cap2_content(&self) -> Option<(&str, &[capsula_core::RefEntry])> {
        match &self.content {
            CapsuleContent::Cap2Content { owner_id, refs } => {
                Some((owner_id.as_str(), refs.as_slice()))
            }
            _ => None,
        }
    }
}
