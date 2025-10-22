use capsula_core::{Capsule, CapsuleContent};
use capsula_key::{Key, RsaKey};

use crate::{
    db::capsule as db_capsule,
    error::{AppError, Result},
    models::{capsule::CapsuleRecord, recipe::Recipe},
    static_files::key,
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
/// 1. 使用系统密钥解密（无需传入密钥参数）
/// 2. 根据 Recipe 中的 IDs 和 owner_id 查询胶囊
/// 3. 使用系统私钥解密每个胶囊
/// 4. 返回解密后的内容
///
/// # 注意
/// 所有胶囊都使用银行系统密钥加密，因此解密时统一使用 get_system_key()
pub async fn fetch_and_decrypt_capsules(
    recipe: &Recipe,
    owner_id: &str,
) -> Result<Vec<DecryptedCapsule>> {
    // 获取系统密钥用于解密
    let system_key = key::get_system_key();

    // 根据 Recipe 中的 IDs 查询胶囊
    let capsule_records = db_capsule::get_capsules_by_owner_and_ids(owner_id, &recipe.ids).await?;

    decrypt_capsule_records(capsule_records, system_key)
}

fn decrypt_capsule_records(
    capsule_records: Vec<CapsuleRecord>,
    system_key: &RsaKey,
) -> Result<Vec<DecryptedCapsule>> {
    // 解密每个胶囊
    let mut decrypted_capsules = Vec::new();

    for record in capsule_records {
        // 将 capsule_data (JSON Value) 反序列化为 Capsule
        tracing::debug!("Deserializing capsule: {}", record.capsule_id);
        tracing::debug!("capsule_data type: {:?}", record.capsule_data);

        let capsule: Capsule =
            serde_json::from_value(record.capsule_data.clone()).map_err(|e| {
                tracing::error!("Failed to deserialize capsule {}: {}", record.capsule_id, e);
                tracing::error!("capsule_data: {:?}", record.capsule_data);
                AppError::Internal(format!("Failed to deserialize capsule: {}", e))
            })?;

        // 解密胶囊载荷（使用系统密钥）
        match capsule.unseal_payload(system_key) {
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

/// 创建并封装 Cap1 胶囊（使用系统密钥）
///
/// # 参数
/// - `cap0_id`: 关联的 Cap0 胶囊 ID
/// - `meta_data`: 元数据明文
/// - `bnf_extract_data`: BNF 提取数据明文
/// - `content_type`: 内容类型（如 "medical.blood_test"）
/// - `policy_uri`: 策略 URI
/// - `permissions`: 权限列表
/// - `creator`: 创建者（可选）
///
/// # 返回
/// 完整的 Capsule 实例，已使用系统密钥加密
///
/// # 注意
/// 此函数自动使用银行系统密钥进行加密，无需传入密钥参数
pub fn create_cap1_capsule(
    cap0_id: String,
    meta_data: &[u8],
    bnf_extract_data: &[u8],
    content_type: String,
    policy_uri: String,
    permissions: Vec<String>,
    creator: Option<String>,
) -> Result<capsula_core::Capsule> {
    use capsula_core::{Cap1, Capsule, ContentType};

    // 获取系统密钥
    let system_key = key::get_system_key();

    // 获取系统公钥 SPKI DER
    let public_keys = system_key.public_keys();
    let signing_key_entry = public_keys
        .signing_key()
        .ok_or_else(|| AppError::Internal("System key missing signing capability".to_string()))?;
    let spki_der = &signing_key_entry.spki_der;

    // 生成胶囊 ID
    let capsule_id = capsula_crypto::generate_id("cid");

    // 创建 AAD（额外认证数据）
    let aad = format!("capsule:{}", capsule_id);

    // 创建空的 Keyring（将在 seal 中填充）
    let mut keyring = capsula_core::Keyring::new();

    // 封装 Cap1
    let cap1 = Cap1::seal(
        cap0_id,
        meta_data,
        bnf_extract_data,
        (ContentType::Json, ContentType::Json),
        aad.as_bytes(),
        &mut keyring,
        spki_der,
        system_key, // 用于签名
        None,       // 暂不使用 ZKP
    )
    .map_err(|e| AppError::Internal(format!("Failed to seal Cap1: {}", e)))?;

    // 创建完整的 Capsule
    let capsule = Capsule::with_cap1(
        capsule_id,
        content_type,
        policy_uri,
        permissions,
        keyring,
        cap1,
        creator,
    )
    .map_err(|e| AppError::Internal(format!("Failed to create Capsule: {}", e)))?;

    Ok(capsule)
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
