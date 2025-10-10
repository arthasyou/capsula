use crate::{
    db::get_db,
    error::{AppError, Result},
    models::private_key::PrivateKey,
};

/// 创建私钥表
pub async fn create_private_key_table() -> Result<()> {
    let query = r#"
        -- ---------------------
        -- 私钥表定义
        -- ---------------------
        DEFINE TABLE IF NOT EXISTS private_keys SCHEMAFULL;

        -- 字段定义
        DEFINE FIELD IF NOT EXISTS key_id              ON TABLE private_keys TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS owner_id            ON TABLE private_keys TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS private_key_pem     ON TABLE private_keys TYPE string ASSERT $value != NONE AND $value != "";

        -- ---------------------
        -- 索引定义
        -- ---------------------
        DEFINE INDEX IF NOT EXISTS key_id_idx          ON TABLE private_keys COLUMNS key_id UNIQUE;
        DEFINE INDEX IF NOT EXISTS owner_id_idx        ON TABLE private_keys COLUMNS owner_id;
    "#;

    let db = get_db();
    db.query(query).await?;
    Ok(())
}

/// 创建新私钥记录
pub async fn create_private_key(private_key: PrivateKey) -> Result<PrivateKey> {
    let db = get_db();
    let key_id = private_key.key_id.clone();
    let created: Option<PrivateKey> = db
        .create(("private_keys", key_id))
        .content(private_key)
        .await?;

    created.ok_or_else(|| AppError::Internal("Failed to create private key".into()))
}

/// 根据密钥ID查询
pub async fn get_private_key_by_id(key_id: &str) -> Result<Option<PrivateKey>> {
    let db = get_db();
    let key: Option<PrivateKey> = db.select(("private_keys", key_id)).await?;
    Ok(key)
}

/// 查询用户的所有密钥
pub async fn get_all_keys_by_owner(owner_id: &str) -> Result<Vec<PrivateKey>> {
    let db = get_db();
    let query = "SELECT * FROM private_keys WHERE owner_id = $owner_id";
    let mut response = db
        .query(query)
        .bind(("owner_id", owner_id.to_string()))
        .await?;
    let keys: Vec<PrivateKey> = response.take(0)?;
    Ok(keys)
}

/// 更新私钥记录
pub async fn update_private_key(private_key: &PrivateKey) -> Result<PrivateKey> {
    let db = get_db();
    let updated: Option<PrivateKey> = db
        .update(("private_keys", private_key.key_id.clone()))
        .content(private_key.clone())
        .await?;

    updated.ok_or_else(|| AppError::Internal("Failed to update private key".into()))
}

/// 删除私钥
pub async fn delete_private_key(key_id: &str) -> Result<()> {
    let db = get_db();
    let _: Option<PrivateKey> = db.delete(("private_keys", key_id)).await?;
    Ok(())
}

/// 删除用户的所有密钥
pub async fn delete_all_keys_for_owner(owner_id: &str) -> Result<()> {
    let db = get_db();
    let query = "DELETE private_keys WHERE owner_id = $owner_id";
    db.query(query)
        .bind(("owner_id", owner_id.to_string()))
        .await?;
    Ok(())
}
