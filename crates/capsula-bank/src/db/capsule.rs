use crate::{db::get_db, error::Result, models::capsule::CapsuleRecord};

/// 创建胶囊表
pub async fn create_capsule_table() -> Result<()> {
    let query = r#"
        -- ---------------------
        -- 数据胶囊表定义（简化版）
        -- ---------------------
        DEFINE TABLE IF NOT EXISTS capsules SCHEMAFULL;
        
        -- ===== Header 核心字段（用于查询） =====
        DEFINE FIELD IF NOT EXISTS capsule_id       ON TABLE capsules TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS version          ON TABLE capsules TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS stage            ON TABLE capsules TYPE string 
            ASSERT $value IN ['first', 'second', 'third'];
        DEFINE FIELD IF NOT EXISTS content_type     ON TABLE capsules TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS created_at       ON TABLE capsules TYPE int;
        DEFINE FIELD IF NOT EXISTS creator          ON TABLE capsules TYPE option<string>;
        DEFINE FIELD IF NOT EXISTS owner_id         ON TABLE capsules TYPE string ASSERT $value != NONE AND $value != "";
        
        -- ===== 胶囊完整数据（JSON存储） =====
        DEFINE FIELD IF NOT EXISTS capsule_data     ON TABLE capsules FLEXIBLE TYPE object;
        
        -- ===== 自定义元数据（可选） =====
        DEFINE FIELD IF NOT EXISTS metadata         ON TABLE capsules TYPE option<object>;
        
        -- ---------------------
        -- 索引定义（简化版）
        -- ---------------------
        DEFINE INDEX IF NOT EXISTS capsule_id_idx       ON TABLE capsules COLUMNS capsule_id UNIQUE;
        DEFINE INDEX IF NOT EXISTS owner_id_idx         ON TABLE capsules COLUMNS owner_id;
        DEFINE INDEX IF NOT EXISTS content_type_idx     ON TABLE capsules COLUMNS content_type;
        DEFINE INDEX IF NOT EXISTS stage_idx            ON TABLE capsules COLUMNS stage;
        DEFINE INDEX IF NOT EXISTS created_at_idx       ON TABLE capsules COLUMNS created_at;
        
        -- 复合索引
        DEFINE INDEX IF NOT EXISTS owner_type_idx       ON TABLE capsules COLUMNS owner_id, content_type;
        DEFINE INDEX IF NOT EXISTS type_stage_idx       ON TABLE capsules COLUMNS content_type, stage;
    "#;

    let db = get_db();
    db.query(query).await?;
    Ok(())
}

/// 创建新胶囊
pub async fn create_capsule(capsule: CapsuleRecord) -> Result<CapsuleRecord> {
    let db = get_db();
    let created: Option<CapsuleRecord> = db
        .create(("capsules", capsule.capsule_id.clone()))
        .content(capsule)
        .await?;

    created.ok_or_else(|| crate::error::AppError::Internal("Failed to create capsule".into()))
}

/// 根据ID查询胶囊
pub async fn get_capsule_by_id(capsule_id: &str) -> Result<Option<CapsuleRecord>> {
    let db = get_db();
    let capsule: Option<CapsuleRecord> = db.select(("capsules", capsule_id)).await?;
    Ok(capsule)
}

/// 查询所有者的胶囊
pub async fn get_capsules_by_owner(owner_id: &str) -> Result<Vec<CapsuleRecord>> {
    let db = get_db();
    let query = "SELECT * FROM capsules WHERE owner_id = $owner_id ORDER BY created_at DESC";
    let mut response = db
        .query(query)
        .bind(("owner_id", owner_id.to_string()))
        .await?;
    let capsules: Vec<CapsuleRecord> = response.take(0)?;
    Ok(capsules)
}

/// 根据所有者和ID列表查询胶囊
pub async fn get_capsules_by_owner_and_ids(
    owner_id: &str,
    capsule_ids: &[String],
) -> Result<Vec<CapsuleRecord>> {
    let db = get_db();
    let query = "SELECT * FROM capsules WHERE owner_id = $owner_id AND capsule_id IN $capsule_ids \
                 ORDER BY created_at DESC";
    let mut response = db
        .query(query)
        .bind(("owner_id", owner_id.to_string()))
        .bind(("capsule_ids", capsule_ids.to_vec()))
        .await?;
    let capsules: Vec<CapsuleRecord> = response.take(0)?;
    Ok(capsules)
}

/// 查询特定类型的胶囊
pub async fn get_capsules_by_type(content_type: &str) -> Result<Vec<CapsuleRecord>> {
    let db = get_db();
    let query = "SELECT * FROM capsules WHERE content_type = $content_type";
    let mut response = db
        .query(query)
        .bind(("content_type", content_type.to_string()))
        .await?;
    let capsules: Vec<CapsuleRecord> = response.take(0)?;
    Ok(capsules)
}

/// 更新胶囊
pub async fn update_capsule(capsule: &CapsuleRecord) -> Result<CapsuleRecord> {
    let db = get_db();
    let updated: Option<CapsuleRecord> = db
        .update(("capsules", capsule.capsule_id.clone()))
        .content(capsule.clone())
        .await?;

    updated.ok_or_else(|| crate::error::AppError::Internal("Failed to update capsule".into()))
}

/// 删除胶囊（物理删除，慎用）
pub async fn delete_capsule(capsule_id: &str) -> Result<()> {
    let db = get_db();
    let _: Option<CapsuleRecord> = db.delete(("capsules", capsule_id)).await?;
    Ok(())
}

/// 搜索胶囊（简化的复合条件）
pub async fn search_capsules(
    owner_id: Option<&str>,
    content_type: Option<&str>,
    stage: Option<&str>,
) -> Result<Vec<CapsuleRecord>> {
    let db = get_db();

    let mut query = "SELECT * FROM capsules WHERE 1=1".to_string();
    let mut bindings = vec![];

    if let Some(owner) = owner_id {
        query.push_str(" AND owner_id = $owner_id");
        bindings.push(("owner_id", owner.to_string()));
    }

    if let Some(ct) = content_type {
        query.push_str(" AND content_type = $content_type");
        bindings.push(("content_type", ct.to_string()));
    }

    if let Some(s) = stage {
        query.push_str(" AND stage = $stage");
        bindings.push(("stage", s.to_string()));
    }

    query.push_str(" ORDER BY created_at DESC");

    let mut db_query = db.query(&query);
    for (key, value) in bindings {
        db_query = db_query.bind((key, value));
    }

    let mut response = db_query.await?;
    let capsules: Vec<CapsuleRecord> = response.take(0)?;
    Ok(capsules)
}
