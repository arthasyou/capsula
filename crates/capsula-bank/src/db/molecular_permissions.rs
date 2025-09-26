use crate::{
    db::get_db,
    error::Result,
    models::permission::{get_default_molecular_permissions, MolecularPermission},
};

/// Create molecular permissions table - stores predefined permission combinations
/// 分子权属表：存储预定义的权限组合，每个分子权限由多个原子权限组成
pub async fn create_molecular_permissions_table() -> Result<()> {
    let query = r#"
        -- ---------------------
        -- 分子权限表定义
        -- ---------------------
        DEFINE TABLE IF NOT EXISTS molecular_permissions SCHEMAFULL;

        -- 字段定义
        DEFINE FIELD IF NOT EXISTS molecule_id      ON TABLE molecular_permissions TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS name             ON TABLE molecular_permissions TYPE string;
        DEFINE FIELD IF NOT EXISTS description      ON TABLE molecular_permissions TYPE string;
        DEFINE FIELD IF NOT EXISTS atomic_permissions ON TABLE molecular_permissions TYPE array<bool>;
        DEFINE FIELD IF NOT EXISTS permission_level ON TABLE molecular_permissions TYPE string
            ASSERT $value IN ['owner','admin','editor','user','viewer','auditor'];
        DEFINE FIELD IF NOT EXISTS is_active        ON TABLE molecular_permissions TYPE bool     DEFAULT true;
        DEFINE FIELD IF NOT EXISTS created_at       ON TABLE molecular_permissions TYPE int DEFAULT time::unix();
        DEFINE FIELD IF NOT EXISTS updated_at       ON TABLE molecular_permissions TYPE int DEFAULT time::unix();

        -- 索引定义
        DEFINE INDEX IF NOT EXISTS molecule_id_idx        ON TABLE molecular_permissions COLUMNS molecule_id UNIQUE;
        DEFINE INDEX IF NOT EXISTS permission_level_idx   ON TABLE molecular_permissions COLUMNS permission_level;
        DEFINE INDEX IF NOT EXISTS is_active_idx          ON TABLE molecular_permissions COLUMNS is_active;
    "#;

    let db = get_db();
    db.query(query).await?;
    Ok(())
}

/// Initialize default molecular permissions using Rust code
/// 初始化预定义的分子权限 - 根据文档定义的10种分子权限
pub async fn initialize_molecular_permissions() -> Result<()> {
    let db = get_db();

    // 获取默认的分子权限列表
    let permissions = get_default_molecular_permissions();

    // 批量插入分子权限
    for permission in permissions {
        let _: Option<MolecularPermission> = db
            .create(("molecular_permissions", &permission.molecule_id))
            .content(permission)
            .await?;
    }

    Ok(())
}

/// 查询所有分子权限
#[allow(dead_code)]
pub async fn get_all_molecular_permissions() -> Result<Vec<MolecularPermission>> {
    let db = get_db();
    let permissions: Vec<MolecularPermission> = db.select("molecular_permissions").await?;
    Ok(permissions)
}

/// 根据ID查询分子权限
#[allow(dead_code)]
pub async fn get_molecular_permission_by_id(
    molecule_id: &str,
) -> Result<Option<MolecularPermission>> {
    let db = get_db();
    let permission: Option<MolecularPermission> =
        db.select(("molecular_permissions", molecule_id)).await?;
    Ok(permission)
}

/// 根据权限级别查询分子权限
#[allow(dead_code)]
pub async fn get_molecular_permissions_by_level(level: &str) -> Result<Vec<MolecularPermission>> {
    let db = get_db();
    let query =
        "SELECT * FROM molecular_permissions WHERE permission_level = $level AND is_active = true";
    let permissions: Vec<MolecularPermission> = db
        .query(query)
        .bind(("level", level.to_string()))
        .await?
        .take(0)?;
    Ok(permissions)
}
