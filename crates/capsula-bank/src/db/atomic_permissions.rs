use crate::{
    db::get_db,
    error::Result,
    models::permission::{get_default_atomic_permissions, AtomicPermission},
};

/// Create atomic permissions table - stores atomic permission definitions
/// 原子权限表：存储原子权限的定义，主要用于文档和展示
pub async fn create_atomic_permissions_table() -> Result<()> {
    let query = r#"
        -- ---------------------
        -- 原子权限表定义
        -- ---------------------
        DEFINE TABLE IF NOT EXISTS atomic_permissions SCHEMAFULL;
        
        -- 字段定义
        DEFINE FIELD IF NOT EXISTS atom_id              ON TABLE atomic_permissions TYPE string ASSERT $value != NONE AND $value != "";
        DEFINE FIELD IF NOT EXISTS name                 ON TABLE atomic_permissions TYPE string;
        DEFINE FIELD IF NOT EXISTS position             ON TABLE atomic_permissions TYPE int ASSERT $value >= 0 AND $value < 14;
        DEFINE FIELD IF NOT EXISTS category             ON TABLE atomic_permissions TYPE string 
            ASSERT $value IN ['read_edit', 'usage', 'transfer', 'supervision'];
        DEFINE FIELD IF NOT EXISTS description          ON TABLE atomic_permissions TYPE string;
        DEFINE FIELD IF NOT EXISTS created_at           ON TABLE atomic_permissions TYPE int DEFAULT time::unix();
        DEFINE FIELD IF NOT EXISTS updated_at           ON TABLE atomic_permissions TYPE int DEFAULT time::unix();
        
        -- ---------------------
        -- 索引定义
        -- ---------------------
        DEFINE INDEX IF NOT EXISTS atom_id_idx    ON TABLE atomic_permissions COLUMNS atom_id UNIQUE;
        DEFINE INDEX IF NOT EXISTS position_idx   ON TABLE atomic_permissions COLUMNS position UNIQUE;
        DEFINE INDEX IF NOT EXISTS category_idx   ON TABLE atomic_permissions COLUMNS category;
    "#;

    let db = get_db();
    db.query(query).await?;
    Ok(())
}

/// Initialize default atomic permissions using Rust code
pub async fn initialize_atomic_permissions() -> Result<()> {
    let db = get_db();

    // 获取默认的原子权限列表
    let permissions = get_default_atomic_permissions();

    // 批量插入原子权限，使用 position 作为记录ID
    for permission in permissions {
        let _: Option<AtomicPermission> = db
            .create(("atomic_permissions", permission.position as i64))
            .content(permission)
            .await?;
    }

    Ok(())
}

/// 查询所有原子权限
#[allow(dead_code)]
pub async fn get_all_atomic_permissions() -> Result<Vec<AtomicPermission>> {
    let db = get_db();
    let permissions: Vec<AtomicPermission> = db.select("atomic_permissions").await?;
    Ok(permissions)
}

/// 根据位置查询原子权限
#[allow(dead_code)]
pub async fn get_atomic_permission_by_position(position: u8) -> Result<Option<AtomicPermission>> {
    let db = get_db();
    let permission: Option<AtomicPermission> = db.select(("atomic_permissions", position as i64)).await?;
    Ok(permission)
}

/// 根据atom_id查询原子权限
#[allow(dead_code)]
pub async fn get_atomic_permission_by_atom_id(atom_id: &str) -> Result<Option<AtomicPermission>> {
    let db = get_db();
    let query = "SELECT * FROM atomic_permissions WHERE atom_id = $atom_id";
    let mut response = db.query(query).bind(("atom_id", atom_id.to_string())).await?;
    let permissions: Vec<AtomicPermission> = response.take(0)?;
    Ok(permissions.into_iter().next())
}
