pub mod atomic_permissions;
pub mod capsule;
pub mod molecular_permissions;
pub mod operations;
pub mod token;
pub mod user;

use std::sync::LazyLock;

use serde::Deserialize;
use surrealdb::{
    engine::remote::ws::{Client, Ws},
    opt::auth::Root,
    Surreal,
};

use crate::{
    db::{
        atomic_permissions::{create_atomic_permissions_table, initialize_atomic_permissions},
        molecular_permissions::{
            create_molecular_permissions_table, initialize_molecular_permissions,
        },
    },
    error::Result,
};

/// Struct representing the Surrealdb configuration parameters.
#[derive(Debug, Deserialize)]
pub struct SurrealdbCfg {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub namespace: String,
    pub database: String,
}

static DB: LazyLock<Surreal<Client>> = LazyLock::new(Surreal::init);

pub async fn init_db(cfg: SurrealdbCfg) -> Result<()> {
    let addr = format!("{}:{}", cfg.host, cfg.port);
    DB.connect::<Ws>(addr).await?;
    DB.signin(Root {
        username: &cfg.username,
        password: &cfg.password,
    })
    .await?;
    DB.use_ns(cfg.namespace).use_db(cfg.database).await?;
    Ok(())
}

pub fn get_db() -> &'static Surreal<Client> {
    &DB
}

pub async fn create_tables() -> Result<()> {
    // Create atomic permissions table (原子权限定义)
    create_atomic_permissions_table().await?;

    // Create molecular permissions table (分子权限组合)
    create_molecular_permissions_table().await?;
    
    // Create token table (令牌管理)
    token::create_token_table().await?;
    
    // Create capsule table (数据胶囊存储)
    capsule::create_capsule_table().await?;

    Ok(())
}

/// 强制初始化数据库默认数据（不检查是否为空）
/// 用于 init_permissions 程序，已经清空表的情况
pub async fn force_initialize_default_data() -> Result<()> {
    println!("   初始化原子权限默认数据...");
    initialize_atomic_permissions().await?;
    println!("   ✅ 原子权限初始化成功");
    
    println!("   初始化分子权限默认数据...");
    initialize_molecular_permissions().await?;
    println!("   ✅ 分子权限初始化成功");
    
    Ok(())
}

/// 初始化数据库默认数据
/// 这个函数应该只在第一次部署或需要重置默认数据时调用
/// 它会检查表是否为空，只有在表为空时才插入默认数据
pub async fn initialize_default_data() -> Result<()> {
    let db = get_db();

    // 检查原子权限表是否需要初始化
    let atomic_count_query = "SELECT count() FROM atomic_permissions";
    let mut response = db.query(atomic_count_query).await?;
    let atomic_result: Vec<serde_json::Value> = response.take(0)?;

    let should_init_atomic = if let Some(first) = atomic_result.first() {
        first
            .get("count")
            .and_then(|c| c.as_u64())
            .map(|c| c == 0)
            .unwrap_or(true)
    } else {
        true
    };

    if should_init_atomic {
        println!("Initializing atomic permissions with default data...");
        initialize_atomic_permissions().await?;
        println!("Atomic permissions initialized successfully.");
    } else {
        println!("Atomic permissions table already has data, skipping initialization.");
    }

    // 检查分子权限表是否需要初始化
    let molecular_count_query = "SELECT count() FROM molecular_permissions";
    let mut response = db.query(molecular_count_query).await?;
    let molecular_result: Vec<serde_json::Value> = response.take(0)?;

    let should_init_molecular = if let Some(first) = molecular_result.first() {
        first
            .get("count")
            .and_then(|c| c.as_u64())
            .map(|c| c == 0)
            .unwrap_or(true)
    } else {
        true
    };

    if should_init_molecular {
        println!("Initializing molecular permissions with default data...");
        initialize_molecular_permissions().await?;
        println!("Molecular permissions initialized successfully.");
    } else {
        println!("Molecular permissions table already has data, skipping initialization.");
    }

    Ok(())
}
