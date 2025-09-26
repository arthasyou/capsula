/// 权限数据初始化程序
///
/// 用于初始化数据库中的默认权限数据
/// 通常在以下情况下运行：
/// 1. 首次部署系统
/// 2. 需要重置权限数据到默认状态
/// 3. 升级后需要更新权限定义
///
/// 使用方法：
/// ```bash
/// cargo run --bin init_permissions
/// ```
use capsula_bank::{
    db::{create_tables, force_initialize_default_data, get_db, init_db},
    settings::Settings,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    tracing_subscriber::fmt().with_target(false).init();

    println!("========================================");
    println!("    权限数据初始化程序");
    println!("========================================\n");

    // 加载配置
    println!("📋 加载配置文件...");
    let settings = Settings::load("config/services.toml")?;
    println!("✅ 配置加载成功\n");

    // 连接数据库
    println!("🔌 连接数据库...");
    println!(
        "   Host: {}:{}",
        settings.surrealdb.host, settings.surrealdb.port
    );
    println!("   Namespace: {}", settings.surrealdb.namespace);
    println!("   Database: {}", settings.surrealdb.database);

    init_db(settings.surrealdb).await?;
    println!("✅ 数据库连接成功\n");

    // 清理现有表
    println!("🗑️ 清理现有表...");
    let db = get_db();
    db.query("REMOVE TABLE IF EXISTS tokens").await?;
    db.query("REMOVE TABLE IF EXISTS molecular_permissions").await?;
    db.query("REMOVE TABLE IF EXISTS atomic_permissions").await?;
    println!("✅ 现有表已清理\n");

    // 创建表结构
    println!("📊 创建表结构...");
    create_tables().await?;
    println!("✅ 表结构创建成功\n");

    // 初始化权限数据
    println!("🔐 初始化权限数据...");
    force_initialize_default_data().await?;

    println!("\n========================================");
    println!("✨ 权限数据初始化完成！");
    println!("========================================");
    println!("\n现在可以启动 Capsula Bank 服务器了：");
    println!("cargo run");

    Ok(())
}
