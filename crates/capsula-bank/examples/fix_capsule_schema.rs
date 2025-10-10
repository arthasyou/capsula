//! 修复胶囊数据表 schema
//! 将 capsule_data 字段从 TYPE object 改为 FLEXIBLE TYPE object

use capsula_bank::{db::init_db, settings::Settings};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 修复胶囊数据表 Schema ===\n");

    // 加载配置
    println!("正在加载配置...");
    let cfg = Settings::load("crates/capsula-bank/config/services.toml")?;
    println!("✓ 配置加载成功");

    // 初始化数据库连接
    println!("\n正在连接数据库...");
    init_db(cfg.surrealdb).await?;
    println!("✓ 数据库连接成功");

    // 删除旧的 capsule_data 字段定义
    println!("\n正在删除旧的 capsule_data 字段定义...");
    let db = capsula_bank::db::get_db();
    let remove_query = "REMOVE FIELD capsule_data ON TABLE capsules;";
    db.query(remove_query).await?;
    println!("✓ 旧字段定义已删除");

    // 重新创建 capsule_data 字段为 FLEXIBLE TYPE object
    println!("\n正在创建新的 FLEXIBLE capsule_data 字段...");
    let create_query = "DEFINE FIELD capsule_data ON TABLE capsules FLEXIBLE TYPE object;";
    db.query(create_query).await?;
    println!("✓ 新字段定义已创建");

    println!("\n=== Schema 修复完成 ===");
    println!("capsule_data 字段现在是 FLEXIBLE TYPE object");
    println!("可以存储任意嵌套的 JSON 结构");

    Ok(())
}
