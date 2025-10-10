//! 插入 Owner 私钥到数据库
//!
//! 从文件加载 owner_private.pem 并插入到数据库
//! owner_id: P001

use std::fs;

use capsula_bank::{
    db::{init_db, private_key as db_private_key},
    models::private_key::PrivateKey,
    settings::Settings,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 插入 Owner 私钥到数据库 ===\n");

    // 1. 加载配置
    println!("正在加载配置...");
    let cfg = Settings::load("crates/capsula-bank/config/services.toml")?;
    println!("✓ 配置加载成功");

    // 2. 初始化数据库连接
    println!("\n正在连接数据库...");
    init_db(cfg.surrealdb).await?;
    println!("✓ 数据库连接成功");

    // 3. 从文件加载 owner 私钥
    println!("\n正在加载 owner 私钥文件...");
    let owner_private_pem = fs::read_to_string("temp/keys/owner_private.pem")?;
    println!("✓ 私钥文件加载成功");

    // 4. 创建私钥记录
    let key_id = format!("key-owner-P001-{}", chrono::Utc::now().timestamp());
    let owner_id = "P001".to_string();

    let private_key = PrivateKey::new(key_id.clone(), owner_id.clone(), owner_private_pem);

    println!("\n正在插入私钥到数据库...");
    println!("  Key ID: {}", key_id);
    println!("  Owner ID: {}", owner_id);

    // 5. 插入到数据库
    let created_key = db_private_key::create_private_key(private_key).await?;

    println!("\n✓ 私钥插入成功");
    println!("\n=== 插入结果 ===");
    println!("Key ID: {}", created_key.key_id);
    println!("Owner ID: {}", created_key.owner_id);
    println!("私钥长度: {} 字节", created_key.private_key_pem.len());

    // 6. 验证：重新读取
    println!("\n正在验证插入结果...");
    let retrieved_keys = db_private_key::get_all_keys_by_owner(&owner_id).await?;
    println!("✓ 找到 {} 个私钥记录", retrieved_keys.len());

    for (index, key) in retrieved_keys.iter().enumerate() {
        println!("  私钥 {}: {}", index + 1, key.key_id);
    }

    println!("\n=== Owner 私钥插入完成 ===");
    println!("现在可以运行 test_recipe_decrypt 来测试解密功能");

    Ok(())
}
