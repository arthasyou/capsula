//! 插入系统私钥到数据库
//!
//! 生成一个 RSA 2048 私钥并存储到数据库，owner_id 为 "system"

use capsula_bank::{
    db::{init_db, private_key as db_private_key},
    models::private_key::PrivateKey,
    settings::Settings,
};
use capsula_key::{KeyExport, RsaKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 插入系统私钥到数据库 ===\n");

    // 1. 加载配置
    println!("正在加载配置...");
    let cfg = Settings::load("crates/capsula-bank/config/services.toml")?;
    println!("✓ 配置加载成功");

    // 2. 初始化数据库连接
    println!("\n正在连接数据库...");
    init_db(cfg.surrealdb).await?;
    println!("✓ 数据库连接成功");

    // 3. 生成 RSA 2048 密钥对
    println!("\n正在生成 RSA 2048 密钥对...");
    let key_pair = RsaKey::generate_2048()?;
    println!("✓ 密钥生成成功");

    // 4. 导出私钥为 PEM 格式
    let private_key_pem = key_pair.to_pkcs8_pem()?;
    println!("✓ 私钥导出为 PEM 格式");

    // 5. 生成密钥 ID
    let key_id = format!("key-system-{}", chrono::Utc::now().timestamp());
    println!("✓ 密钥 ID: {}", key_id);

    // 6. 创建私钥记录
    let private_key = PrivateKey::new(
        key_id.clone(),
        "system".to_string(),
        private_key_pem.clone(),
    );

    // 7. 插入到数据库
    println!("\n正在插入私钥到数据库...");
    let created_key = db_private_key::create_private_key(private_key).await?;
    println!("✓ 私钥插入成功");

    // 8. 显示结果
    println!("\n=== 插入结果 ===");
    println!("密钥 ID: {}", created_key.key_id);
    println!("所有者 ID: {}", created_key.owner_id);
    println!(
        "私钥 PEM (前100字符): {}...",
        &created_key.private_key_pem[.. 100.min(created_key.private_key_pem.len())]
    );

    // 9. 验证：从数据库读取
    println!("\n正在验证插入结果...");
    let retrieved_key = db_private_key::get_private_key_by_id(&key_id).await?;

    if let Some(key) = retrieved_key {
        println!("✓ 验证成功：从数据库成功读取密钥");
        println!("  - 密钥 ID: {}", key.key_id);
        println!("  - 所有者 ID: {}", key.owner_id);
        println!("  - 私钥长度: {} 字节", key.private_key_pem.len());

        // 10. 验证私钥可以被正确加载
        println!("\n正在验证私钥可用性...");
        let loaded_key = RsaKey::from_pkcs8_pem(&key.private_key_pem)?;
        println!("✓ 私钥可以正常加载使用");
        println!("  - RSA 密钥大小: {} bits", loaded_key.size_bits());
    } else {
        println!("❌ 验证失败：无法从数据库读取密钥");
    }

    println!("\n=== 完成 ===");
    Ok(())
}
