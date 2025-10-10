//! 测试 Recipe 查询和解密胶囊功能
//!
//! 演示如何使用 Recipe 查询数据库中的胶囊并解密
//! - 从数据库加载 owner 的私钥
//! - 使用 Recipe 查询胶囊
//! - 解密并显示胶囊内容

use capsula_bank::{
    db::init_db, models::recipe::Recipe, settings::Settings,
    utils::capsula_util::fetch_and_decrypt_capsules,
};
use capsula_key::RsaKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Recipe 查询和解密胶囊测试 ===\n");

    // 1. 加载配置
    println!("正在加载配置...");
    let cfg = Settings::load("config/services.toml")?;
    println!("✓ 配置加载成功");

    // 2. 初始化数据库连接
    println!("\n正在连接数据库...");
    init_db(cfg.surrealdb).await?;
    println!("✓ 数据库连接成功");

    // 3. 创建 Recipe 示例
    let recipe = Recipe {
        ids: vec![
            "cid:Cap1-Interpretation-001".to_string(),
            // 可以添加更多胶囊 ID
        ],
        from: 1727000000, // Unix 时间戳 (示例)
        to: 1728000000,   // Unix 时间戳 (示例)
        privacy: "L1".to_string(),
        aggregate: "llm".to_string(),
        llm_input: Some("请分析这些医疗数据".to_string()),
    };

    println!("\n=== Recipe 信息 ===");
    println!("查询胶囊 IDs: {:?}", recipe.ids);
    println!("时间范围: {} - {}", recipe.from, recipe.to);
    println!("隐私级别: {}", recipe.privacy);
    println!("聚合模式: {}", recipe.aggregate);

    // 4. 使用所有者 ID 查询并解密胶囊
    let owner_id = "P001"; // 示例所有者 ID
    println!("\n正在查询并解密胶囊...");
    println!("所有者 ID: {}", owner_id);

    // 先查询一下看看数据库中有什么
    use capsula_bank::db::capsule as db_capsule;
    let records = db_capsule::get_capsules_by_owner_and_ids(owner_id, &recipe.ids).await?;
    println!("\n找到 {} 个胶囊记录", records.len());
    for r in &records {
        println!("胶囊 ID: {}", r.capsule_id);
        println!(
            "capsule_data keys: {:?}",
            r.capsule_data
                .as_object()
                .map(|o| o.keys().collect::<Vec<_>>())
        );
    }

    // 5. 从数据库加载 owner 的私钥
    println!("\n正在从数据库加载私钥...");
    use capsula_bank::db::private_key as db_private_key;

    // 查询 owner 的所有私钥
    let keys = db_private_key::get_all_keys_by_owner(owner_id).await?;

    if keys.is_empty() {
        println!("❌ 未找到所有者 {} 的私钥", owner_id);
        println!("\n提示:");
        println!("1. 需要先生成并插入 owner 的私钥到数据库");
        println!("2. 或者可以从文件加载: temp/keys/owner_private.pem");
        return Ok(());
    }

    // 使用第一个私钥（实际应用中可能需要根据 key_id 选择）
    let private_key_record = &keys[0];
    println!("✓ 找到私钥: {}", private_key_record.key_id);

    let key = RsaKey::from_pkcs8_pem(&private_key_record.private_key_pem)?;
    println!("✓ 私钥加载成功");

    // 6. 使用私钥解密胶囊
    match fetch_and_decrypt_capsules(&recipe, owner_id, &key).await {
        Ok(decrypted_capsules) => {
            println!("\n✓ 成功解密 {} 个胶囊", decrypted_capsules.len());

            for (index, capsule) in decrypted_capsules.iter().enumerate() {
                println!("\n=== 胶囊 {} ===", index + 1);
                println!("胶囊 ID: {}", capsule.capsule_id);
                println!("所有者: {}", capsule.owner_id);
                println!("内容类型: {}", capsule.content_type);
                println!("创建时间: {}", capsule.created_at);

                // 根据内容类型显示解密数据
                if let Some((cap0_id, meta_data, bnf_data)) = capsule.as_cap1_content() {
                    println!("\n📦 Cap1 内容:");
                    println!("  关联 Cap0 ID: {}", cap0_id);
                    println!("  元数据大小: {} 字节", meta_data.len());
                    println!("  BNF 提取数据大小: {} 字节", bnf_data.len());

                    // 尝试解析 JSON 数据
                    if let Ok(meta_json) = serde_json::from_slice::<serde_json::Value>(meta_data) {
                        println!("\n  元数据内容:");
                        println!("{}", serde_json::to_string_pretty(&meta_json)?);
                    }

                    if let Ok(bnf_json) = serde_json::from_slice::<serde_json::Value>(bnf_data) {
                        println!("\n  BNF 提取数据内容:");
                        println!("{}", serde_json::to_string_pretty(&bnf_json)?);
                    }
                } else if let Some((owner, refs)) = capsule.as_cap2_content() {
                    println!("\n📦 Cap2 内容:");
                    println!("  所有者: {}", owner);
                    println!("  引用数量: {}", refs.len());
                }
            }
        }
        Err(e) => {
            println!("\n❌ 查询或解密失败: {}", e);
            println!("\n提示:");
            println!("1. 确保数据库中有对应 owner 的私钥");
            println!("2. 确保私钥与胶囊加密时使用的公钥匹配");
            println!("3. 确保数据库中有对应的胶囊数据");
        }
    }

    println!("\n=== 测试完成 ===");
    Ok(())
}
