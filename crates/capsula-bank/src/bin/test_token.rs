/// 测试令牌插入程序
use capsula_bank::{
    db::{init_db, token},
    models::token::{Token, TokenType},
    settings::Settings,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    tracing_subscriber::fmt().with_target(false).init();

    println!("========================================");
    println!("    令牌测试程序");
    println!("========================================\n");

    // 加载配置
    println!("📋 加载配置文件...");
    let settings = Settings::load("config/services.toml")?;
    println!("✅ 配置加载成功\n");

    // 连接数据库
    println!("🔌 连接数据库...");
    init_db(settings.surrealdb).await?;
    println!("✅ 数据库连接成功\n");

    // 创建测试令牌
    println!("🔑 创建测试令牌...");

    // 生成令牌ID和哈希（实际应用中应该使用加密库生成安全的令牌）
    let token_id = format!("tok_{}", Uuid::new_v4().to_string());
    let token_hash = format!("hash_{}", Uuid::new_v4().to_string()); // 实际应该是真实令牌的哈希值
    let capsule_id = format!("cap_{}", Uuid::new_v4().to_string()); // 模拟的胶囊ID

    // 创建令牌对象
    let test_token = Token::new(
        token_id.clone(),
        token_hash,
        TokenType::Access,
        capsule_id.clone(),                                         // 关联的胶囊ID
        "ownership",                                                // 使用所有权分子权限作为授权ID
        "user_001",                                                 // 测试用户ID
        "capsula-bank",                                             // 颁发者
        Utc::now().timestamp() + Duration::hours(24).num_seconds(), // 24小时后过期
    )
    .with_use_limit(100) // 限制使用100次
    .with_scopes(vec![
        "ownership".to_string(),  // 所有权分子权限
        "readonly".to_string(),   // 只读分子权限
        "full_usage".to_string(), // 完全使用分子权限
    ])
    .with_pubkey_binding("SHA256:abcd1234efgh5678ijkl9012mnop3456"); // 模拟的公钥指纹

    // 插入令牌到数据库
    let created_token = token::create_token(test_token).await?;

    println!("✅ 令牌创建成功！\n");
    println!("令牌详情：");
    println!("  ID: {}", created_token.token_id);
    println!("  类型: {:?}", created_token.token_type);
    println!("  胶囊ID: {}", created_token.capsule_id);
    println!("  持有者: {}", created_token.subject_id);
    println!("  授权ID: {}", created_token.grant_id);
    println!(
        "  过期时间: {}",
        chrono::DateTime::from_timestamp(created_token.expires_at, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "Invalid timestamp".to_string())
    );
    println!("  剩余使用次数: {:?}", created_token.remaining_uses);
    println!("  分子权限: {:?}", created_token.scopes);
    println!("  绑定公钥指纹: {:?}", created_token.bind_pubkey_fpr);

    // 查询刚插入的令牌
    println!("\n📋 查询令牌...");
    if let Some(queried_token) = token::get_token_by_id(&token_id).await? {
        println!("✅ 成功查询到令牌");
        println!("  状态: {:?}", queried_token.status);
        println!("  是否有效: {}", queried_token.is_valid());

        // 测试使用令牌一次
        println!("\n🔧 测试使用令牌...");
        if token::use_token(&token_id).await? {
            println!("✅ 令牌使用成功");

            // 再次查询以查看使用次数变化
            if let Some(used_token) = token::get_token_by_id(&token_id).await? {
                println!("  剩余使用次数: {:?}", used_token.remaining_uses);
                println!(
                    "  最后使用时间: {:?}",
                    used_token
                        .last_used_at
                        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string()))
                );
            }
        }
    } else {
        println!("❌ 未找到令牌");
    }

    // 查询用户的所有活跃令牌
    println!("\n📋 查询用户的所有活跃令牌...");
    let user_tokens = token::get_active_tokens_by_subject("user_001").await?;
    println!("✅ 用户 user_001 有 {} 个活跃令牌", user_tokens.len());
    for (i, t) in user_tokens.iter().enumerate() {
        println!(
            "  {}. {} - 胶囊: {}, 类型: {:?}, 过期: {}",
            i + 1,
            t.token_id,
            t.capsule_id,
            t.token_type,
            chrono::DateTime::from_timestamp(t.expires_at, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "Invalid".to_string())
        );
    }

    // 查询特定胶囊的所有令牌
    println!("\n📋 查询胶囊 {} 的所有令牌...", capsule_id);
    let capsule_tokens = token::get_tokens_by_capsule(&capsule_id).await?;
    println!("✅ 胶囊有 {} 个令牌", capsule_tokens.len());

    // 查询用户对特定胶囊的访问令牌
    println!("\n📋 查询用户对胶囊的访问权限...");
    if let Some(access_token) = token::get_token_for_capsule_access("user_001", &capsule_id).await?
    {
        println!("✅ 用户有访问权限，令牌ID: {}", access_token.token_id);
        println!("  权限范围: {:?}", access_token.scopes);
    } else {
        println!("❌ 用户没有该胶囊的访问权限");
    }

    println!("\n========================================");
    println!("✨ 测试完成！");
    println!("========================================");

    Ok(())
}
