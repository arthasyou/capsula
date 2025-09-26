/// 测试胶囊插入程序
use capsula_bank::{
    db::{init_db, capsule},
    models::capsule::CapsuleRecord,
    settings::Settings,
};
use serde_json::json;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    tracing_subscriber::fmt().with_target(false).init();

    println!("========================================");
    println!("    胶囊测试程序");
    println!("========================================\n");

    // 加载配置
    println!("📋 加载配置文件...");
    let settings = Settings::load("config/services.toml")?;
    println!("✅ 配置加载成功\n");

    // 连接数据库
    println!("🔌 连接数据库...");
    init_db(settings.surrealdb).await?;
    println!("✅ 数据库连接成功\n");

    // 创建测试胶囊数据（模拟 capsula-core 的 Capsule 结构）
    println!("📦 创建测试胶囊...");
    
    let capsule_id = format!("cid:{}", Uuid::new_v4().to_string());
    let owner_id = "user_001";
    
    // 构造完整的胶囊数据（模拟 capsula-core::Capsule 的 JSON 结构）
    let capsule_data = json!({
        "header": {
            "id": &capsule_id,
            "version": "1.0",
            "stage": "first",
            "content_type": "medical.blood_test",
            "created_at": "2025-01-14T10:30:00Z",
            "creator": "医院A实验室",
            "metadata": {
                "patient_id": "P123456",
                "test_date": "2025-01-14",
                "department": "内科"
            }
        },
        "aad_binding": {
            "hash": "SHA256:abcdef1234567890",
            "components": ["header", "policy", "payload"],
            "timestamp": "2025-01-14T10:30:00Z"
        },
        "policy": {
            "policy_uri": "policy://medical/blood_test",
            "permissions": ["readonly", "full_usage"],
            "constraints": {
                "valid_until": "2025-12-31",
                "max_access": "100"
            }
        },
        "keyring": {
            "recipients": [
                {
                    "recipient_id": "doctor_001",
                    "encrypted_key": "base64_encrypted_key_here"
                }
            ]
        },
        "payload": {
            "type": "Cap0",
            "data": {
                "origin": {
                    "ct": "encrypted_blood_test_data_here",
                    "uri": "s3://medical-data/blood_tests/test_001.enc",
                    "size": 2048,
                    "content_type": "application/pdf"
                },
                "origin_text": {
                    "ct": "encrypted_extracted_text_here",
                    "uri": "s3://medical-data/blood_tests/test_001_text.enc",
                    "size": 512,
                    "content_type": "text/plain"
                }
            }
        },
        "integrity": {
            "signature": {
                "alg": "Ed25519",
                "sig": "signature_value_here",
                "signer": "医院A"
            },
            "digest": {
                "alg": "SHA-256",
                "hash": "hash_value_here"
            },
            "watermark": null
        },
        "audit_ref": "audit://medical/2025/01/14/blood_test_001"
    });
    
    // 创建胶囊记录
    let capsule_record = CapsuleRecord::new(
        capsule_id.clone(),
        "1.0".to_string(),
        "first".to_string(),
        "medical.blood_test".to_string(),
        owner_id.to_string(),
        capsule_data.clone(),
    )
    .with_creator("医院A实验室".to_string())
    .add_metadata("patient_id".to_string(), "P123456".to_string())
    .add_metadata("test_type".to_string(), "全血常规".to_string());
    
    // 插入到数据库
    let created_capsule = capsule::create_capsule(capsule_record).await?;
    
    println!("✅ 胶囊创建成功！\n");
    println!("胶囊详情：");
    println!("  ID: {}", created_capsule.capsule_id);
    println!("  版本: {}", created_capsule.version);
    println!("  阶段: {}", created_capsule.stage);
    println!("  类型: {}", created_capsule.content_type);
    println!("  所有者: {}", created_capsule.owner_id);
    println!("  创建者: {:?}", created_capsule.creator);
    println!("  创建时间: {}", 
        chrono::DateTime::from_timestamp(created_capsule.created_at, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "Invalid timestamp".to_string())
    );
    println!("  元数据: {:?}", created_capsule.metadata);
    
    // 查询刚插入的胶囊
    println!("\n📋 查询胶囊...");
    if let Some(queried_capsule) = capsule::get_capsule_by_id(&capsule_id).await? {
        println!("✅ 成功查询到胶囊");
        
        // 解析胶囊数据中的一些信息
        if let Some(header) = queried_capsule.capsule_data.get("header") {
            println!("\n📄 Header 信息：");
            println!("  版本: {:?}", header.get("version"));
            println!("  阶段: {:?}", header.get("stage"));
            println!("  内容类型: {:?}", header.get("content_type"));
        }
        
        if let Some(policy) = queried_capsule.capsule_data.get("policy") {
            println!("\n🔐 策略信息：");
            println!("  策略URI: {:?}", policy.get("policy_uri"));
            println!("  权限: {:?}", policy.get("permissions"));
        }
        
        if let Some(payload) = queried_capsule.capsule_data.get("payload") {
            println!("\n📦 载荷信息：");
            println!("  类型: {:?}", payload.get("type"));
            if let Some(data) = payload.get("data") {
                if let Some(origin) = data.get("origin") {
                    println!("  原始数据URI: {:?}", origin.get("uri"));
                    println!("  数据大小: {:?}", origin.get("size"));
                }
            }
        }
    } else {
        println!("❌ 未找到胶囊");
    }
    
    // 查询用户的所有胶囊
    println!("\n📋 查询用户的所有胶囊...");
    let user_capsules = capsule::get_capsules_by_owner(owner_id).await?;
    println!("✅ 用户 {} 有 {} 个胶囊", owner_id, user_capsules.len());
    for (i, cap) in user_capsules.iter().enumerate() {
        println!("  {}. {} - 类型: {}, 阶段: {}, 创建: {}", 
            i + 1, 
            cap.capsule_id,
            cap.content_type,
            cap.stage,
            chrono::DateTime::from_timestamp(cap.created_at, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "Invalid".to_string())
        );
    }
    
    // 测试搜索功能
    println!("\n🔍 搜索医疗类型的胶囊...");
    let medical_capsules = capsule::search_capsules(
        None,
        Some("medical.blood_test"),
        Some("first"),
    ).await?;
    println!("✅ 找到 {} 个医疗血液测试胶囊", medical_capsules.len());
    
    println!("\n========================================");
    println!("✨ 测试完成！");
    println!("========================================");

    Ok(())
}