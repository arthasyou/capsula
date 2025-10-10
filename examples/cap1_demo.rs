//! Cap1 数据胶囊封装演示
//!
//! 演示如何创建1阶数据胶囊（Cap1，解释层）
//! - 基于已有的Cap0数据胶囊
//! - 封装元数据和BNF提取的结构化数据
//! - 使用producer_private.pem进行签名（证明数据来源）
//! - 使用owner_public.pem进行加密（保护数据隐私，只有owner能解密）
//! - 演示完整的封装和解封流程
//! - 生成包含解释层信息的完整Capsule结构
//! - 将胶囊插入数据库

use std::fs;

use capsula_bank::{
    db::{capsule as db_capsule, init_db},
    models::capsule::CapsuleRecord,
    settings::Settings,
};
use capsula_core::{Cap1, Capsule, ContentType, Keyring};
use capsula_key::RsaKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Cap1 数据胶囊封装演示 ===\n");

    // 1. 准备模拟数据
    prepare_demo_data()?;

    // 2. 加载密钥
    println!("正在加载密钥...");
    let (signing_key, owner_spki_der) = load_keys()?;
    println!("✓ 密钥加载成功");

    // 3. 创建密钥环
    let mut keyring = Keyring::new();
    println!("✓ 密钥环创建完成");

    // 4. 准备AAD（额外认证数据）
    let aad = b"medical:blood_test:interpretation:v1.0";
    println!("✓ AAD准备完成");

    // 5. 准备元数据（JSON格式）
    let meta_data = prepare_meta_data()?;
    println!("\n正在准备元数据...");
    println!("✓ 元数据准备完成，大小: {} 字节", meta_data.len());

    // 6. 准备BNF提取的结构化数据（JSON格式）
    let bnf_extract_data = prepare_bnf_extract_data()?;
    println!("\n正在准备BNF提取数据...");
    println!(
        "✓ BNF提取数据准备完成，大小: {} 字节",
        bnf_extract_data.len()
    );

    // 7. 封装Cap1（内联存储模式）
    println!("\n正在封装Cap1数据胶囊...");
    let cap1 = Cap1::seal(
        "cid:QH9OhT7vR4oJZ+MyV3kfdQ==".to_string(), // 关联的Cap0 ID
        &meta_data,                                 // 元数据
        &bnf_extract_data,                          // BNF提取数据
        (ContentType::Json, ContentType::Json),     // 内容类型
        aad,                                        // 额外认证数据
        &mut keyring,                               // 密钥环
        &owner_spki_der,                            /* 所有者公钥（用于加密DEK，
                                                     * 确保只有owner能解密） */
        &signing_key, // 生产者私钥（用于签名，证明数据来源）
        None,         // 暂不使用ZKP证明
    )?;
    println!("✓ Cap1封装完成");

    // 8. 包装成完整的数据胶囊 (Capsule)
    println!("\n正在创建Capsule数据胶囊...");
    let capsule = Capsule::with_cap1(
        "cid:Cap1-Interpretation-001".to_string(), // 胶囊唯一ID
        "medical.blood_test.interpretation".to_string(), // 内容类型
        "policy://medical/read_analyze".to_string(), // 策略URI
        vec!["Read".to_string(), "Analyze".to_string()], // 权限列表
        keyring,                                   // 密钥环
        cap1,                                      // Cap1载荷
        Some("Medical AI Assistant".to_string()),  // 创建者
    )?;
    println!("✓ Capsule数据胶囊创建完成");

    // 9. 序列化保存Capsule
    println!("\n正在保存Capsule胶囊...");
    let capsule_json = serde_json::to_string_pretty(&capsule)?;
    fs::write("temp/capsule_interpretation.json", &capsule_json)?;
    println!("✓ Capsule胶囊已保存到: temp/capsule_interpretation.json");

    // 10. 插入数据库
    println!("\n=== 插入数据库 ===");

    // 加载配置
    println!("正在加载配置...");
    let cfg = Settings::load("crates/capsula-bank/config/services.toml")?;
    println!("✓ 配置加载成功");

    // 初始化数据库连接
    println!("\n正在连接数据库...");
    init_db(cfg.surrealdb).await?;
    println!("✓ 数据库连接成功");

    // 将 capsule JSON 字符串转换为 Value
    let capsule_data: serde_json::Value = serde_json::from_str(&capsule_json)?;

    // 创建 CapsuleRecord
    let owner_id = "P001"; // 与元数据中的 Patient 001 对应
    let capsule_record = CapsuleRecord::from_json(capsule_data, owner_id.to_string())
        .ok_or("Failed to create CapsuleRecord from JSON")?;

    // 插入数据库（如果已存在则先删除）
    println!("\n正在插入胶囊到数据库...");
    let capsule_id = capsule_record.capsule_id.clone();

    // 尝试删除已存在的记录
    let _ = db_capsule::delete_capsule(&capsule_id).await;

    let created = db_capsule::create_capsule(capsule_record).await?;
    println!("✓ 胶囊插入成功");

    // 显示插入结果
    println!("\n=== 插入结果 ===");
    println!("胶囊 ID: {}", created.capsule_id);
    println!("所有者 ID: {}", created.owner_id);
    println!("内容类型: {}", created.content_type);
    println!("版本: {}", created.version);
    println!("阶段: {}", created.stage);
    println!("创建时间: {}", created.created_at);

    println!("\n=== Cap1数据胶囊封装演示完成 ===");
    println!("Cap1数据胶囊成功创建、保存并插入数据库！");
    println!("生成的文件:");
    println!("  - temp/capsule_interpretation.json (完整的Cap1数据胶囊JSON)");
    println!("  - temp/cap1_meta.json (元数据示例)");
    println!("  - temp/cap1_bnf_extract.json (BNF提取数据示例)");
    println!("\n数据库记录:");
    println!("  - capsules 表中已插入胶囊记录");
    println!("  - 胶囊 ID: {}", created.capsule_id);

    Ok(())
}

/// 准备演示用的元数据
fn prepare_meta_data() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 创建模拟的元数据（6元素向量部分）
    let meta = serde_json::json!({
        "collector": {
            "name": "Central Hospital",
            "id": "hospital-001",
            "department": "Laboratory",
            "certified": true
        },
        "owner": {
            "name": "Patient 001",
            "id": "P001",
            "consent_given": true,
            "consent_date": "2024-09-20"
        },
        "collection_info": {
            "collected_at": "2024-09-23T08:30:00Z",
            "sample_type": "Blood",
            "sample_id": "BLD-20240923-001",
            "collection_method": "Venipuncture"
        },
        "processing_info": {
            "processed_at": "2024-09-23T09:15:00Z",
            "processor": "李医生",
            "equipment_id": "EQ-XYZ-789",
            "quality_check": "Passed"
        },
        "sensitivity": {
            "level": "High",
            "category": "Medical",
            "retention_period_days": 3650,
            "encryption_required": true
        }
    });

    let meta_bytes = serde_json::to_vec_pretty(&meta)?;

    // 保存示例文件
    fs::create_dir_all("temp")?;
    fs::write("temp/cap1_meta.json", &meta_bytes)?;

    Ok(meta_bytes)
}

/// 准备BNF提取的结构化数据
fn prepare_bnf_extract_data() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 创建模拟的BNF提取数据
    // 这些数据是从原始血液检测报告中通过BNF语法规则提取和标准化的
    let bnf_extract = serde_json::json!({
        "test_type": "Blood Chemistry Panel",
        "test_date": "2024-09-23",
        "patient_id": "P001",
        "tests": [
            {
                "category": "Complete Blood Count",
                "items": [
                    {
                        "name": "White Blood Cell Count",
                        "code": "WBC",
                        "value": 6.5,
                        "unit": "10^9/L",
                        "reference_range": {
                            "min": 4.0,
                            "max": 10.0
                        },
                        "status": "Normal",
                        "flag": null
                    },
                    {
                        "name": "Red Blood Cell Count",
                        "code": "RBC",
                        "value": 4.8,
                        "unit": "10^12/L",
                        "reference_range": {
                            "min": 4.0,
                            "max": 5.5
                        },
                        "status": "Normal",
                        "flag": null
                    },
                    {
                        "name": "Hemoglobin",
                        "code": "HGB",
                        "value": 145.0,
                        "unit": "g/L",
                        "reference_range": {
                            "min": 120.0,
                            "max": 160.0
                        },
                        "status": "Normal",
                        "flag": null
                    },
                    {
                        "name": "Platelet Count",
                        "code": "PLT",
                        "value": 280.0,
                        "unit": "10^9/L",
                        "reference_range": {
                            "min": 100.0,
                            "max": 300.0
                        },
                        "status": "Normal",
                        "flag": null
                    }
                ]
            },
            {
                "category": "Blood Chemistry",
                "items": [
                    {
                        "name": "Blood Glucose",
                        "code": "GLU",
                        "value": 5.2,
                        "unit": "mmol/L",
                        "reference_range": {
                            "min": 3.9,
                            "max": 6.1
                        },
                        "status": "Normal",
                        "flag": null
                    },
                    {
                        "name": "Total Cholesterol",
                        "code": "CHOL",
                        "value": 4.8,
                        "unit": "mmol/L",
                        "reference_range": {
                            "min": 0.0,
                            "max": 5.2
                        },
                        "status": "Normal",
                        "flag": null
                    },
                    {
                        "name": "Triglycerides",
                        "code": "TRIG",
                        "value": 1.2,
                        "unit": "mmol/L",
                        "reference_range": {
                            "min": 0.0,
                            "max": 1.7
                        },
                        "status": "Normal",
                        "flag": null
                    }
                ]
            }
        ],
        "summary": {
            "total_tests": 7,
            "normal_count": 7,
            "abnormal_count": 0,
            "critical_count": 0,
            "overall_status": "Normal",
            "interpretation": "All test results are within normal reference ranges. No abnormalities detected."
        },
        "metadata": {
            "extracted_at": "2024-09-23T10:00:00Z",
            "extraction_version": "BNF-Medical-v1.2",
            "confidence_score": 0.98,
            "validation_status": "Verified"
        }
    });

    let bnf_bytes = serde_json::to_vec_pretty(&bnf_extract)?;

    // 保存示例文件
    fs::write("temp/cap1_bnf_extract.json", &bnf_bytes)?;

    Ok(bnf_bytes)
}

/// 准备演示数据
fn prepare_demo_data() -> Result<(), Box<dyn std::error::Error>> {
    println!("正在准备演示数据...");
    fs::create_dir_all("temp")?;
    println!("✓ 演示目录准备完成");
    Ok(())
}

/// 加载密钥文件
fn load_keys() -> Result<(RsaKey, Vec<u8>), Box<dyn std::error::Error>> {
    // 加载生产者私钥（用于签名）
    let producer_private_pem = fs::read_to_string("temp/keys/producer_private.pem")?;
    let signing_key = RsaKey::from_pkcs8_pem(&producer_private_pem)?;

    // 加载所有者公钥（用于加密DEK）
    let owner_public_pem = fs::read_to_string("temp/keys/owner_public.pem")?;

    // 将PEM格式的公钥转换为DER格式
    let owner_public_der = parse_pem_to_der(&owner_public_pem)?;

    Ok((signing_key, owner_public_der))
}

/// 将PEM格式公钥转换为DER格式
fn parse_pem_to_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 移除PEM头尾和换行符，只保留base64内容
    let base64_content = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    // 解码base64
    let der_bytes = capsula_crypto::base64::decode(&base64_content)?;

    Ok(der_bytes)
}

/// 加载所有者私钥用于解密
fn load_owner_private_key() -> Result<RsaKey, Box<dyn std::error::Error>> {
    // 加载所有者私钥（用于解密）
    let owner_private_pem = fs::read_to_string("temp/keys/owner_private.pem")?;
    let decryption_key = RsaKey::from_pkcs8_pem(&owner_private_pem)?;
    Ok(decryption_key)
}
