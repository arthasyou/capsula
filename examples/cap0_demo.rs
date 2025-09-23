//! Capsule 数据胶囊封装演示
//!
//! 演示如何创建完整的数据胶囊（Capsule，包含Cap0载荷）
//! - 使用模拟的原始数据（存放在raw_data目录）
//! - 使用producer_private.pem进行签名
//! - 使用owner_public.pem进行加密
//! - 生成包含头部信息、策略控制、密钥环的完整Capsule结构

use std::{fs, path::Path};

use capsula_core::{Cap0, Capsule, ContentType, Keyring};
use capsula_key::RsaKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Capsule 数据胶囊封装演示 ===\n");

    // 1. 准备模拟数据
    prepare_raw_data()?;

    // 2. 加载密钥
    println!("正在加载密钥...");
    let (signing_key, owner_spki_der) = load_keys()?;
    println!("✓ 密钥加载成功");

    // 3. 创建密钥环
    let mut keyring = Keyring::new();
    println!("✓ 密钥环创建完成");

    // 4. 准备AAD（额外认证数据）
    let aad = b"medical:blood_test:v1.0"; // 简单的AAD字符串
    println!("✓ AAD准备完成");

    // 5. 封装Cap0（外部存储模式）
    println!("\n正在封装Cap0数据胶囊...");
    let mut external_seal = Cap0::seal(
        Path::new("temp/raw_data/medical_report.pdf"), // 主要文档
        Path::new("temp/encrypted_files/report.enc"),  // 加密后主文档
        Path::new("temp/raw_data/test_results.txt"),   // 附加文档
        Path::new("temp/encrypted_files/results.enc"), // 加密后附加文档
        (ContentType::Pdf, ContentType::Text),         // 内容类型
        aad,                                           // 额外认证数据
        &mut keyring,                                  // 密钥环
        &owner_spki_der,                               // 所有者公钥
        &signing_key,                                  // 签名密钥
    )?;

    println!("✓ Cap0预封装完成，加密文件已生成");

    // 6. 模拟上传到外部存储并设置URI
    println!("\n正在模拟上传到外部存储...");

    // 模拟上传主文档
    let main_storage_uri = "s3://medical-bucket/patient-001/report.enc".to_string();
    external_seal.set_origin_uri(main_storage_uri.clone())?;

    // 模拟上传附加文档
    let text_storage_uri = "s3://medical-bucket/patient-001/results.enc".to_string();
    external_seal.set_origin_text_uri(text_storage_uri.clone())?;

    // 转换为最终的Cap0
    let cap0 = external_seal.into_cap0()?;
    println!("✓ Cap0封装完成");
    println!("  - 主文档URI: {}", main_storage_uri);
    println!("  - 附加文档URI: {}", text_storage_uri);

    // 7. 包装成完整的数据胶囊 (Capsule)
    println!("\n正在创建Capsule数据胶囊...");
    let capsule = Capsule::with_cap0(
        "cid:QH9OhT7vR4oJZ+MyV3kfdQ==".to_string(),  // 胶囊唯一ID
        "medical.blood_test".to_string(),            // 内容类型
        "policy://medical/read_decrypt".to_string(), // 策略URI
        vec!["Read".to_string()],                    // 权限列表
        keyring,                                     // 密钥环
        cap0,                                        // Cap0载荷
        Some("Central Hospital".to_string()),        // 创建者
    )?;
    println!("✓ Capsule数据胶囊创建完成");

    // 8. 序列化保存Capsule
    println!("\n正在保存Capsule胶囊...");
    let capsule_json = serde_json::to_string_pretty(&capsule)?;
    fs::write("temp/capsule_medical.json", &capsule_json)?;
    println!("✓ Capsule胶囊已保存到: temp/capsule_medical.json");

    // 9. 显示Capsule信息
    println!("\n=== Capsule数据胶囊信息 ===");
    println!("胶囊ID: {}", capsule.header.id);
    println!("胶囊版本: {}", capsule.header.version);
    println!("胶囊阶段: {:?}", capsule.header.stage);
    println!("内容类型: {}", capsule.header.content_type);
    println!("创建时间: {}", capsule.header.created_at);
    println!("创建者: {:?}", capsule.header.creator);
    println!("载荷类型: {}", capsule.get_payload_type());
    println!("策略URI: {}", capsule.policy.policy_uri);
    println!("权限列表: {:?}", capsule.policy.permissions);
    println!("密钥环大小: {} 个密钥", capsule.keyring.len());

    // 显示载荷中Cap0的信息
    if let Some(cap0) = capsule.as_cap0() {
        println!("\n=== 载荷Cap0信息 ===");
        println!("主文档内容类型: {:?}", cap0.origin.content_type);
        println!("附加文档内容类型: {:?}", cap0.origin_text.content_type);
        println!("主文档存储URI: {}", cap0.origin.get_external_uri()?);
        println!("附加文档存储URI: {}", cap0.origin_text.get_external_uri()?);
        println!("主文档签名算法: {}", cap0.origin.proof.signature.alg);
        println!("附加文档签名算法: {}", cap0.origin_text.proof.signature.alg);
        if !cap0.origin.proof.signature.author_hint.is_empty() {
            println!(
                "主文档作者提示: {}",
                cap0.origin.proof.signature.author_hint
            );
        }
        if !cap0.origin_text.proof.signature.author_hint.is_empty() {
            println!(
                "附加文档作者提示: {}",
                cap0.origin_text.proof.signature.author_hint
            );
        }
    }

    // 9. 清理临时文件（保留加密文件以供查看）
    println!("\n正在清理临时文件...");
    cleanup_demo_files()?;
    println!("✓ 临时文件已清理");

    println!("\n=== Capsule数据胶囊封装演示完成 ===");
    println!("Capsule数据胶囊成功创建并保存为JSON格式！");
    println!("生成的文件:");
    println!("  - temp/capsule_medical.json (完整的Capsule数据胶囊JSON)");
    println!("  - temp/encrypted_files/report.enc (加密的医疗报告)");
    println!("  - temp/encrypted_files/results.enc (加密的检测结果)");

    Ok(())
}

/// 准备模拟的原始数据
fn prepare_raw_data() -> Result<(), Box<dyn std::error::Error>> {
    println!("正在准备模拟数据...");

    // 创建目录
    fs::create_dir_all("temp/raw_data")?;
    fs::create_dir_all("temp/encrypted_files")?;

    // 创建模拟的医疗报告PDF（以文本形式模拟）
    let medical_report = r#"%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 200
>>
stream
BT
/F1 12 Tf
50 750 Td
(医疗检查报告) Tj
0 -20 Td
(患者: 张三) Tj
0 -20 Td
(检查日期: 2024-09-23) Tj
0 -20 Td
(检查项目: 血液检测) Tj
0 -20 Td
(结果: 正常) Tj
ET
endstream
endobj

xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000204 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
456
%%EOF"#;

    fs::write("temp/raw_data/medical_report.pdf", medical_report)?;

    // 创建模拟的检测结果文本
    let test_results = r#"血液检测结果报告
==================

患者信息:
- 姓名: 张三
- 年龄: 35岁
- 性别: 男
- 患者ID: P001

检测项目:
1. 血常规检查
   - 白细胞计数: 6.5 × 10^9/L (正常范围: 4.0-10.0)
   - 红细胞计数: 4.8 × 10^12/L (正常范围: 4.0-5.5)
   - 血红蛋白: 145 g/L (正常范围: 120-160)
   - 血小板计数: 280 × 10^9/L (正常范围: 100-300)

2. 生化检查
   - 血糖: 5.2 mmol/L (正常范围: 3.9-6.1)
   - 总胆固醇: 4.8 mmol/L (正常范围: <5.2)
   - 甘油三酯: 1.2 mmol/L (正常范围: <1.7)

结论: 所有检测指标均在正常范围内

报告日期: 2024-09-23
检测机构: 中心医院检验科
医师签名: 李医生"#;

    fs::write("temp/raw_data/test_results.txt", test_results)?;

    println!("✓ 模拟数据准备完成");
    println!("  - 医疗报告: temp/raw_data/medical_report.pdf");
    println!("  - 检测结果: temp/raw_data/test_results.txt");

    Ok(())
}

/// 加载密钥文件
fn load_keys() -> Result<(RsaKey, Vec<u8>), Box<dyn std::error::Error>> {
    // 加载生产者私钥（用于签名）
    let producer_private_pem = fs::read_to_string("temp/keys/producer_private.pem")?;
    let signing_key = RsaKey::from_pkcs8_pem(&producer_private_pem)?;

    // 加载所有者公钥（用于加密）
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

/// 清理演示文件
fn cleanup_demo_files() -> Result<(), Box<dyn std::error::Error>> {
    // 只删除原始数据目录，保留加密文件供查看
    if Path::new("temp/raw_data").exists() {
        fs::remove_dir_all("temp/raw_data")?;
    }

    // 保留以下文件供查看:
    // - temp/capsule_medical.json (Capsule胶囊JSON)
    // - temp/encrypted_files/ (加密文件目录)

    Ok(())
}
