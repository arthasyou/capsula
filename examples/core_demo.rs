//! 数据胶囊核心功能演示
//! 
//! 展示如何使用capsula-core进行数据的封包和解包

use capsula_core::{create_medical_capsule, decrypt_medical_capsule_rsa};
use capsula_key::{RsaKey, Key};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 数据胶囊核心功能演示 ===\n");

    // 1. 生成密钥
    println!("1. 生成密钥...");
    let doctor_key = RsaKey::generate_2048()?;
    let nurse_key = RsaKey::generate_2048()?;
    let patient_key = RsaKey::generate_2048()?;
    println!("   ✓ 医生密钥已生成");
    println!("   ✓ 护士密钥已生成");
    println!("   ✓ 患者密钥已生成\n");

    // 2. 准备医疗数据
    println!("2. 准备医疗数据...");
    let medical_data = serde_json::json!({
        "patient_id": "P001",
        "test_type": "血常规检查",
        "results": {
            "白细胞计数": "6.8 × 10^9/L (正常)",
            "红细胞计数": "4.5 × 10^12/L (正常)",
            "血红蛋白": "140 g/L (正常)",
            "血小板计数": "280 × 10^9/L (正常)"
        },
        "doctor": "李医生",
        "date": "2024-01-15",
        "notes": "各项指标正常，建议定期复查"
    });
    let medical_data_bytes = serde_json::to_vec(&medical_data)?;
    println!("   ✓ 医疗数据已准备: {} 字节\n", medical_data_bytes.len());

    // 3. 创建授权用户列表
    println!("3. 设置授权用户...");
    let authorized_users = vec![
        ("nurse_001".to_string(), &nurse_key as &dyn Key),
        ("patient_001".to_string(), &patient_key as &dyn Key),
    ];
    println!("   ✓ 护士授权: nurse_001");
    println!("   ✓ 患者授权: patient_001\n");

    // 4. 创建医疗数据胶囊
    println!("4. 创建数据胶囊...");
    let capsule = create_medical_capsule(
        medical_data_bytes,
        "blood_test",
        "中心医院".to_string(),
        "张三".to_string(),
        &doctor_key,
        &authorized_users,
        Some(30), // 30天有效期
    )?;
    
    println!("   ✓ 胶囊已创建");
    println!("   ✓ 胶囊ID: {}", capsule.header.id);
    println!("   ✓ 数据类型: {}", capsule.header.type_);
    println!("   ✓ 授权用户数: {}", capsule.keyring.len());
    println!("   ✓ 有效期: {:?}\n", capsule.meta.expires_at);

    // 5. 序列化胶囊（用于传输或存储）
    println!("5. 序列化胶囊...");
    let capsule_json = serde_json::to_string_pretty(&capsule)?;
    println!("   ✓ 胶囊已序列化为JSON");
    println!("   ✓ JSON大小: {} 字节\n", capsule_json.len());

    // 6. 护士访问数据
    println!("6. 护士访问数据...");
    // TODO: 由于当前密钥包装实现还不完整，这里会失败
    // 需要完善RSA密钥解包功能
    
    // 创建新的护士密钥用于解密测试
    let nurse_decrypt_key = RsaKey::generate_2048()?;
    match decrypt_medical_capsule_rsa(
        &capsule,
        nurse_decrypt_key,
        "nurse_001".to_string(),
        vec![], // TODO: 需要医生的公钥
    ) {
        Ok(result) => {
            println!("   ✓ 护士成功解包数据");
            println!("   ✓ 验证状态: {:?}", result.verification);
            println!("   ✓ 原始数据大小: {} 字节", result.data.len());
        }
        Err(e) => {
            println!("   ⚠ 护士解包失败: {} (实现未完成)", e);
        }
    }

    // 7. 显示胶囊结构信息
    println!("\n7. 胶囊结构信息:");
    println!("   - 版本: {}", capsule.header.ver);
    println!("   - 阶段: {:?}", capsule.header.stage);
    println!("   - 生产者: {}", capsule.meta.producer);
    println!("   - 拥有者: {}", capsule.meta.owner);
    println!("   - 摘要算法: {}", capsule.meta.digest.alg);
    println!("   - 加密算法: {}", capsule.payload.enc);
    println!("   - 签名算法: {}", capsule.integrity.signature.alg);
    println!("   - 策略规则: {:?}", capsule.policy.simple_rules);

    println!("\n=== 演示完成 ===");
    println!("注意: 当前实现仍在开发中，某些功能可能不完整");

    Ok(())
}