//! 综合功能示例 - 医疗数据胶囊系统

use std::fs;

use capsula_crypto::{hash_data_hex, EccKeyPair, HashAlgorithm, LocationInfo};
use capsula_pki::{CAConfig, CertificateAuthority, CertificateStore, CertificateSubject};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct MedicalRecord {
    patient_id: String,
    patient_name: String,
    diagnosis: String,
    treatment: String,
    doctor: String,
    hospital: String,
    created_at: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DataCapsule {
    id: String,
    data_hash: String,
    encrypted_data: Vec<u8>, // 在实际应用中，这里应该是加密的数据
    signature: String,
    certificate_serial: String,
    created_at: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Capsula 医疗数据胶囊系统示例 ===\n");

    // 1. 建立 PKI 基础设施
    println!("1. 建立 PKI 基础设施");
    let ca_config = CAConfig {
        name: "Medical Data CA".to_string(),
        organization: "Example Hospital Group".to_string(),
        country: "CN".to_string(),
        validity_days: 3650,
        ..CAConfig::default()
    };

    let mut ca = CertificateAuthority::new_root_ca(ca_config)?;
    println!("✓ 创建医疗数据 CA");

    // 2. 为医生创建证书
    println!("\n2. 创建医生身份证书");
    let doctor_keypair = EccKeyPair::generate_keypair()?;
    let doctor_subject = CertificateSubject::doctor(
        "Dr. Li".to_string(),
        "DOC20240001".to_string(),
        "Example Central Hospital".to_string(),
        "Internal Medicine".to_string(),
        Some("doctor@example.com".to_string()),
    );

    let doctor_cert = ca.issue_certificate(
        doctor_subject,
        &doctor_keypair,
        Some(730), // 2年有效期
        false,
    )?;
    println!("✓ 签发医生证书");
    println!("  - 医生: 李医生 (ID: DOC20240001)");
    println!("  - 证书序列号: {}", doctor_cert.info.serial_number);

    // 3. 创建医疗记录
    println!("\n3. 创建医疗记录");
    let medical_record = MedicalRecord {
        patient_id: "P2024001".to_string(),
        patient_name: "测试患者".to_string(),
        diagnosis: "上呼吸道感染".to_string(),
        treatment: "抗生素治疗，建议休息".to_string(),
        doctor: "李医生".to_string(),
        hospital: "示例中心医院".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let record_json = serde_json::to_string_pretty(&medical_record)?;
    println!("✓ 创建医疗记录:");
    println!("{}", record_json);

    // 4. 创建数据胶囊
    println!("\n4. 创建数据胶囊");

    // 计算数据哈希
    let data_hash = hash_data_hex(record_json.as_bytes(), HashAlgorithm::Sha256);
    println!("✓ 计算数据哈希: {}", &data_hash[.. 32]);

    // 创建位置信息
    let location = LocationInfo {
        latitude: Some(39.9042),
        longitude: Some(116.4074),
        address: Some("示例中心医院".to_string()),
        institution_id: Some("HOSP2024001".to_string()),
        department: Some("内科".to_string()),
    };

    // 对数据进行签名
    let signature = doctor_keypair.sign_data(
        record_json.as_bytes(),
        location,
        Some("李医生".to_string()),
        Some("医疗记录签名".to_string()),
    )?;
    println!("✓ 医生签名数据");

    // 创建数据胶囊
    let capsule = DataCapsule {
        id: format!("CAP-{}", uuid::Uuid::new_v4()),
        data_hash: data_hash.clone(),
        encrypted_data: record_json.as_bytes().to_vec(), // 实际应用中应该加密
        signature: signature.to_json()?,
        certificate_serial: doctor_cert.info.serial_number.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    println!("✓ 创建数据胶囊");
    println!("  - ID: {}", capsule.id);
    println!("  - 数据大小: {} 字节", capsule.encrypted_data.len());

    // 5. 验证数据胶囊
    println!("\n5. 验证数据胶囊");

    // 验证数据完整性
    let computed_hash = hash_data_hex(&capsule.encrypted_data, HashAlgorithm::Sha256);
    let integrity_valid = computed_hash == capsule.data_hash;
    println!(
        "✓ 数据完整性验证: {}",
        if integrity_valid { "通过" } else { "失败" }
    );

    // 验证签名
    let signature_obj = capsula_crypto::DigitalSignature::from_json(&capsule.signature)?;
    let signature_valid =
        doctor_keypair.verify_signature(&capsule.encrypted_data, &signature_obj)?;
    println!(
        "✓ 签名验证: {}",
        if signature_valid { "通过" } else { "失败" }
    );

    // 6. 存储和检索
    println!("\n6. 证书存储管理");
    let store_path = "./demo_pki_store";
    fs::create_dir_all(store_path).ok();

    let mut store = CertificateStore::file_system(store_path)?;
    store.store_certificate(&doctor_cert)?;
    println!("✓ 存储医生证书");

    // 检索证书
    let _retrieved = store.get_certificate(&doctor_cert.info.serial_number)?;
    println!("✓ 检索证书: 成功");

    // 7. 审计日志
    println!("\n7. 审计信息");
    println!("✓ 操作记录:");
    println!("  - 时间: {}", capsule.created_at);
    println!(
        "  - 操作者: 李医生 (证书: {})",
        doctor_cert.info.serial_number
    );
    println!("  - 位置: 示例中心医院 内科");
    println!("  - 数据哈希: {}", &data_hash[.. 32]);

    // 清理
    fs::remove_dir_all(store_path).ok();

    println!("\n=== 示例完成 ===");
    println!("\n这个示例展示了如何使用 Capsula 系统：");
    println!("1. 建立 PKI 基础设施");
    println!("2. 创建和管理数字身份");
    println!("3. 安全地封装敏感数据");
    println!("4. 进行数字签名和验证");
    println!("5. 确保数据完整性和不可否认性");

    Ok(())
}

// 添加 uuid 依赖用于生成唯一ID
// 在实际使用中需要在 Cargo.toml 中添加:
// uuid = { version = "1.0", features = ["v4"] }
// chrono = "0.4"

// 临时实现 uuid 功能
mod uuid {
    pub struct Uuid;
    impl Uuid {
        pub fn new_v4() -> String {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            format!(
                "{:x}-{:x}-{:x}-{:x}",
                nanos as u32,
                (nanos >> 32) as u16,
                (nanos >> 48) as u16,
                (nanos >> 64) as u32
            )
        }
    }
}

// 临时实现 chrono 功能
mod chrono {
    pub struct Utc;
    impl Utc {
        pub fn now() -> DateTime {
            DateTime
        }
    }

    pub struct DateTime;
    impl DateTime {
        pub fn to_rfc3339(&self) -> String {
            time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        }
    }
}
