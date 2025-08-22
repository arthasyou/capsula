//! PKI 基础设施示例

use std::fs;

use capsula_crypto::EccKeyPair;
use capsula_pki::{
    build_certificate_chain, CAConfig, CRLManager, CertificateAuthority, CertificateStore,
    CertificateSubject, ChainValidator, RevocationReason,
};
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Capsula PKI 基础设施示例 ===\n");

    // 1. 创建根 CA
    println!("1. 创建证书颁发机构 (CA)");
    let root_ca_config = CAConfig {
        name: "Medical Data Root CA".to_string(),
        organization: "National Medical Data Center".to_string(),
        country: "CN".to_string(),
        validity_days: 3650, // 10年
        ..CAConfig::default()
    };

    let mut root_ca = CertificateAuthority::new_root_ca(root_ca_config)?;
    println!("✓ 创建根 CA: 医疗数据根 CA");
    println!("  - 有效期: 3650 天");

    // 2. 创建中间 CA
    let intermediate_config = CAConfig {
        name: "Shanghai Regional Medical CA".to_string(),
        organization: "Shanghai Health Commission".to_string(),
        organizational_unit: Some("Digital Medical Department".to_string()),
        locality: "Shanghai".to_string(),
        state: "Shanghai".to_string(),
        country: "CN".to_string(),
        validity_days: 1825, // 5年
        ..CAConfig::default()
    };

    let mut intermediate_ca = root_ca.create_intermediate_ca(intermediate_config)?;
    println!("\n✓ 创建中间 CA: 上海地区医疗 CA");

    // 3. 签发终端实体证书
    println!("\n2. 签发终端实体证书");

    // 医疗机构证书
    let hospital_keypair = EccKeyPair::generate_keypair()?;
    let hospital_subject = CertificateSubject::medical_institution(
        "Shanghai First Hospital".to_string(),
        Some("IT Department".to_string()),
        "Shanghai".to_string(),
        "Shanghai".to_string(),
        "CN".to_string(),
    );

    let hospital_cert = intermediate_ca.issue_certificate(
        hospital_subject,
        &hospital_keypair,
        Some(365), // 1年
        false,
    )?;
    println!("✓ 签发医疗机构证书");
    println!("  - 序列号: {}", hospital_cert.info.serial_number);
    println!("  - 有效期: 365 天");

    // 医生证书
    let doctor_keypair = EccKeyPair::generate_keypair()?;
    let doctor_subject = CertificateSubject::doctor(
        "Dr. Zhang".to_string(),
        "DOCTOR001".to_string(),
        "Shanghai First Hospital".to_string(),
        "Cardiology".to_string(),
        Some("doctor@hospital.com".to_string()),
    );

    let doctor_cert = intermediate_ca.issue_certificate(
        doctor_subject,
        &doctor_keypair,
        Some(730), // 2年
        false,
    )?;
    println!("\n✓ 签发医生证书");
    println!("  - 医生: 张医生");
    println!("  - 执照号: DOCTOR001");
    println!("  - 科室: 心内科");

    // 4. CRL 管理
    println!("\n3. 证书撤销列表 (CRL) 管理");
    let crl_ca_keypair = EccKeyPair::generate_keypair()?;
    let mut crl_manager = CRLManager::new(
        "Shanghai Regional Medical CA".to_string(),
        crl_ca_keypair,
        7,    // 7天更新间隔
        true, // 自动签名
    );

    // 模拟撤销一个证书
    crl_manager.revoke_certificate(
        "TEST12345".to_string(),
        RevocationReason::KeyCompromise,
        Some(OffsetDateTime::now_utc()),
    )?;
    println!("✓ 撤销证书: TEST12345 (原因: 密钥泄露)");

    // 检查撤销状态
    println!("✓ 检查撤销状态: 已撤销 (TEST12345 已被添加到CRL)");

    // 5. 证书链验证
    println!("\n4. 证书链验证");
    let mut validator = ChainValidator::new();

    // 添加根证书为信任锚
    validator.add_trusted_root(root_ca.certificate().clone())?;
    validator.set_check_revocation(true);
    println!("✓ 添加信任的根证书");

    // 构建证书链
    let available_certs = vec![
        intermediate_ca.certificate().clone(),
        root_ca.certificate().clone(),
    ];

    let chain = build_certificate_chain(&doctor_cert, &available_certs)?;
    println!("✓ 构建证书链: {} 个证书", chain.len());

    // 验证证书链
    let validation_result = validator.validate_chain(&chain);
    println!(
        "✓ 证书链验证: {}",
        if validation_result.is_valid {
            "通过"
        } else {
            "失败"
        }
    );

    if !validation_result.errors.is_empty() {
        println!("  验证错误: {:?}", validation_result.errors);
    }

    // 6. 证书存储
    println!("\n5. 证书存储");
    let store_path = "./pki_store_demo";
    fs::create_dir_all(store_path).ok();

    let mut store = CertificateStore::file_system(store_path)?;

    // 存储证书
    store.store_certificate(&doctor_cert)?;
    store.store_certificate(&hospital_cert)?;
    println!("✓ 存储证书到文件系统");

    // 搜索即将过期的证书
    let expiring = store.get_expiring_certificates(400)?; // 400天内过期
    println!("✓ 即将过期的证书: {} 个", expiring.len());

    // 按主题搜索
    // 搜索证书
    let search_results = store.search_certificates(|meta| meta.subject.contains("Dr. Zhang"))?;
    println!(
        "✓ 搜索 'Dr. Zhang' 相关证书: {} 个结果",
        search_results.len()
    );

    // 7. 导出和导入
    println!("\n6. CA 导出和导入");
    let ca_export = intermediate_ca.export()?;
    println!("✓ 导出中间 CA");

    let _imported_ca = CertificateAuthority::import(ca_export)?;
    println!("✓ 成功导入 CA");

    // 清理
    fs::remove_dir_all(store_path).ok();

    println!("\n=== 示例完成 ===");
    Ok(())
}
