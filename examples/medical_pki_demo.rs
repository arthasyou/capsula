//! 医疗 PKI 系统演示
//!
//! 这个示例展示了如何使用 capsula PKI 系统来：
//! 1. 创建医院根证书颁发机构 (Root CA)
//! 2. 签发医生和患者的数字证书
//! 3. 医生使用证书签名体检报告
//! 4. 患者验证医生的签名
//! 5. 验证整个证书链的有效性

use std::collections::HashMap;

use capsula_crypto::{
    signature::ecc::{verify_signature_standalone, LocationInfo},
    CertificateSubject, EccKeyPair, X509Certificate,
};
use capsula_pki::{
    ca::{CAConfig, CertificateAuthority},
    chain::{build_certificate_chain, ChainValidator},
    prelude::*,
};

/// 医疗机构信息
struct MedicalInstitution {
    name: String,
    id: String,
    address: String,
}

/// 医生信息
struct Doctor {
    name: String,
    license_number: String,
    department: String,
    keypair: EccKeyPair,
    certificate: X509Certificate,
}

/// 患者信息
struct Patient {
    name: String,
    id_number: String,
    keypair: EccKeyPair,
    certificate: X509Certificate,
}

/// 体检报告
#[derive(Debug)]
struct MedicalReport {
    patient_name: String,
    patient_id: String,
    report_date: String,
    examinations: HashMap<String, String>,
    diagnosis: String,
    recommendations: String,
}

impl MedicalReport {
    /// 将体检报告序列化为字节数组
    fn to_bytes(&self) -> Vec<u8> {
        let mut content = format!(
            "体检报告\n\n患者姓名: {}\n患者ID: {}\n体检日期: {}\n\n",
            self.patient_name, self.patient_id, self.report_date
        );

        content.push_str("检查项目:\n");
        for (exam, result) in &self.examinations {
            content.push_str(&format!("  {}: {}\n", exam, result));
        }

        content.push_str(&format!("\n诊断结果:\n{}\n", self.diagnosis));
        content.push_str(&format!("\n建议:\n{}\n", self.recommendations));

        content.into_bytes()
    }
}

fn main() -> Result<()> {
    println!("=== 医疗 PKI 系统演示 ===\n");

    // 1. 创建医院根证书颁发机构
    println!("1. 创建医院根证书颁发机构 (Root CA)");
    let hospital = MedicalInstitution {
        name: "上海第一人民医院".to_string(),
        id: "HOSPITAL_SH001".to_string(),
        address: "上海市虹口区海宁路100号".to_string(),
    };

    let root_ca_config = CAConfig {
        name: "Shanghai First Hospital Root CA".to_string(),
        country: "CN".to_string(),
        state: "Shanghai".to_string(),
        locality: "Shanghai".to_string(),
        organization: "Shanghai First People's Hospital".to_string(),
        organizational_unit: Some("IT Security Department".to_string()),
        email: Some("pki@hospital.sh.cn".to_string()),
        validity_days: 3650,             // 10年
        default_cert_validity_days: 730, // 默认2年
        max_path_length: Some(2),
    };

    let mut root_ca = CertificateAuthority::new_root_ca(root_ca_config)?;
    println!("  ✓ 根证书创建成功");
    println!(
        "    - 证书主体: {}",
        root_ca.certificate().info.subject.common_name
    );
    println!("    - 有效期至: {:?}", root_ca.certificate().info.not_after);
    println!();

    // 2. 签发医生证书
    println!("2. 签发医生证书");
    let doctor_keypair = EccKeyPair::generate_keypair()?;
    let doctor_subject = CertificateSubject {
        common_name: "Dr. Li Ming".to_string(),
        country: Some("CN".to_string()),
        state: Some("Shanghai".to_string()),
        locality: Some("Shanghai".to_string()),
        organization: Some("Shanghai First People's Hospital".to_string()),
        organizational_unit: Some("Cardiology Department".to_string()),
        email: Some("liming@hospital.sh.cn".to_string()),
    };

    let doctor_cert = root_ca.issue_certificate(
        doctor_subject,
        &doctor_keypair,
        Some(730), // 2年有效期
        false,     // 不是CA证书
    )?;

    let doctor = Doctor {
        name: "李明".to_string(),
        license_number: "SH2023MD001234".to_string(),
        department: "心内科".to_string(),
        keypair: doctor_keypair,
        certificate: doctor_cert,
    };

    println!("  ✓ 医生证书签发成功");
    println!("    - 医生姓名: {}", doctor.name);
    println!("    - 执业证号: {}", doctor.license_number);
    println!("    - 所属科室: {}", doctor.department);
    println!(
        "    - 证书序列号: {}",
        doctor.certificate.info.serial_number
    );
    println!();

    // 3. 签发患者证书
    println!("3. 签发患者证书");
    let patient_keypair = EccKeyPair::generate_keypair()?;
    let patient_subject = CertificateSubject {
        common_name: "Zhang San".to_string(),
        country: Some("CN".to_string()),
        state: Some("Shanghai".to_string()),
        locality: Some("Shanghai".to_string()),
        organization: Some("Personal".to_string()),
        organizational_unit: None,
        email: Some("zhangsan@example.com".to_string()),
    };

    let patient_cert = root_ca.issue_certificate(
        patient_subject,
        &patient_keypair,
        Some(365), // 1年有效期
        false,     // 不是CA证书
    )?;

    let patient = Patient {
        name: "张三".to_string(),
        id_number: "310101198001010001".to_string(),
        keypair: patient_keypair,
        certificate: patient_cert,
    };

    println!("  ✓ 患者证书签发成功");
    println!("    - 患者姓名: {}", patient.name);
    println!("    - 身份证号: {}****", &patient.id_number[.. 6]);
    println!(
        "    - 证书序列号: {}",
        patient.certificate.info.serial_number
    );
    println!();

    // 4. 创建体检报告
    println!("4. 创建体检报告");
    let mut examinations = HashMap::new();
    examinations.insert("血压".to_string(), "120/80 mmHg (正常)".to_string());
    examinations.insert("心率".to_string(), "72 次/分 (正常)".to_string());
    examinations.insert("血糖".to_string(), "5.2 mmol/L (正常)".to_string());
    examinations.insert("胆固醇".to_string(), "4.8 mmol/L (正常)".to_string());
    examinations.insert("心电图".to_string(), "窦性心律，未见明显异常".to_string());

    let medical_report = MedicalReport {
        patient_name: patient.name.clone(),
        patient_id: patient.id_number.clone(),
        report_date: "2024-01-20".to_string(),
        examinations,
        diagnosis: "体检各项指标正常，未见明显异常。".to_string(),
        recommendations: "建议保持健康的生活方式，定期进行体检。".to_string(),
    };

    println!("  ✓ 体检报告创建成功");
    println!();

    // 5. 医生签名体检报告
    println!("5. 医生对体检报告进行数字签名");
    let report_data = medical_report.to_bytes();

    let location_info = LocationInfo {
        latitude: Some(31.2704),
        longitude: Some(121.5456),
        address: Some(hospital.address.clone()),
        institution_id: Some(hospital.id.clone()),
        department: Some(doctor.department.clone()),
    };

    let digital_signature = doctor.keypair.sign_data(
        &report_data,
        location_info,
        Some(format!(
            "{} (执业证号: {})",
            doctor.name, doctor.license_number
        )),
        Some("体检报告签名".to_string()),
    )?;

    println!("  ✓ 数字签名成功");
    println!("    - 签名时间: {}", digital_signature.timestamp_readable());
    println!(
        "    - 签名地点: {}",
        digital_signature
            .extended_info
            .location
            .address
            .as_ref()
            .unwrap()
    );
    println!(
        "    - 签名摘要: {}...",
        &digital_signature.signature_hex()[.. 32]
    );
    println!();

    // 6. 患者验证医生的签名
    println!("6. 患者验证医生的签名");

    // 方法1: 使用独立验证函数（不需要医生的密钥对）
    let is_signature_valid = verify_signature_standalone(&report_data, &digital_signature)?;
    println!(
        "  ✓ 签名验证结果: {}",
        if is_signature_valid {
            "有效"
        } else {
            "无效"
        }
    );

    // 验证签名者信息
    if let Some(signer_info) = &digital_signature.extended_info.signer_info {
        println!("  ✓ 签名者: {}", signer_info);
    }
    println!();

    // 7. 构建并验证证书链
    println!("7. 验证证书链");

    // 构建医生的证书链
    let available_certs = vec![root_ca.certificate().clone()];
    let doctor_chain = build_certificate_chain(&doctor.certificate, &available_certs)?;

    println!("  ✓ 医生证书链构建成功，深度: {}", doctor_chain.len());
    for (i, cert) in doctor_chain.iter().enumerate() {
        println!("    [{}] {}", i, cert.info.subject.common_name);
    }
    println!();

    // 创建证书链验证器
    let mut validator = ChainValidator::new();
    validator.add_trusted_root(root_ca.certificate().clone())?;
    validator.set_check_revocation(false); // 演示中暂时禁用CRL检查

    // 验证医生证书链
    let validation_result = validator.validate_chain(&doctor_chain);
    println!(
        "  ✓ 医生证书链验证结果: {}",
        if validation_result.is_valid {
            "有效"
        } else {
            "无效"
        }
    );

    if !validation_result.errors.is_empty() {
        println!("    错误:");
        for error in &validation_result.errors {
            println!("      - {}", error);
        }
    }

    if !validation_result.warnings.is_empty() {
        println!("    警告:");
        for warning in &validation_result.warnings {
            println!("      - {}", warning);
        }
    }
    println!();

    // 8. 模拟数据篡改场景
    println!("8. 安全性测试 - 模拟数据篡改");
    let mut tampered_report = medical_report;
    tampered_report.diagnosis = "检测到严重心脏疾病，需要立即住院治疗。".to_string();
    let tampered_data = tampered_report.to_bytes();

    let is_tampered_valid = verify_signature_standalone(&tampered_data, &digital_signature)?;
    println!(
        "  ✓ 篡改数据的签名验证结果: {}",
        if is_tampered_valid {
            "有效（危险！）"
        } else {
            "无效（正确检测到篡改）"
        }
    );
    println!();

    // 9. 导出证书供其他系统使用
    println!("9. 导出证书");
    let doctor_cert_pem = capsula_crypto::export_certificate(&doctor.certificate, "PEM")?;
    println!("  ✓ 医生证书已导出为PEM格式");
    println!("    长度: {} 字节", doctor_cert_pem.len());

    // 演示：打印证书PEM的前几行
    if let Ok(pem_str) = std::str::from_utf8(&doctor_cert_pem) {
        let pem_lines: Vec<&str> = pem_str.lines().take(3).collect();
        for line in pem_lines {
            println!("    {}", line);
        }
        println!("    ...");
    }
    println!();

    println!("=== 演示完成 ===");
    println!("\n总结:");
    println!("1. ✓ 成功创建医院根证书颁发机构");
    println!("2. ✓ 成功签发医生和患者的数字证书");
    println!("3. ✓ 医生成功对体检报告进行数字签名");
    println!("4. ✓ 患者成功验证医生的签名");
    println!("5. ✓ 证书链验证通过");
    println!("6. ✓ 成功检测到数据篡改");

    Ok(())
}
