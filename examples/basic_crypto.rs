//! 基础加密功能示例

use capsula_crypto::{
    hash_data, hash_data_hex, verify_hash, DigitalSignature, EccKeyPair, HashAlgorithm,
    LocationInfo,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Capsula 基础加密功能示例 ===\n");

    // 1. 密钥对生成和管理
    println!("1. 密钥对生成和管理");
    let keypair = EccKeyPair::generate_keypair()?;
    println!("✓ 生成 Ed25519 密钥对");

    // 导出密钥
    let private_pem = keypair.export_private_key()?;
    let public_pem = keypair.export_public_key_pem()?;
    println!("✓ 导出私钥 (PEM 格式): {} 字节", private_pem.len());
    println!("私钥内容:\n{}", private_pem);
    println!("\n✓ 导出公钥 (PEM 格式): {} 字节", public_pem.len());
    println!("公钥内容:\n{}", public_pem);

    // 导入密钥
    let _imported_keypair = EccKeyPair::import_private_key(&private_pem)?;
    println!("✓ 成功导入私钥");

    // 2. 数字签名
    println!("\n2. 数字签名");
    let data = "重要的医疗数据".as_bytes();

    // 简单签名
    let simple_signature = keypair.sign_with_timestamp(data, Some("张医生".to_string()))?;
    println!("✓ 创建带时间戳的签名");
    if let Some(ref signer) = simple_signature.extended_info.signer_info {
        println!("  - 签名者: {}", signer);
    }
    println!("  - 时间戳: {}", simple_signature.extended_info.timestamp);
    println!("  - 签名值 (hex): {}", simple_signature.signature_hex());
    println!("  - 公钥 (hex): {}", simple_signature.public_key_hex());

    // 带位置信息的签名
    let location = LocationInfo {
        latitude: Some(31.2304),
        longitude: Some(121.4737),
        address: Some("上海市第一人民医院".to_string()),
        institution_id: Some("HOSP001".to_string()),
        department: Some("心内科".to_string()),
    };

    let full_signature = keypair.sign_data(
        data,
        location.clone(),
        Some("张医生".to_string()),
        Some("患者病历签名".to_string()),
    )?;
    println!("\n✓ 创建带位置信息的签名");
    println!("  - 医疗机构: {}", location.address.as_ref().unwrap());
    println!("  - 科室: {}", location.department.as_ref().unwrap());
    if let Some(ref sig_type) = full_signature.extended_info.signature_type {
        println!("  - 说明: {}", sig_type);
    }

    // 验证签名
    let is_valid = keypair.verify_signature(data, &full_signature)?;
    println!("\n✓ 签名验证: {}", if is_valid { "通过" } else { "失败" });

    // 3. 哈希计算
    println!("\n3. 哈希计算");
    let hash_sha256 = hash_data(data, HashAlgorithm::Sha256);
    let hash_sha256_hex = hash_data_hex(data, HashAlgorithm::Sha256);
    println!("✓ SHA-256 哈希: {}", hash_sha256_hex);

    let _hash_sha512 = hash_data(data, HashAlgorithm::Sha512);
    let hash_sha512_hex = hash_data_hex(data, HashAlgorithm::Sha512);
    println!("✓ SHA-512 哈希: {}", &hash_sha512_hex[.. 32]); // 只显示前32个字符

    // 验证哈希
    let hash_valid = verify_hash(data, &hash_sha256, HashAlgorithm::Sha256);
    println!("\n✓ 哈希验证: {}", if hash_valid { "通过" } else { "失败" });

    // 4. 序列化和反序列化
    println!("\n4. 签名序列化");
    let signature_json = full_signature.to_json()?;
    println!("✓ 签名序列化为 JSON: {} 字节", signature_json.len());

    let deserialized = DigitalSignature::from_json(&signature_json)?;
    println!("✓ 从 JSON 反序列化签名");

    // 验证反序列化的签名
    let is_valid_deserialized = keypair.verify_signature(data, &deserialized)?;
    println!(
        "✓ 反序列化签名验证: {}",
        if is_valid_deserialized {
            "通过"
        } else {
            "失败"
        }
    );

    println!("\n=== 示例完成 ===");
    Ok(())
}
