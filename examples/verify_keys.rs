//! 验证生成的密钥文件
//!
//! 测试从DER文件加载密钥并验证其功能

use std::fs;

use capsula_key::{Key, KeySign, RsaKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 密钥验证工具 ===\n");

    let key_names = ["producer", "owner", "user"];

    for name in &key_names {
        println!("验证 {} 密钥...", name);
        
        // 加载私钥
        let private_key_path = format!("keys/{}_private.pem", name);
        let private_key_pem = fs::read_to_string(&private_key_path)?;
        let private_key = RsaKey::from_pkcs8_pem(&private_key_pem)?;
        
        // 加载公钥
        let public_key_path = format!("keys/{}_public.pem", name);
        let public_key_pem = fs::read_to_string(&public_key_path)?;
        
        // 验证密钥基本信息
        println!("  ✓ 私钥加载成功: {}", private_key_path);
        println!("  ✓ 公钥加载成功: {}", public_key_path);
        println!("  ✓ 密钥长度: {} bits", private_key.size_bits());
        println!("  ✓ 算法: {:?}", private_key.algorithm());
        println!("  ✓ 密钥ID: {}", private_key.key_id_hex());
        
        // 测试签名功能
        let test_message = b"Hello, Capsula!";
        let signature = private_key.sign(test_message)?;
        println!("  ✓ 签名测试成功，签名长度: {} bytes", signature.len());
        
        // 验证公钥匹配
        let extracted_public_key = private_key.public_keys();
        let signing_key = extracted_public_key.signing_key().unwrap();
        
        // 将提取的公钥转换为PEM格式进行比较
        let extracted_public_base64 = capsula_crypto::base64::encode(&signing_key.spki_der);
        let extracted_public_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            extracted_public_base64
                .chars()
                .collect::<Vec<char>>()
                .chunks(64)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<String>>()
                .join("\n")
        );
        
        if extracted_public_pem == public_key_pem {
            println!("  ✓ 公钥/私钥匹配验证成功");
        } else {
            println!("  ❌ 公钥/私钥不匹配！");
        }
        
        println!();
    }

    println!("=== 所有密钥验证完成 ===");
    Ok(())
}