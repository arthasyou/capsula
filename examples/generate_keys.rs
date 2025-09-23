//! 密钥生成工具
//!
//! 生成三对RSA 2048密钥：producer, owner, user
//! 可通过环境变量KEYS_DIR指定保存目录，默认为当前目录的keys子目录

use std::{env, fs, path::Path, time::SystemTime};

use capsula_crypto::base64;
use capsula_key::{ExportablePrivateKey, Key, RsaKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== RSA 2048 密钥生成工具 ===\n");

    // 从环境变量获取密钥保存目录，默认为temp/keys
    let keys_dir_name = env::var("KEYS_DIR").unwrap_or_else(|_| "temp/keys".to_string());
    let keys_dir = Path::new(&keys_dir_name);
    if !keys_dir.exists() {
        fs::create_dir_all(keys_dir)?;
        println!("✓ 创建目录: {}", keys_dir_name);
    }

    // 定义要生成的密钥
    let key_names = ["producer", "owner", "user"];

    for name in &key_names {
        println!("正在生成 {} 密钥...", name);

        // 生成RSA 2048密钥对
        let key_pair = RsaKey::generate_2048()?;

        // 导出私钥为PKCS#8 PEM格式
        let private_key_pem = key_pair.to_pkcs8_pem()?;

        // 获取公钥信息
        let public_keys = key_pair.public_keys();
        let signing_key = public_keys.signing_key().ok_or("No signing key found")?;

        // 将DER格式的公钥转换为PEM格式
        let public_key_base64 = base64::encode(&signing_key.spki_der);
        let public_key_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            public_key_base64
                .chars()
                .collect::<Vec<char>>()
                .chunks(64)
                .map(|chunk| chunk.iter().collect::<String>())
                .collect::<Vec<String>>()
                .join("\n")
        );

        // 保存私钥
        let private_key_path = keys_dir.join(format!("{}_private.pem", name));
        fs::write(&private_key_path, &private_key_pem)?;

        // 保存公钥（RSA可用于签名和加密）
        let public_key_path = keys_dir.join(format!("{}_public.pem", name));
        fs::write(&public_key_path, &public_key_pem)?;

        println!("✓ {} 密钥生成完成", name);
        println!("  - 私钥: {:?}", private_key_path);
        println!("  - 公钥: {:?}", public_key_path);
        println!("  - 密钥长度: {} bits", key_pair.size_bits());
        println!();
    }

    // 生成密钥信息文件
    let info_path = keys_dir.join("keys_info.txt");
    let info_content = format!(
        "RSA 2048 密钥对信息
===================

生成时间: {}
密钥算法: RSA 2048
生成的密钥对:

1. producer - 生产者密钥
   - producer_private.pem (私钥)
   - producer_public.pem  (公钥)

2. owner - 所有者密钥  
   - owner_private.pem (私钥)
   - owner_public.pem  (公钥)

3. user - 用户密钥
   - user_private.pem (私钥)  
   - user_public.pem  (公钥)

注意事项:
- 私钥文件(.pem)包含敏感信息，请妥善保管
- 公钥文件可以安全分发
- 私钥为PKCS#8 PEM格式，公钥为SPKI PEM格式
- RSA密钥可用于数字签名和数据加密
",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    fs::write(&info_path, info_content)?;

    println!("✓ 密钥信息文件已生成: {:?}", info_path);
    println!("\n=== 密钥生成完成 ===");
    println!("共生成 {} 对RSA 2048密钥", key_names.len());
    println!("所有文件保存在 {}/ 目录中", keys_dir_name);

    Ok(())
}
