use std::{fs, path::Path};

use colored::Colorize;
use ed25519_dalek::{pkcs8::DecodePrivateKey, SigningKey};

use crate::error::{CliError, CliResult};

pub fn handle(key: String) -> CliResult<()> {
    println!("{}", format!("密钥信息: {}", key).cyan().bold());
    println!();

    // 检查文件是否存在
    if !Path::new(&key).exists() {
        return Err(CliError::FileNotFound(key));
    }

    // 读取密钥文件内容
    let key_content = fs::read_to_string(&key)?;

    // 判断是私钥还是公钥
    let is_private = key_content.contains("BEGIN PRIVATE KEY");
    let is_public = key_content.contains("BEGIN PUBLIC KEY");

    if is_private {
        // 处理私钥
        let signing_key = SigningKey::from_pkcs8_pem(&key_content)
            .map_err(|e| CliError::Other(format!("Failed to import private key: {}", e)))?;

        println!("{}", "密钥类型: 私钥".yellow());
        println!("算法: Ed25519");
        println!("格式: PKCS#8 PEM");

        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();
        println!();
        println!("{}", "对应的公钥信息:".cyan());
        println!("  公钥长度: {} 位", public_key_bytes.len() * 8);
        println!("  公钥指纹: {}", hex::encode(&public_key_bytes[.. 8]));
        println!("  公钥哈希: {}", hex::encode(&public_key_bytes));

        println!();
        println!("{}", "⚠ 注意: 请妥善保管私钥文件！".yellow().bold());
    } else if is_public {
        // 处理公钥
        println!("{}", "密钥类型: 公钥".green());
        println!("算法: Ed25519");
        println!("格式: SPKI PEM");

        // 从 PEM 提取公钥字节（这里简化处理，实际应该正确解析）
        println!();
        println!("{}", "注意: 公钥可以安全地分享给他人。".green());
    } else {
        return Err(CliError::InvalidInput("无法识别的密钥格式".to_string()));
    }

    // 显示文件信息
    let metadata = fs::metadata(&key)?;
    println!();
    println!("{}", "文件信息:".cyan());
    println!("  文件大小: {} 字节", metadata.len());
    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
            let secs = duration.as_secs();
            let datetime = time::OffsetDateTime::from_unix_timestamp(secs as i64)
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
            println!(
                "  修改时间: {}",
                datetime
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default()
            );
        }
    }

    Ok(())
}
