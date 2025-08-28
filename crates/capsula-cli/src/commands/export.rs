use crate::error::{CliError, CliResult};
use colored::Colorize;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};
use std::fs;
use std::path::Path;

pub fn handle(key: String, output: Option<String>) -> CliResult<()> {
    println!("{}", format!("导出公钥: {}", key).cyan());
    
    // 检查私钥文件是否存在
    if !Path::new(&key).exists() {
        return Err(CliError::FileNotFound(key));
    }
    
    // 读取私钥
    let private_key_pem = fs::read_to_string(&key)?;
    let signing_key = SigningKey::from_pkcs8_pem(&private_key_pem)
        .map_err(|e| CliError::Other(format!("Failed to import private key: {}", e)))?;
    
    // 导出公钥
    let verifying_key = signing_key.verifying_key();
    let public_key_pem = verifying_key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| CliError::Other(format!("Failed to export public key: {}", e)))?;
    
    // 确定输出文件名
    let output_file = output.unwrap_or_else(|| {
        let key_path = Path::new(&key);
        let stem = key_path.file_stem().unwrap_or_default().to_string_lossy();
        if stem.ends_with("_private") {
            format!("{}_public.pem", &stem[..stem.len() - 8])
        } else {
            format!("{}_public.pem", stem)
        }
    });
    
    // 保存公钥
    fs::write(&output_file, public_key_pem.as_bytes())?;
    
    println!("{} 公钥已导出到: {}", "✓".green(), output_file);
    
    // 显示公钥信息
    let public_key_bytes = verifying_key.to_bytes();
    println!();
    println!("{}", "公钥信息:".cyan());
    println!("  算法: Ed25519");
    println!("  密钥长度: {} 位", public_key_bytes.len() * 8);
    println!("  公钥指纹: {}", hex::encode(&public_key_bytes[..8]));
    
    Ok(())
}