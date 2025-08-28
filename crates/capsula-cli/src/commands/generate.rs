use crate::error::{CliError, CliResult};
use colored::Colorize;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};
use std::fs;
use std::path::Path;

pub fn handle(name: String, algorithm: String, output: Option<String>) -> CliResult<()> {
    // 目前只支持 Ed25519
    if algorithm.to_lowercase() != "ed25519" {
        return Err(CliError::InvalidInput(
            "目前仅支持 ed25519 算法".to_string(),
        ));
    }
    
    println!("{}", format!("生成 {} 密钥对...", algorithm).cyan());
    
    // 生成密钥对
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    
    // 确定输出目录
    let output_dir = output.unwrap_or_else(|| ".".to_string());
    let output_path = Path::new(&output_dir);
    
    if !output_path.exists() {
        fs::create_dir_all(output_path)?;
    }
    
    // 导出私钥
    let private_key_path = output_path.join(format!("{}_private.pem", name));
    let private_key_pem = signing_key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| CliError::Other(format!("Failed to export private key: {}", e)))?;
    fs::write(&private_key_path, private_key_pem.as_bytes())?;
    println!("{} 私钥已保存到: {:?}", "✓".green(), private_key_path);
    
    // 导出公钥
    let public_key_path = output_path.join(format!("{}_public.pem", name));
    let public_key_pem = verifying_key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| CliError::Other(format!("Failed to export public key: {}", e)))?;
    fs::write(&public_key_path, public_key_pem.as_bytes())?;
    println!("{} 公钥已保存到: {:?}", "✓".green(), public_key_path);
    
    // 显示公钥信息
    let public_key_bytes = verifying_key.to_bytes();
    println!();
    println!("{}", "密钥信息:".cyan());
    println!("  算法: Ed25519");
    println!("  密钥长度: {} 位", public_key_bytes.len() * 8);
    println!("  公钥指纹: {}", hex::encode(&public_key_bytes[..8]));
    
    Ok(())
}