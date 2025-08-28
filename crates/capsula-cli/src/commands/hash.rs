use crate::error::{CliError, CliResult};
use capsula_key::{hash_data_hex, HashAlgorithm};
use colored::Colorize;
use std::fs;
use std::path::Path;

pub fn handle(file: String, algorithm: String) -> CliResult<()> {
    println!("{}", format!("计算文件哈希: {}", file).cyan());
    
    // 检查文件是否存在
    if !Path::new(&file).exists() {
        return Err(CliError::FileNotFound(file));
    }
    
    // 解析哈希算法
    let hash_algo = match algorithm.to_lowercase().as_str() {
        "sha256" => HashAlgorithm::Sha256,
        "sha512" => HashAlgorithm::Sha512,
        _ => {
            return Err(CliError::InvalidInput(
                "不支持的哈希算法，请使用 sha256 或 sha512".to_string(),
            ));
        }
    };
    
    // 读取文件
    let data = fs::read(&file)?;
    println!("  文件大小: {} 字节", data.len());
    println!("  算法: {}", algorithm.to_uppercase());
    
    // 计算哈希
    let hash = hash_data_hex(&data, hash_algo);
    
    println!();
    println!("{} {}", "哈希值:".green().bold(), hash);
    
    // 同时显示简短版本（前16个字符）
    println!("{} {}", "简短版:".cyan(), &hash[..16]);
    
    Ok(())
}