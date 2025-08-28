use crate::error::{CliError, CliResult};
use capsula_key::{signature::DigitalSignature, verify_signature_standalone};
use colored::Colorize;
use std::fs;
use std::path::Path;

pub fn handle(file: String, signature: String) -> CliResult<()> {
    println!("{}", format!("验证文件签名: {}", file).cyan());
    
    // 检查文件是否存在
    if !Path::new(&file).exists() {
        return Err(CliError::FileNotFound(file.clone()));
    }
    
    if !Path::new(&signature).exists() {
        return Err(CliError::FileNotFound(signature.clone()));
    }
    
    // 读取文件内容
    let data = fs::read(&file)?;
    println!("  文件大小: {} 字节", data.len());
    
    // 读取签名
    let signature_json = fs::read_to_string(&signature)?;
    let digital_signature = DigitalSignature::from_json(&signature_json)
        .map_err(|e| CliError::Key(e))?;
    
    // 验证签名
    println!("{}", "验证签名...".cyan());
    let is_valid = verify_signature_standalone(&data, &digital_signature)
        .map_err(|e| CliError::Key(e))?;
    
    if is_valid {
        println!("{} {}", "✓".green(), "签名验证通过！".green().bold());
        
        // 显示签名信息
        println!();
        println!("{}", "签名详情:".cyan());
        println!("  时间戳: {}", digital_signature.timestamp_readable());
        println!("  数据哈希: {}", hex::encode(&digital_signature.extended_info.data_hash[..16]));
        if let Some(ref s) = digital_signature.extended_info.signer_info {
            println!("  签名者: {}", s);
        }
        if let Some(ref t) = digital_signature.extended_info.signature_type {
            println!("  签名类型: {}", t);
        }
        if let Some(ref addr) = digital_signature.extended_info.location.address {
            println!("  签名位置: {}", addr);
        }
        
        // 验证数据完整性
        use capsula_key::{hash_data, HashAlgorithm};
        let current_hash = hash_data(&data, HashAlgorithm::Sha256);
        if current_hash == digital_signature.extended_info.data_hash {
            println!("{} 数据完整性验证通过", "✓".green());
        } else {
            println!("{} 警告: 数据可能已被修改！", "⚠".yellow());
        }
    } else {
        println!("{} {}", "✗".red(), "签名验证失败！".red().bold());
        println!("{}", "可能的原因:".yellow());
        println!("  - 文件已被修改");
        println!("  - 签名文件损坏");
        println!("  - 使用了错误的公钥");
    }
    
    Ok(())
}