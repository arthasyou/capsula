use crate::error::{CliError, CliResult};
use capsula_key::{LocationInfo, DigitalSignature};
use colored::Colorize;
use ed25519_dalek::{SigningKey, Signer};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use std::fs;
use std::path::Path;
use sha2::{Sha256, Digest};

pub fn handle(
    file: String,
    key: String,
    output: Option<String>,
    signer: Option<String>,
    location: Option<String>,
) -> CliResult<()> {
    println!("{}", format!("签名文件: {}", file).cyan());
    
    // 检查文件是否存在
    if !Path::new(&file).exists() {
        return Err(CliError::FileNotFound(file));
    }
    
    // 读取文件内容
    let data = fs::read(&file)?;
    println!("  文件大小: {} 字节", data.len());
    
    // 读取私钥
    let private_key_pem = fs::read_to_string(&key)?;
    let signing_key = SigningKey::from_pkcs8_pem(&private_key_pem)
        .map_err(|e| CliError::Other(format!("Failed to import private key: {}", e)))?;
    println!("  使用私钥: {}", key);
    
    // 构建位置信息
    let location_info = if let Some(loc) = location {
        LocationInfo {
            latitude: None,
            longitude: None,
            address: Some(loc),
            institution_id: None,
            department: None,
        }
    } else {
        LocationInfo {
            latitude: None,
            longitude: None,
            address: None,
            institution_id: None,
            department: None,
        }
    };
    
    // 签名数据
    println!("{}", "执行签名...".cyan());
    
    // 计算数据哈希
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let data_hash = hasher.finalize().to_vec();
    
    // 创建扩展签名信息
    use capsula_key::ExtendedSignatureInfo;
    let extended_info = ExtendedSignatureInfo {
        data_hash: data_hash.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        location: location_info,
        signer_info: signer,
        signature_type: Some("文件签名".to_string()),
    };
    
    // 序列化扩展信息
    let extended_info_bytes = serde_json::to_vec(&extended_info)
        .map_err(|e| CliError::Serialization(e))?;
    
    // 构建待签名数据
    let mut sign_data = Vec::new();
    sign_data.extend_from_slice(&data_hash);
    sign_data.extend_from_slice(&extended_info_bytes);
    
    // 签名
    let signature_bytes = signing_key.sign(&sign_data).to_bytes().to_vec();
    let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    
    // 创建数字签名
    let signature = DigitalSignature {
        signature: signature_bytes,
        extended_info,
        public_key: public_key_bytes,
    };
    
    // 确定输出文件名
    let output_file = output.unwrap_or_else(|| format!("{}.sig", file));
    
    // 将签名保存为 JSON
    let signature_json = signature.to_json()
        .map_err(|e| CliError::Key(e))?;
    fs::write(&output_file, signature_json)?;
    
    println!("{} 签名已保存到: {}", "✓".green(), output_file);
    println!();
    println!("{}", "签名信息:".cyan());
    println!("  时间戳: {}", signature.timestamp_readable());
    println!("  数据哈希: {}", hex::encode(&signature.extended_info.data_hash[..16]));
    if let Some(ref s) = signature.extended_info.signer_info {
        println!("  签名者: {}", s);
    }
    if let Some(ref addr) = signature.extended_info.location.address {
        println!("  位置: {}", addr);
    }
    
    Ok(())
}