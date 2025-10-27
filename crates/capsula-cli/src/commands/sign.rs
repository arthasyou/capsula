use std::{fs, path::Path};

use capsula_key::{load_signing_key_from_pkcs8_pem, DigitalSignature};
use colored::Colorize;

use crate::error::{CliError, CliResult};

pub fn handle(file: String, key: String, output: Option<String>) -> CliResult<()> {
    println!("{}", format!("签名文件: {}", file).cyan());

    // 检查文件是否存在
    if !Path::new(&file).exists() {
        return Err(CliError::FileNotFound(file));
    }

    // 读取文件内容
    let data = fs::read(&file)?;
    println!("  文件大小: {} 字节", data.len());

    // 读取并解析私钥（目前使用 Curve25519 / Ed25519 组合）
    let private_key_pem = fs::read_to_string(&key)?;
    let signing_key = load_signing_key_from_pkcs8_pem(&private_key_pem)?;
    println!("  使用私钥: {}", key);

    // 签名数据
    println!("{}", "执行签名...".cyan());

    // 使用 capsula-key 的签名能力
    let signature_bytes = signing_key.sign(&data)?;

    // 选择公钥数据（优先使用原始公钥，否则使用 SPKI DER）
    let public_key_bytes = signing_key
        .public_keys()
        .signing_key()
        .ok_or_else(|| CliError::Other("未找到可用的签名公钥".to_string()))
        .map(|entry| {
            entry
                .raw_public_key
                .clone()
                .unwrap_or_else(|| entry.spki_der.clone())
        })?;

    // 将算法使用可序列化的名称形式（string）传递，以避免不同 crate 中同名 enum 的类型冲突
    let alg = signing_key.algorithm();

    // 创建数字签名
    let signature = DigitalSignature {
        signature: signature_bytes,
        alg,
        public_key: public_key_bytes,
    };

    // 确定输出文件名
    let output_file = output.unwrap_or_else(|| format!("{}.sig", file));

    // 将签名保存为 JSON
    let signature_json = signature.to_json().map_err(|e| CliError::Key(e))?;
    fs::write(&output_file, signature_json)?;

    println!("{} 签名已保存到: {}", "✓".green(), output_file);
    println!();
    println!("{}", "签名信息:".cyan());
    println!("  算法: {}", signing_key.algorithm().name());
    println!("  密钥ID: {}", signing_key.key_id_hex());

    Ok(())
}
