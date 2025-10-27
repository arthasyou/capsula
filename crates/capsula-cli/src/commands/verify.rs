use std::{fs, path::Path};

use capsula_key::DigitalSignature;
use colored::Colorize;

use crate::error::{CliError, CliResult};

pub fn handle(file: String, signature_path: String) -> CliResult<()> {
    println!("{} {}", "验证文件:".cyan(), file);

    if !Path::new(&file).exists() {
        return Err(CliError::FileNotFound(file));
    }

    let data = fs::read(&file)?;
    println!("  {} {} 字节", "文件大小:".cyan(), data.len());

    let signature_content = fs::read_to_string(&signature_path)?;
    let digital_signature = DigitalSignature::from_json(&signature_content)?;

    let algorithm_label = if digital_signature.public_key.len() == 32 {
        "Ed25519"
    } else {
        "RSA"
    };
    println!("  {} {}", "签名算法:".cyan(), algorithm_label);

    // // Recompute data hash and compare
    // let computed_hash = sha512(&data);
    // if computed_hash.as_slice() != digital_signature.extended_info.data_hash.as_slice() {
    //     return Err(CliError::Other(
    //         "数据哈希与签名记录不匹配，请确认文件是否被篡改".to_string(),
    //     ));
    // }

    // // Recreate signed payload: data_hash + serialized extended info
    // let mut verify_payload = Vec::new();
    // verify_payload.extend_from_slice(&digital_signature.extended_info.data_hash);
    // let extended_info_bytes =
    //     serde_json::to_vec(&digital_signature.extended_info).map_err(CliError::Serialization)?;
    // verify_payload.extend_from_slice(&extended_info_bytes);

    // // Perform signature verification depending on public key format
    // let public_key_der = if digital_signature.public_key.len() == 32 {
    //     // Raw Ed25519 public key; convert to SPKI DER for unified verification
    //     let mut pk_bytes = [0u8; 32];
    //     pk_bytes.copy_from_slice(&digital_signature.public_key);
    //     let verifying_key = capsula_crypto::asymmetric::ed25519::public_key_from_bytes(&pk_bytes)
    //         .map_err(|e| CliError::Other(format!("无效的公钥格式: {e}")))?;

    //     verifying_key
    //         .to_public_key_der()
    //         .map_err(|e| CliError::Other(format!("公钥编码失败: {e}")))?
    //         .as_bytes()
    //         .to_vec()
    // } else {
    //     digital_signature.public_key.clone()
    // };

    // let verified = verify_signature(
    //     &public_key_der,
    //     &verify_payload,
    //     &digital_signature.signature,
    // )
    // .map_err(|e| CliError::Other(format!("签名验证失败: {e}")))?;

    // if !verified {
    //     return Err(CliError::Other("签名验证失败".to_string()));
    // }

    // println!("{} {}", "✓".green(), "签名验证通过".green());
    // println!(
    //     "  {} {}",
    //     "时间戳:".cyan(),
    //     digital_signature.timestamp_readable()
    // );
    // println!(
    //     "  {} {}",
    //     "数据哈希:".cyan(),
    //     hex::encode(
    //         &digital_signature.extended_info.data_hash
    //             [.. std::cmp::min(16, digital_signature.extended_info.data_hash.len())]
    //     )
    // );
    // if let Some(ref signer) = digital_signature.extended_info.signer_info {
    //     println!("  {} {}", "签名者:".cyan(), signer);
    // }
    // if let Some(ref address) = digital_signature.extended_info.location.address {
    //     println!("  {} {}", "位置:".cyan(), address);
    // }

    Ok(())
}
