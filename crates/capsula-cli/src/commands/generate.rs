use std::{fs, path::Path};

use capsula_key::{
    Curve25519, Key, KeyCapabilities, KeyExportInfo, KeyFileIO, KeyUsage, P256Key, RsaKey,
};
use colored::Colorize;

use crate::error::{CliError, CliResult};

pub fn handle(name: String, algorithm: String, output: Option<String>) -> CliResult<()> {
    let normalized = algorithm.to_lowercase();
    println!("{}", format!("生成 {} 密钥...", algorithm).cyan());

    let output_dir = output.unwrap_or_else(|| ".".to_string());
    let output_path = Path::new(&output_dir);
    if !output_path.exists() {
        fs::create_dir_all(output_path)?;
    }

    match normalized.as_str() {
        "ed25519" | "curve25519" | "x25519" => {
            let key = Curve25519::generate()?;
            let export_info = <Curve25519 as KeyFileIO>::export_all_keys(&key, output_path, &name)?;
            let extra =
                vec!["  说明: 同时导出 Ed25519（签名）与 X25519（密钥协商）公钥".to_string()];
            print_key_summary(&key, &export_info, &extra);

            let info_path = output_path.join(format!("{}_export_info.json", name));
            if info_path.exists() {
                println!("{} 导出信息: {}", "✓".green(), info_path.display());
            }
        }
        "p256" | "secp256r1" => {
            let key = P256Key::generate()?;
            let export_info = <P256Key as KeyFileIO>::export_all_keys(&key, output_path, &name)?;
            let extra = vec!["  曲线: NIST P-256 (secp256r1)".to_string()];
            print_key_summary(&key, &export_info, &extra);
        }
        "rsa" | "rsa2048" | "rsa-2048" => {
            let key = RsaKey::generate_2048()?;
            let export_info = <RsaKey as KeyFileIO>::export_all_keys(&key, output_path, &name)?;
            let extra = vec![format!("  RSA 模数位数: {} 位", key.size_bits())];
            print_key_summary(&key, &export_info, &extra);
        }
        "rsa3072" | "rsa-3072" => {
            let key = RsaKey::generate_3072()?;
            let export_info = <RsaKey as KeyFileIO>::export_all_keys(&key, output_path, &name)?;
            let extra = vec![format!("  RSA 模数位数: {} 位", key.size_bits())];
            print_key_summary(&key, &export_info, &extra);
        }
        "rsa4096" | "rsa-4096" => {
            let key = RsaKey::generate_4096()?;
            let export_info = <RsaKey as KeyFileIO>::export_all_keys(&key, output_path, &name)?;
            let extra = vec![format!("  RSA 模数位数: {} 位", key.size_bits())];
            print_key_summary(&key, &export_info, &extra);
        }
        unsupported => {
            return Err(CliError::InvalidInput(format!(
                "不支持的算法: {}",
                unsupported
            )));
        }
    }

    Ok(())
}

fn print_key_summary(key: &dyn Key, export_info: &KeyExportInfo, extra_lines: &[String]) {
    println!(
        "{} 私钥已保存到: {}",
        "✓".green(),
        export_info.private_key_path
    );
    for public in &export_info.public_key_paths {
        println!(
            "{} {}已保存到: {}",
            "✓".green(),
            label_for_usage(public.key_type),
            public.file_path
        );
    }

    println!();
    println!("{}", "密钥信息:".cyan());
    println!("  算法: {}", key.algorithm().name());
    println!("  密钥ID: {}", key.key_id_hex());
    println!("  指纹(SHA-256 SPKI): {}", key.fingerprint_hex());

    let capabilities = key.capabilities();
    println!("  支持能力: {}", format_capabilities(capabilities));
    for line in extra_lines {
        println!("{}", line);
    }

    let public_keys = key.public_keys();
    if let Some(signing) = public_keys.signing_key() {
        if let Some(raw) = &signing.raw_public_key {
            println!("  签名公钥长度: {} 位", raw.len() * 8);
            println!("  签名公钥指纹: {}", hex::encode(&raw[.. raw.len().min(8)]));
        }
    }

    if let Some(kex) = public_keys.key_agreement_key() {
        if let Some(raw) = &kex.raw_public_key {
            println!("  密钥协商公钥长度: {} 位", raw.len() * 8);
            println!(
                "  密钥协商公钥指纹: {}",
                hex::encode(&raw[.. raw.len().min(8)])
            );
        }
    }

    if let Some(enc) = public_keys.encryption_key() {
        if let Some(raw) = &enc.raw_public_key {
            println!("  加密公钥长度: {} 位", raw.len() * 8);
            println!("  加密公钥指纹: {}", hex::encode(&raw[.. raw.len().min(8)]));
        }
    }
}

fn format_capabilities(capabilities: KeyCapabilities) -> String {
    let mut parts = Vec::new();
    if capabilities.supports_signing() {
        parts.push("签名");
    }
    if capabilities.supports_key_agreement() {
        parts.push("密钥协商");
    }
    if capabilities.supports_encryption() {
        parts.push("加密");
    }

    if parts.is_empty() {
        "无".to_string()
    } else {
        parts.join(" / ")
    }
}

fn label_for_usage(usage: KeyUsage) -> &'static str {
    match usage {
        KeyUsage::Signing => "签名公钥",
        KeyUsage::KeyAgreement => "密钥协商公钥",
        KeyUsage::Encryption => "加密公钥",
    }
}
