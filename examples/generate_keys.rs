//! 密钥生成工具 - 简化版
//!
//! 生成三对RSA 2048密钥：producer, owner, user
//! 可通过环境变量KEYS_DIR指定保存目录，默认为当前目录的keys子目录

use std::{env, fs, path::Path};

use capsula_key::{KeyFileIO, RsaKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== RSA 2048 密钥生成工具 (简化版) ===\n");

    // 从环境变量获取密钥保存目录，默认为temp/keys
    let keys_dir_name = env::var("KEYS_DIR").unwrap_or_else(|_| "temp/keys".to_string());
    let keys_dir = Path::new(&keys_dir_name);
    if !keys_dir.exists() {
        fs::create_dir_all(keys_dir)?;
        println!("✓ 创建目录: {}", keys_dir_name);
    }

    // 定义要生成的密钥
    let key_names = ["producer", "owner", "user"];

    // 存储所有密钥的导出信息
    let mut all_exports = Vec::new();

    for name in &key_names {
        println!("正在生成 {} 密钥...", name);

        // 生成RSA 2048密钥对
        let key_pair = RsaKey::generate_2048()?;

        // 使用KeyFileIO trait的export_all_keys方法导出密钥
        // 这个方法会自动处理私钥和公钥的导出
        let export_info = key_pair.export_all_keys(keys_dir, name)?;

        println!("✓ {} 密钥生成完成", name);
        println!("  - 私钥: {}", export_info.private_key_path);
        for public_key in &export_info.public_key_paths {
            println!(
                "  - 公钥 ({:?}): {}",
                public_key.key_type, public_key.file_path
            );
        }
        println!("  - 密钥ID: {}", export_info.key_id);
        println!();

        all_exports.push(export_info);
    }

    // 生成密钥信息文件（JSON格式）
    let info_path = keys_dir.join("keys_info.json");
    let info_json = serde_json::to_string_pretty(&all_exports)?;
    fs::write(&info_path, info_json)?;

    println!("✓ 密钥信息文件已生成: {:?}", info_path);
    println!("\n=== 密钥生成完成 ===");
    println!("共生成 {} 对RSA 2048密钥", key_names.len());
    println!("所有文件保存在 {}/ 目录中", keys_dir_name);

    Ok(())
}
