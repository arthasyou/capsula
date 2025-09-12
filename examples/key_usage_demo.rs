use capsula_key::{Curve25519, Key, KeyExportInfo, KeyFileIO};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔑 Simple Key Export and Usage Demo");
    println!("===================================");

    // Generate a key
    println!("📝 Generating new key...");
    let key = Curve25519::generate()?;
    println!("✅ Generated key with ID: {}", key.key_id_hex());

    // Export to ./keys directory
    println!("\n📁 Exporting key files...");
    let export_info = <Curve25519 as KeyFileIO>::export_all_keys(&key, "./keys", "my_key")?;

    println!("✅ Exported files:");
    println!("   📜 Private key: {}", export_info.private_key_path);
    for pub_key in &export_info.public_key_paths {
        println!(
            "   🔓 {} key: {}",
            pub_key.key_type.as_str(),
            pub_key.file_path
        );
    }

    // Show export info JSON path
    println!("   📋 Export info: ./keys/my_key_export_info.json");

    // Load export info back
    println!("\n🔍 Loading export info...");
    let loaded_info = KeyExportInfo::load_from_file("./keys/my_key_export_info.json")?;
    println!("✅ Loaded export info:");
    println!("   Algorithm: {}", loaded_info.algorithm);
    println!("   Key ID: {}", loaded_info.key_id);
    println!(
        "   Files: {} public keys + 1 private key",
        loaded_info.public_key_paths.len()
    );

    // Show file sizes
    println!("\n📊 File sizes:");
    for path in loaded_info.all_file_paths() {
        if std::path::Path::new(&path).exists() {
            let size = std::fs::metadata(&path)?.len();
            println!("   {} - {} bytes", path, size);
        }
    }

    println!("\n✨ Key export demo completed!");

    Ok(())
}
