use capsula_key::{Curve25519, Key, KeyFileIO};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new key
    let key = Curve25519::generate()?;
    println!("Generated key with ID: {}", key.key_id_hex());

    // Export all keys to ./keys directory
    // let export_info = <Curve25519 as KeyFileIO>::export_all_keys( "./keys", "demo_key")?;

    let export_info = key.export_all_keys("./keys", "demo_key")?;

    println!("Keys exported to:");
    println!("  Private: {}", export_info.private_key_path);
    for pub_key in &export_info.public_key_paths {
        println!("  {}: {}", pub_key.key_type.as_str(), pub_key.file_path);
    }

    Ok(())
}
