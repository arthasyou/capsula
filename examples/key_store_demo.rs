//! Key Store功能演示
//!
//! 展示如何使用capsula-key的存储功能来管理密钥

use std::collections::HashMap;

use capsula_key::{
    store::{create_key_store, KeyHandle, KeyMetadata, KeyStoreConfig},
    Algorithm, ExportablePrivateKey, P256Key, RsaKey,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Key Store 功能演示 ===\n");

    // 1. 创建内存存储
    println!("1. 创建内存存储...");
    let memory_store = create_key_store(KeyStoreConfig::Memory)?;
    println!("   ✓ 内存存储创建成功\n");

    // 2. 生成和存储RSA密钥
    println!("2. 生成和存储RSA密钥...");
    let rsa_key = RsaKey::generate_2048()?;
    let rsa_der = rsa_key.to_pkcs8_der()?;

    let rsa_metadata = KeyMetadata {
        handle: KeyHandle(1),
        algorithm: Algorithm::Rsa,
        created_at: std::time::SystemTime::now(),
        label: Some("医院主密钥".to_string()),
        attributes: {
            let mut attrs = HashMap::new();
            attrs.insert("usage".to_string(), "signing".to_string());
            attrs.insert("owner".to_string(), "Central Hospital".to_string());
            attrs
        },
    };

    memory_store.store_key(rsa_metadata.clone(), rsa_der)?;
    println!("   ✓ RSA密钥存储成功 (Handle: {})", rsa_metadata.handle.0);
    println!("   ✓ 标签: {:?}", rsa_metadata.label);
    println!("   ✓ 用途: {:?}", rsa_metadata.attributes.get("usage"));

    // 3. 生成和存储P256密钥
    println!("\n3. 生成和存储P256密钥...");
    let p256_key = P256Key::generate()?;
    let p256_der = p256_key.to_pkcs8_der()?;

    let p256_metadata = KeyMetadata {
        handle: KeyHandle(2),
        algorithm: Algorithm::P256,
        created_at: std::time::SystemTime::now(),
        label: Some("患者签名密钥".to_string()),
        attributes: {
            let mut attrs = HashMap::new();
            attrs.insert("usage".to_string(), "patient_signature".to_string());
            attrs.insert("patient_id".to_string(), "P001".to_string());
            attrs
        },
    };

    memory_store.store_key(p256_metadata.clone(), p256_der)?;
    println!("   ✓ P256密钥存储成功 (Handle: {})", p256_metadata.handle.0);
    println!("   ✓ 标签: {:?}", p256_metadata.label);

    // 4. 列出所有存储的密钥
    println!("\n4. 列出所有存储的密钥...");
    let handles = memory_store.list_keys()?;
    println!("   ✓ 共找到 {} 个密钥:", handles.len());

    for handle in &handles {
        let metadata = memory_store.get_metadata(*handle)?;
        println!(
            "     - Handle {}: {} ({:?})",
            handle.0,
            metadata.label.as_deref().unwrap_or("无标签"),
            metadata.algorithm
        );
    }

    // 5. 检索和验证密钥
    println!("\n5. 检索和验证密钥...");
    let (retrieved_metadata, retrieved_key_data) = memory_store.get_key(KeyHandle(1))?;
    println!("   ✓ 成功检索RSA密钥");
    println!("   ✓ 密钥大小: {} 字节", retrieved_key_data.len());
    println!("   ✓ 创建时间: {:?}", retrieved_metadata.created_at);

    // 验证密钥可用性
    let recovered_rsa = RsaKey::from_pkcs8_der(&retrieved_key_data)?;
    println!("   ✓ 密钥验证成功，可以正常使用");

    // 6. 文件存储演示
    println!("\n6. 文件存储演示...");
    let file_path = std::path::PathBuf::from("./key");
    let file_store = create_key_store(KeyStoreConfig::File {
        path: file_path.clone(),
        encryption_key: None, // 不加密，仅演示
    })?;

    // 将内存中的密钥复制到文件存储
    for handle in handles {
        let (metadata, key_data) = memory_store.get_key(handle)?;
        file_store.store_key(metadata, key_data)?;
    }

    println!("   ✓ 密钥已保存到文件: {:?}", file_path);
    println!("   ✓ 文件存储包含 {} 个密钥", file_store.list_keys()?.len());

    // 7. 密钥存在性检查
    println!("\n7. 密钥管理操作...");
    println!("   密钥1存在: {}", file_store.exists(KeyHandle(1))?);
    println!("   密钥999存在: {}", file_store.exists(KeyHandle(999))?);

    // 8. 清理演示
    println!("\n8. 清理演示文件...");
    if file_path.exists() {
        std::fs::remove_file(&file_path)?;
        println!("   ✓ 演示文件已清理");
    }

    println!("\n=== Key Store 演示完成 ===");
    println!("新的存储功能已准备好用于capsula-core集成！");

    Ok(())
}
