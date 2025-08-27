use capsula_key::{
    impls::Ed25519Provider,
    provider::KeyProvider,
};

fn main() -> capsula_key::error::Result<()> {
    println!("=== Capsula Key 存储系统演示 ===\n");
    
    // 1. 默认内存存储 (向后兼容)
    println!("1. 内存存储:");
    {
        let provider = Ed25519Provider::new()?;
        
        let handle = provider.generate()?;
        println!("   生成密钥: {:?}", handle);
        
        let message = "内存存储测试".as_bytes();
        let signature = provider.sign(handle, message)?;
        let public_key = provider.public_spki_der(handle)?;
        let is_valid = provider.verify(&public_key, message, &signature)?;
        
        println!("   验证结果: {}", if is_valid { "✅ 通过" } else { "❌ 失败" });
    }
    
    // 2. 文件存储
    println!("\n2. 文件存储:");
    {
        let key_dir = std::path::PathBuf::from("./demo_keys");
        let provider = Ed25519Provider::with_file_store(key_dir.clone(), None)?;
        
        let handle = provider.generate()?;
        println!("   生成密钥: {:?}", handle);
        println!("   存储位置: {}", key_dir.display());
        
        // 验证文件是否存在
        if key_dir.join(format!("{}.key", handle.0)).exists() {
            println!("   密钥文件: ✅ 已创建");
        }
        if key_dir.join(format!("{}.json", handle.0)).exists() {
            println!("   元数据文件: ✅ 已创建");
        }
        
        // 清理
        std::fs::remove_dir_all(&key_dir).ok();
    }
    
    // 3. 加密文件存储
    println!("\n3. 加密文件存储:");
    {
        let key_dir = std::path::PathBuf::from("./demo_encrypted_keys");
        let encryption_key = vec![42u8; 32]; // 生产环境请使用适当的密钥派生
        let provider = Ed25519Provider::with_file_store(key_dir.clone(), Some(encryption_key))?;
        
        let handle = provider.generate()?;
        println!("   生成密钥: {:?}", handle);
        println!("   加密存储位置: {}", key_dir.display());
        
        let message = "加密存储测试".as_bytes();
        let signature = provider.sign(handle, message)?;
        let public_key = provider.public_spki_der(handle)?;
        let is_valid = provider.verify(&public_key, message, &signature)?;
        
        println!("   加密测试: {}", if is_valid { "✅ 通过" } else { "❌ 失败" });
        
        // 清理
        std::fs::remove_dir_all(&key_dir).ok();
    }
    
    // 4. HSM存储 (示例配置)
    println!("\n4. HSM存储 (需要硬件HSM):");
    println!("   配置示例:");
    println!("   - 模块: /usr/local/lib/softhsm/libsofthsm2.so");
    println!("   - 插槽: 0");
    println!("   - PIN: 1234");
    println!("   注意: HSM密钥无法导出，所有操作在HSM内部进行")
;
    
    println!("\n=== 演示完成 ===");
    println!("所有存储后端都使用相同的KeyProvider接口！");
    
    Ok(())
}