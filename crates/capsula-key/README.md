# Capsula Key Management

Capsula项目的灵活密钥管理库，支持多种存储后端。

## 特性

- **统一接口**: 所有存储后端都实现相同的 `KeyProvider` trait
- **多种存储**: 内存、文件、HSM支持
- **文件加密**: 使用ChaCha20Poly1305的可选加密
- **向后兼容**: 保持现有API不变
- **统一错误处理**: 集成到主error模块
- **异步支持**: 基于Tokio的异步存储操作

## 存储后端

### 1. 内存存储 (默认)
```rust
use capsula_key::impls::Ed25519Provider;

// 默认使用内存存储 (向后兼容)
let provider = Ed25519Provider::new()?;
```

### 2. 文件存储
```rust
use std::path::PathBuf;

// 未加密文件存储
let provider = Ed25519Provider::with_file_store(
    PathBuf::from("./keys"), 
    None
)?;

// 加密文件存储
let encryption_key = vec![0u8; 32]; // 生产环境请使用适当的密钥派生
let provider = Ed25519Provider::with_file_store(
    PathBuf::from("./keys"), 
    Some(encryption_key)
)?;
```

### 3. HSM存储
```rust
// 需要硬件HSM或SoftHSM
let provider = Ed25519Provider::with_hsm_store(
    "/usr/local/lib/softhsm/libsofthsm2.so".to_string(),
    0, // 插槽号
    Some("1234".to_string()) // PIN
)?;
```

## 使用示例

所有存储后端都使用相同的API：

```rust
use capsula_key::{impls::Ed25519Provider, provider::KeyProvider};

// 创建provider (任何存储后端)
let provider = Ed25519Provider::new()?; // 或其他存储方式

// 生成密钥
let handle = provider.generate()?;

// 签名
let message = b"Hello, world!";
let signature = provider.sign(handle, message)?;

// 获取公钥
let public_key = provider.public_spki_der(handle)?;

// 验证签名
let is_valid = provider.verify(&public_key, message, &signature)?;

// 导入/导出 (某些存储后端支持)
let pkcs8_der = provider.export_pkcs8_der(handle)?;
let new_handle = provider.import_pkcs8_der(&pkcs8_der)?;
```

## 运行演示

```bash
cargo run --example storage_demo
```

## 测试

```bash
cargo test
```

## HSM设置 (可选)

如需使用HSM功能，可安装SoftHSM进行测试：

```bash
# Ubuntu/Debian
sudo apt-get install softhsm2

# macOS
brew install softhsm

# 初始化测试令牌
softhsm2-util --init-token --slot 0 --label "test" --pin 1234 --so-pin 1234
```

## 架构设计

### 核心设计原则

1. **保持向后兼容**: 现有的 `Ed25519Provider::new()` 继续工作
2. **统一接口**: 所有存储后端实现相同的 `KeyProvider` trait
3. **统一错误处理**: 不再有独立的存储错误类型
4. **可插拔存储**: 通过配置轻松切换存储后端

### 存储抽象层

```rust
// 统一的存储配置
pub enum KeyStoreConfig {
    Memory,
    File { path: PathBuf, encryption_key: Option<Vec<u8>> },
    Hsm { module_path: String, slot: u64, pin: Option<String> },
}

// 统一的存储接口
#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn store_key(&self, metadata: KeyMetadata, pkcs8_der_bytes: Vec<u8>) -> Result<()>;
    async fn get_key(&self, handle: KeyHandle) -> Result<(KeyMetadata, Vec<u8>)>;
    // ... 其他方法
}
```

### 提供程序集成

`Ed25519Provider` 现在内部使用可配置的存储系统：

```rust
pub struct Ed25519Provider {
    store: Arc<dyn KeyStore>,    // 存储抽象
    runtime: Runtime,            // 异步运行时
    next_handle: Arc<Mutex<u64>>, // 句柄生成器
}
```

## 依赖项

- `tokio`: 异步运行时
- `async-trait`: 异步trait支持  
- `chacha20poly1305`: 文件加密
- `pkcs11`: HSM支持
- `ed25519-dalek`: Ed25519实现

## 许可证

与父级Capsula项目相同。