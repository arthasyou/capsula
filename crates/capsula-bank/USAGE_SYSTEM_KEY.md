# System RSA Key Usage Guide

## 初始化（在 main.rs 中）

在 `main.rs` 中，**必须**在启动服务器之前初始化系统 RSA 密钥：

```rust
use capsula_bank::{
    db::{create_tables, init_db},
    logging::init_tracing,
    routes,
    settings::Settings,
    static_files::key,  // 添加这一行
};

#[tokio::main]
async fn main() {
    init_tracing();
    let settings = Settings::load("config/services.toml").unwrap();

    // 初始化数据库...
    init_db(settings.surrealdb).await.unwrap();
    create_tables().await.unwrap();

    // 初始化系统 RSA 密钥 - 必须在启动服务前调用
    tracing::info!("Initializing system RSA key from: {}", settings.key.private_key_path);
    key::init_system_key(&settings.key.private_key_path)
        .expect("Failed to initialize system RSA key. Server cannot start.");
    tracing::info!("System RSA key initialized successfully");

    // 启动服务器...
    let router = routes::create_routes();
    let http_task = http_server::start(settings.http.port, router);

    let _ = tokio::join!(http_task);
}
```

## 使用（在任何地方）

初始化后，在代码的任何地方都可以直接获取密钥引用，**不需要处理 Result**：

```rust
use capsula_bank::static_files::key;

// 在 handler 中使用
pub async fn some_handler() -> Result<Json<Response>> {
    // 直接获取，返回 &'static RsaKey
    let rsa_key = key::get_system_key();

    // 使用密钥进行签名
    let signature = rsa_key.sign(data)?;

    // 使用密钥进行加密
    let encrypted = rsa_key.encrypt(plaintext)?;

    Ok(Json(response))
}

// 在其他模块中使用
pub fn verify_signature(data: &[u8], signature: &[u8]) -> bool {
    let rsa_key = key::get_system_key();
    // ... 验证逻辑
}
```

## 配置文件

`config/services.toml`:
```toml
[key]
private_key_path = "keys/system_private.pem"
```

## 特点

1. ✅ **线程安全**: 使用 `OnceLock`，多线程环境下安全
2. ✅ **零成本**: 内联函数，无性能开销
3. ✅ **编译时保证**: 返回 `&'static RsaKey`，生命周期由编译器保证
4. ✅ **启动时失败快**: 如果密钥加载失败，应用直接 panic，不会启动
5. ✅ **简洁 API**: 不需要到处传递 `Result`，代码更清晰

## 注意事项

⚠️ **必须在 main() 中调用 `init_system_key()`**，否则首次调用 `get_system_key()` 时会 panic。

这是设计上的选择：如果系统密钥加载失败，应用程序不应该启动，而不是在运行时才发现问题。
