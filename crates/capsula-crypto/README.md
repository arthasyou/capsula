# capsula-crypto

基础加密原语库，提供密钥管理、数字签名和哈希功能。

## 功能特性

- **Ed25519 密钥对管理**
  - 安全的密钥生成
  - 多格式导入/导出（PEM、DER、HEX）
  - 密钥验证

- **数字签名**
  - 标准 Ed25519 签名
  - 扩展签名（支持位置信息和时间戳）
  - 签名验证

- **哈希功能**
  - SHA-256
  - SHA-512
  - 多种输出格式

## 使用示例

### 密钥管理

```rust
use capsula_crypto::EccKeyPair;

// 生成密钥对
let keypair = EccKeyPair::generate_keypair()?;

// 导出私钥
let private_pem = keypair.export_private_key()?;
let private_der = keypair.export_private_key_der()?;
let private_hex = keypair.export_private_key_hex();

// 导入私钥
let imported = EccKeyPair::import_private_key(&private_pem)?;
```

### 数字签名

```rust
use capsula_crypto::{EccKeyPair, LocationInfo};

let keypair = EccKeyPair::generate_keypair()?;
let data = b"important data";

// 简单签名
let signature = keypair.sign_with_timestamp(data, Some("signer".to_string()))?;

// 带位置信息的签名
let location = LocationInfo {
    latitude: Some(31.2304),
    longitude: Some(121.4737),
    address: Some("Hospital".to_string()),
    institution_id: Some("HOSP001".to_string()),
    department: Some("Cardiology".to_string()),
};

let signature = keypair.sign_data(
    data,
    location,
    Some("Dr. Smith".to_string()),
    Some("Medical Record".to_string()),
)?;

// 验证签名
let is_valid = keypair.verify_signature(data, &signature)?;
```

### 哈希计算

```rust
use capsula_crypto::{hash_data, hash_data_hex, HashAlgorithm};

let data = b"hello world";

// 计算哈希
let hash = hash_data(data, HashAlgorithm::SHA256);
let hash_hex = hash_data_hex(data, HashAlgorithm::SHA256);

// 验证哈希
use capsula_crypto::verify_hash;
let is_valid = verify_hash(data, &hash, HashAlgorithm::SHA256);
```

## 依赖

- `ed25519-dalek` - Ed25519 实现
- `sha2` - SHA 哈希算法
- `getrandom` - 安全随机数生成
- `serde` - 序列化支持