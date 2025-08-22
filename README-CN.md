# Capsula - 数据胶囊加密库

[English](README.md) | [中文](README-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)

Capsula 是一个用 Rust 编写的数据胶囊加密库，提供完整的加密基础设施，包括密钥管理、数字签名、PKI 基础设施等功能。

## 项目结构

本项目采用 Rust workspace 结构，包含以下 crates：

- **`capsula-crypto`** - 基础加密原语库
  - Ed25519 密钥对生成和管理
  - 数字签名（支持位置信息和时间戳）
  - 哈希功能（SHA-256, SHA-512）

- **`capsula-pki`** - PKI 基础设施库
  - X.509 证书管理
  - 证书颁发机构（CA）
  - 证书撤销列表（CRL）
  - 证书链验证
  - 证书存储

- **`capsula-core`** - 核心功能库（开发中）
  - 数据加密和解密
  - 访问控制
  - 数据完整性验证

- **`capsula-api`** - API 服务库（开发中）
  - RESTful API 接口
  - 认证和授权
  - 请求处理

- **`capsula-cli`** - 命令行工具（开发中）
  - 用户交互界面
  - 功能命令实现

## 功能特性

### 🔐 加密功能
- **Ed25519 密钥管理**：安全的密钥生成、导入/导出（支持 PEM、DER、HEX 格式）
- **数字签名**：支持带位置信息和时间戳的数字签名
- **哈希算法**：SHA-256 和 SHA-512 支持

### 🏛️ PKI 基础设施
- **X.509 证书**：创建、签名、验证证书
- **证书颁发机构**：完整的 CA 功能，支持根 CA 和中间 CA
- **证书撤销**：CRL 管理和验证
- **证书链验证**：完整的证书链构建和验证

### 🏥 医疗场景支持
- 支持医疗机构证书
- 位置信息签名（医院、科室信息）
- 审计追踪

## 快速开始

### 安装要求

- Rust 1.70 或更高版本
- Cargo

### 编译项目

```bash
git clone https://github.com/ancient/capsula.git
cd capsula
cargo build --release
```

### 运行测试

```bash
cargo test
```

## 使用示例

### 生成密钥对

```rust
use capsula_crypto::EccKeyPair;

// 生成新的 Ed25519 密钥对
let keypair = EccKeyPair::generate_keypair()?;

// 导出私钥为 PEM 格式
let private_key_pem = keypair.export_private_key()?;

// 导出公钥
let public_key_bytes = keypair.get_public_key_bytes();
```

### 数字签名

```rust
use capsula_crypto::{EccKeyPair, LocationInfo};

let keypair = EccKeyPair::generate_keypair()?;

// 创建位置信息
let location = LocationInfo {
    latitude: Some(31.2304),
    longitude: Some(121.4737),
    address: Some("上海市第一人民医院".to_string()),
    institution_id: Some("HOSPITAL_001".to_string()),
    department: Some("心内科".to_string()),
};

// 签名数据
let data = b"patient medical record";
let signature = keypair.sign_data(
    data,
    location,
    Some("Dr. 李医生".to_string()),
    Some("诊断记录".to_string()),
)?;

// 验证签名
let is_valid = keypair.verify_signature(data, &signature)?;
```

### 创建证书

```rust
use capsula_crypto::EccKeyPair;
use capsula_pki::{create_certificate, CertificateSubject};

let keypair = EccKeyPair::generate_keypair()?;

// 创建证书主体信息
let subject = CertificateSubject::medical_institution(
    "上海市第一人民医院".to_string(),
    Some("心内科".to_string()),
    "上海".to_string(),
    "上海".to_string(),
    "CN".to_string(),
);

// 创建证书（有效期 365 天）
let cert = create_certificate(&keypair, subject, None, 365, false)?;
```

### 创建 CA 并签发证书

```rust
use capsula_pki::{CertificateAuthority, CAConfig};

// 创建根 CA
let ca_config = CAConfig::default();
let mut root_ca = CertificateAuthority::new_root_ca(ca_config)?;

// 为终端实体签发证书
let entity_keypair = EccKeyPair::generate_keypair()?;
let entity_subject = CertificateSubject::new("医疗设备-001".to_string());

let entity_cert = root_ca.issue_certificate(
    entity_subject,
    &entity_keypair,
    Some(365),  // 有效期 365 天
    false,      // 不是 CA 证书
)?;
```

## API 文档

详细的 API 文档可以通过以下命令生成：

```bash
cargo doc --open
```

## 项目状态

- ✅ **capsula-crypto** - 已完成
- ✅ **capsula-pki** - 已完成
- 🚧 **capsula-core** - 开发中
- 🚧 **capsula-api** - 开发中
- 🚧 **capsula-cli** - 开发中

## 贡献

欢迎贡献代码！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解更多信息。

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](LICENSE) 文件。

## 联系方式

- 项目主页：[https://github.com/ancient/capsula](https://github.com/ancient/capsula)
- 问题反馈：[Issues](https://github.com/ancient/capsula/issues)

## 致谢

感谢以下开源项目：

- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) - Ed25519 签名算法实现
- [rcgen](https://github.com/rustls/rcgen) - X.509 证书生成
- [x509-cert](https://github.com/RustCrypto/x509-cert) - X.509 证书解析

---

**注意**：本项目仍在积极开发中，API 可能会发生变化。生产环境使用请谨慎评估。