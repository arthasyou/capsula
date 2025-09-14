# Capsula - 安全数据胶囊与PKI基础设施

[English](README.md) | [中文](README-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)

Capsula 是一个用 Rust 编写的综合性密码学基础设施库，提供安全数据封装、PKI管理以及多平台密码学操作，特别针对医疗和机构应用场景进行优化。

## 🏗️ 项目架构

本项目采用模块化 Rust workspace 结构，包含以下组件：

### 核心密码学库
- **`capsula-crypto`** - 基础密码学原语
  - Ed25519、RSA-2048、P256 ECDSA 密钥管理
  - 带位置和时间戳元数据的数字签名
  - 哈希函数（SHA-256、SHA-512）

- **`capsula-key`** - 高级密钥管理系统
  - 多算法密钥生成（Ed25519、RSA、P256）
  - 加密密钥存储
  - 密钥推导和轮换
  - PEM/DER格式支持

- **`capsula-pki`** - 企业级PKI基础设施
  - X.509证书管理和验证
  - 层级证书颁发机构（CA）支持委托
  - 证书撤销列表（CRL）管理
  - 证书链构建和验证
  - 医疗机构证书模板

### 数据管理与API
- **`capsula-core`** - 安全数据封装引擎
  - 数据胶囊创建和验证
  - 基于策略的访问控制
  - 审计跟踪管理
  - 数据完整性和真实性验证

- **`capsula-api`** - REST API服务器（PKI服务器）
  - 证书颁发机构管理端点
  - 证书生命周期操作
  - OpenAPI文档与Swagger UI
  - 基于Axum框架的生产就绪服务

### 多平台支持
- **`capsula-cli`** - 命令行接口
  - 证书和密钥管理操作
  - 批处理功能
  - 管理工具

- **`capsula-wasm`** - WebAssembly绑定
  - 浏览器和Node.js兼容性
  - 密钥生成和密码学操作
  - 适用于Web应用和前端安全

- **`capsula-ffi`** - 外部函数接口
  - C/C++语言绑定
  - 跨平台库集成
  - 内存安全API设计

## ✨ 主要特性

### 🔐 高级密码学
- **多算法支持**：Ed25519、RSA-2048、P256 ECDSA，支持自动算法检测
- **增强数字签名**：上下文感知签名，包含位置、时间戳和元数据
- **安全密钥存储**：加密密钥存储，支持多种导出格式（PEM、DER、PKCS#8）
- **密码学哈希函数**：SHA-256、SHA-512，具备验证功能

### 🏛️ 企业级PKI基础设施
- **完整证书生命周期**：生成、签名、验证和撤销
- **层级证书颁发机构**：根CA和中间CA支持委托
- **证书撤销列表**：完整的CRL管理和验证
- **信任链**：自动化证书链构建和验证
- **REST API服务器**：生产就绪的PKI服务，提供OpenAPI文档

### 🌐 多平台集成
- **WebAssembly**：支持浏览器和Node.js的Web应用
- **C/C++ FFI**：系统编程的本地集成
- **命令行工具**：管理和批处理功能
- **跨平台**：Windows、macOS和Linux支持

### 🏥 专业应用场景
- **医疗机构证书**：专门的医疗保健模板
- **基于位置的签名**：签名中包含地理和机构上下文
- **审计跟踪管理**：全面的日志记录和验证
- **数据胶囊系统**：带访问策略的安全数据封装

## 快速开始

### 安装要求

- Rust 1.70 或更高版本
- Cargo（Rust附带）
- 对于WASM：`wasm-pack`（通过 `curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh` 安装）

### 快速安装

```bash
git clone https://github.com/ancient/capsula.git
cd capsula
cargo build --release
```

### 运行测试

```bash
# 运行所有workspace测试
cargo test --workspace

# 测试特定组件
cargo test -p capsula-crypto    # 密码学原语
cargo test -p capsula-pki       # PKI基础设施
cargo test -p capsula-key       # 密钥管理
cargo test -p capsula-core      # 数据胶囊系统
```

### 启动PKI服务器

```bash
# 启动REST API服务器（默认端口：19878）
cargo run -p capsula-api

# 访问Swagger UI：http://localhost:19878/swagger-ui
# API文档：http://localhost:19878/api-docs/openapi.json
```

## 📋 使用示例

### 基本密钥生成

```rust
use capsula_key::{KeyPair, Algorithm};

// 生成Ed25519密钥对
let keypair = KeyPair::generate(Algorithm::Ed25519)?;

// 导出不同格式
let private_pem = keypair.export_private_key_pem()?;
let public_pem = keypair.export_public_key_pem()?;
let private_der = keypair.export_private_key_der()?;
```

### 多算法支持

```rust
use capsula_key::{KeyPair, Algorithm};

// 支持多种算法
let ed25519_key = KeyPair::generate(Algorithm::Ed25519)?;
let rsa_key = KeyPair::generate(Algorithm::Rsa2048)?;
let p256_key = KeyPair::generate(Algorithm::P256)?;

// 从导入的密钥自动检测算法
let imported_key = KeyPair::import_from_pem_file("my_key.pem")?;
println!("检测到的算法: {:?}", imported_key.algorithm());
```

### 增强数字签名

```rust
use capsula_crypto::{EccKeyPair, LocationInfo};

let keypair = EccKeyPair::generate_keypair()?;

// 创建增强的位置上下文
let location = LocationInfo {
    latitude: Some(31.2304),
    longitude: Some(121.4737),
    address: Some("上海市第一人民医院".to_string()),
    institution_id: Some("HOSPITAL_001".to_string()),
    department: Some("心内科".to_string()),
};

// 使用丰富上下文进行签名
let data = b"患者病历记录 - ID: 12345";
let signature = keypair.sign_data(
    data,
    location,
    Some("李医生".to_string()),
    Some("医学诊断".to_string()),
)?;

// 带上下文验证的签名验证
let is_valid = keypair.verify_signature(data, &signature)?;
assert!(is_valid);
```

### PKI证书管理

```rust
use capsula_pki::{CertificateAuthority, CAConfig, CertificateSubject};
use capsula_key::{KeyPair, Algorithm};

// 创建证书颁发机构
let ca_keypair = KeyPair::generate(Algorithm::Ed25519)?;
let ca_config = CAConfig::default();
let mut ca = CertificateAuthority::new_root_ca(ca_config)?;

// 为医疗机构签发证书
let entity_keypair = KeyPair::generate(Algorithm::Ed25519)?;
let subject = CertificateSubject::medical_institution(
    "北京医院".to_string(),
    Some("放射科".to_string()),
    "北京".to_string(),
    "北京".to_string(),
    "CN".to_string(),
);

let certificate = ca.issue_certificate(
    subject,
    &entity_keypair,
    Some(365), // 1年有效期
    false,     // 终端实体证书
)?;
```

### 数据胶囊操作

```rust
use capsula_core::{DataCapsule, EncryptionPolicy, AccessControl};

// 创建安全数据胶囊
let data = b"机密医疗数据";
let policy = EncryptionPolicy::default()
    .with_access_control(AccessControl::Medical)
    .with_audit_trail(true);

let capsule = DataCapsule::create(data, policy)?;

// 验证并提取数据
let verified_data = capsule.verify_and_extract()?;
assert_eq!(data, verified_data.as_slice());
```

### WebAssembly集成

```javascript
// 在浏览器或Node.js中
import init, { KeyPair, sha256Hex } from './pkg/capsula_wasm.js';

async function cryptoDemo() {
    await init(); // 初始化WASM模块
    
    // 生成密钥对
    const keyPair = new KeyPair();
    const publicKeyPem = keyPair.exportPublicKeyPem();
    
    // 哈希计算
    const data = new TextEncoder().encode('你好，Capsula！');
    const hash = sha256Hex(data);
    
    console.log('公钥:', publicKeyPem);
    console.log('SHA256:', hash);
}
```

### C/C++ FFI集成

```c
#include "capsula.h"

int main() {
    // 使用自动算法选择生成密钥
    CapsulaResult* key = capsula_key_generate(Curve25519);
    if (key->error_code != 0) {
        printf("错误: %s\n", key->error_message);
        return 1;
    }
    
    // 签名数据
    const char* message = "来自C语言的问候！";
    CapsulaResult* signature = capsula_sign(
        key->data, key->data_len,
        (unsigned char*)message, strlen(message)
    );
    
    printf("签名已创建: %u 字节\n", signature->data_len);
    
    // 清理
    capsula_free_result(key);
    capsula_free_result(signature);
    return 0;
}
```

## 🚀 运行示例

项目包含展示主要功能的综合示例程序：

```bash
# 核心功能演示
cargo run --example core_demo

# 密钥管理和使用
cargo run --example key_usage_demo
cargo run --example key_export_demo

# 加密密钥存储功能
cargo run --example key_store_demo

# PKI服务器API测试
curl http://localhost:19878/health
curl http://localhost:19878/api/v1/ca/status
```

### WebAssembly示例

```bash
# 为Web构建WASM模块
cd crates/capsula-wasm
wasm-pack build --target web --out-dir pkg

# 启动本地服务器并测试
python3 -m http.server 8000
# 访问: http://localhost:8000/example.html
```

### FFI示例

```bash
# 构建FFI库
cargo build --release -p capsula-ffi

# 编译并运行C示例
gcc -o demo demo.c \
    -I target/release/include/capsula-ffi \
    -L target/release \
    -lcapsula_ffi
./demo
```

## 📚 文档

生成综合API文档：

```bash
# 为所有crate生成文档
cargo doc --open --workspace

# 为特定crate生成文档
cargo doc -p capsula-pki --open
```

## 📊 开发状态

| 组件 | 状态 | 描述 |
|------|------|------|
| **capsula-crypto** | ✅ **稳定** | 密码学原语和增强签名 |
| **capsula-key** | ✅ **稳定** | 多算法密钥管理系统 |
| **capsula-pki** | ✅ **稳定** | 完整PKI基础设施和CA |
| **capsula-core** | 🚧 **活跃开发** | 数据胶囊系统和访问控制 |
| **capsula-api** | ✅ **测试版** | 带OpenAPI支持的REST API服务器 |
| **capsula-wasm** | ✅ **稳定** | Web平台WebAssembly绑定 |
| **capsula-ffi** | ✅ **稳定** | C/C++外部函数接口 |
| **capsula-cli** | 🚧 **规划中** | 命令行管理工具 |

### 最近更新
- ✅ 增强的多算法密钥支持（Ed25519、RSA、P256）
- ✅ 生产就绪的PKI REST API服务器，带Swagger文档
- ✅ WebAssembly绑定，支持浏览器和Node.js兼容性
- ✅ 内存安全API设计的C/C++ FFI
- 🚧  带基于策略访问控制的数据胶囊系统

## 贡献

欢迎贡献代码！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解更多信息。

## 许可证

本项目采用MIT许可证。详见 [LICENSE](LICENSE) 文件。

## 联系方式

- 项目主页：[https://github.com/ancient/capsula](https://github.com/ancient/capsula)
- 问题反馈：[Issues](https://github.com/ancient/capsula/issues)

## 致谢

感谢以下开源项目：

- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) - Ed25519签名算法实现
- [rcgen](https://github.com/rustls/rcgen) - X.509证书生成
- [x509-cert](https://github.com/RustCrypto/x509-cert) - X.509证书解析

---

**注意**：本项目仍在积极开发中，API可能会发生变化。生产环境使用请谨慎评估。