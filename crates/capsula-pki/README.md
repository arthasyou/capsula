# capsula-pki

PKI (Public Key Infrastructure) 基础设施库，提供证书管理、CA、CRL 等功能。

## 功能特性

- **X.509 证书管理**
  - 证书创建和签名
  - 证书验证
  - 证书导入/导出（PEM、DER）

- **证书颁发机构（CA）**
  - 根 CA 创建
  - 中间 CA 创建
  - 证书签发
  - CA 导入/导出

- **证书撤销列表（CRL）**
  - 证书撤销管理
  - CRL 生成和签名
  - 撤销状态检查

- **证书链验证**
  - 证书链构建
  - 链验证
  - 信任锚管理

- **证书存储**
  - 文件系统存储
  - 证书搜索
  - 元数据管理

## 使用示例

### 创建证书

```rust
use capsula_crypto::EccKeyPair;
use capsula_pki::{create_certificate, CertificateSubject};

let keypair = EccKeyPair::generate_keypair()?;

// 创建医疗机构证书
let subject = CertificateSubject::medical_institution(
    "Shanghai First Hospital".to_string(),
    Some("Cardiology".to_string()),
    "Shanghai".to_string(),
    "Shanghai".to_string(),
    "CN".to_string(),
);

let cert = create_certificate(&keypair, subject, None, 365, false)?;
```

### 创建和使用 CA

```rust
use capsula_pki::{CertificateAuthority, CAConfig};

// 创建根 CA
let config = CAConfig {
    name: "Medical Root CA".to_string(),
    organization: "Healthcare PKI".to_string(),
    validity_days: 3650,
    ..CAConfig::default()
};

let mut root_ca = CertificateAuthority::new_root_ca(config)?;

// 创建中间 CA
let intermediate_config = CAConfig {
    name: "Regional CA".to_string(),
    validity_days: 1825,
    ..CAConfig::default()
};

let mut intermediate_ca = root_ca.create_intermediate_ca(intermediate_config)?;

// 签发终端实体证书
let entity_keypair = EccKeyPair::generate_keypair()?;
let entity_subject = CertificateSubject::new("Medical Device".to_string());

let entity_cert = intermediate_ca.issue_certificate(
    entity_subject,
    &entity_keypair,
    Some(365),
    false,
)?;
```

### 管理 CRL

```rust
use capsula_pki::{CRLManager, RevocationReason};

let ca_keypair = EccKeyPair::generate_keypair()?;
let mut crl_manager = CRLManager::new(
    "Medical CA".to_string(),
    ca_keypair,
    7, // 更新间隔 7 天
    true, // 自动签名
);

// 撤销证书
crl_manager.revoke_certificate(
    "12345".to_string(),
    RevocationReason::KeyCompromise,
    None,
)?;

// 导出 CRL
let crl_json = crl_manager.export()?;
```

### 验证证书链

```rust
use capsula_pki::{ChainValidator, build_certificate_chain};

// 创建验证器
let mut validator = ChainValidator::new();
validator.add_trusted_root(root_ca_cert)?;
validator.set_check_revocation(true);

// 构建证书链
let chain = build_certificate_chain(&end_entity_cert, &available_certs)?;

// 验证链
let result = validator.validate_chain(&chain);
if result.is_valid {
    println!("Certificate chain is valid");
} else {
    println!("Validation errors: {:?}", result.errors);
}
```

### 证书存储

```rust
use capsula_pki::CertificateStore;

// 创建文件系统存储
let mut store = CertificateStore::file_system("./pki_store")?;

// 存储证书
store.store_certificate(&cert)?;

// 搜索即将过期的证书
let expiring = store.get_expiring_certificates(30)?; // 30天内过期

// 更新证书状态
use capsula_pki::CertificateStatus;
store.update_status(&serial_number, CertificateStatus::Revoked {
    reason: RevocationReason::KeyCompromise,
    revoked_at: OffsetDateTime::now_utc(),
})?;
```

## 证书格式

支持的证书格式：
- X.509 v3
- DER 编码
- PEM 编码

支持的密钥算法：
- Ed25519

## 依赖

- `capsula-crypto` - 加密原语
- `rcgen` - 证书生成
- `x509-cert` - 证书解析
- `der` - DER 编码/解码
- `pem` - PEM 格式支持