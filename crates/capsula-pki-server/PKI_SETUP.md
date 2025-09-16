# Capsula PKI Server Setup Guide

## 快速开始

### 1. 初始化PKI基础设施

运行初始化脚本来创建目录结构：

```bash
cd crates/capsula-pki-server
./init_pki.sh
```

脚本将创建以下目录结构：

```
pki_data/
├── ca/                     # Certificate Authority
│   ├── root/              # 根CA
│   │   ├── private/       # 根CA私钥 (权限700)
│   │   ├── certs/         # 根CA证书
│   │   ├── config/        # 根CA配置
│   │   ├── serial         # 证书序列号
│   │   └── index.txt      # 证书数据库
│   ├── intermediate/      # 中间CA
│   │   ├── private/       # 中间CA私钥
│   │   ├── certs/         # 中间CA证书
│   │   ├── config/        # 中间CA配置
│   │   ├── serial         # 证书序列号
│   │   └── index.txt      # 证书数据库
│   └── crl/              # 证书撤销列表
├── certs/                 # 用户证书
│   ├── issued/           # 已签发证书
│   ├── pending/          # 待处理证书请求
│   └── revoked/          # 已撤销证书
├── keys/                 # 密钥存储
│   ├── root/             # 根CA密钥 (权限700)
│   ├── intermediate/     # 中间CA密钥
│   └── users/            # 用户密钥
├── config/               # PKI配置文件
├── logs/                 # 审计日志
└── backup/               # 备份目录
```

### 2. 配置数据库

确保SurrealDB正在运行：

```bash
# 启动SurrealDB (如果尚未运行)
surreal start --bind 127.0.0.1:8000 --user root --pass root memory
```

### 3. 启动PKI服务器

```bash
cargo run -p capsula-pki-server
```

服务器将在 `http://localhost:13001` 启动

### 4. 初始化根CA

通过API初始化根证书颁发机构：

```bash
curl -X POST http://localhost:13001/ca/initialize \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "Capsula Root CA",
    "organization": "Your Organization",
    "organizational_unit": "IT Department",
    "country": "US",
    "state": "California",
    "locality": "San Francisco",
    "key_algorithm": "RSA",
    "key_size": 4096,
    "validity_days": 3650
  }'
```

### 5. 访问API文档

打开Swagger UI查看完整的API文档：

```
http://localhost:13001/swagger-ui
```

## 主要功能

### CA管理
- `GET /ca/status` - 获取CA状态
- `GET /ca/certificate` - 获取CA证书
- `POST /ca/initialize` - 初始化CA

### 证书管理
- `POST /certificates/create` - 创建新证书
- `GET /certificates/list` - 列出证书
- `GET /certificates/get/{id}` - 获取特定证书
- `POST /certificates/revoke/{id}` - 撤销证书

### 系统状态
- `GET /health` - 健康检查
- `GET /status` - 服务状态

## 配置说明

主要配置文件位于 `config/services.toml`：

### PKI配置
```toml
[pki]
# 基础设置
data_dir = "./pki_data"
default_validity_days = 365
root_ca_validity_days = 3650
intermediate_ca_validity_days = 1825

# 安全设置
min_key_size_rsa = 2048
min_key_size_ec = 256
require_strong_passwords = true

# 审计和日志
enable_audit_trail = true
audit_log_path = "./pki_data/logs"
```

### HTTP配置
```toml
[http]
port = 13001
```

### 数据库配置
```toml
[surrealdb]
host = "localhost"
port = 8000
username = "root"
password = "root"
namespace = "dev"
database = "dev"
```

## 安全注意事项

### 权限设置
- 根CA私钥目录权限设为700 (仅所有者可访问)
- 中间CA私钥目录权限设为700
- 其他敏感目录权限设为750
- 公共证书目录权限设为755

### 备份建议
1. 定期备份 `pki_data/ca/root/private/` 目录
2. 备份 `pki_data/ca/intermediate/private/` 目录
3. 备份配置文件和证书数据库
4. 将备份存储在安全的离线位置

### 生产环境建议
1. 使用专用的PKI用户账户
2. 考虑使用硬件安全模块(HSM)
3. 实施访问控制和审计
4. 定期轮换中间CA证书
5. 监控证书过期时间

## 故障排除

### 常见问题

**Q: 初始化脚本失败，提示权限错误**
A: 确保有足够权限创建目录，可能需要调整父目录权限

**Q: 服务器启动失败，数据库连接错误**
A: 检查SurrealDB是否运行，配置是否正确

**Q: CA初始化失败**
A: 检查pki_data目录是否存在且有正确权限

**Q: 证书签发失败**
A: 确保CA已正确初始化，检查日志文件

### 日志查看
```bash
# 查看服务器日志
tail -f pki_data/logs/capsula-pki-server.log

# 查看初始化日志
cat pki_data/.initialized
```

## 开发模式

如果需要重新初始化PKI结构：

```bash
./init_pki.sh --force
```

这将删除现有的PKI数据并重新创建目录结构。

⚠️ **警告：这将删除所有现有的证书和密钥！**