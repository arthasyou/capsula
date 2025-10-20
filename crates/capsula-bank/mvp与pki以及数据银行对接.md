# Capsula Bank 架构设计文档

## 目录
- [PKI 证书申请流程](#pki-证书申请流程)
- [系统架构概览](#系统架构概览)
- [当前实现流程](#当前实现流程)
- [推荐架构流程](#推荐架构流程)

---

## PKI 证书申请流程

### 方案 1: 极简方案（推荐）⭐

**设计理念**：客户端零密码学操作，一次 API 调用完成所有流程。

```mermaid
sequenceDiagram
    participant Client as 客户端
    participant PKI as PKI 服务器
    participant DB as 密钥数据库

    Note over Client: 一次性申请证书和密钥

    Client->>PKI: POST /api/v1/certificate/generate<br/>{<br/>  user_id: "user123",<br/>  cert_type: "encryption",<br/>  validity_days: 365<br/>}

    Note over PKI: 服务器端处理所有密码学操作
    PKI->>PKI: 1. 验证用户身份
    PKI->>PKI: 2. 生成密钥对<br/>(RSA-4096/Ed25519)
    PKI->>PKI: 3. 创建自签名证书<br/>(或向内部 CA 申请)
    PKI->>PKI: 4. 加密存储私钥

    PKI->>DB: 保存密钥对和证书
    DB-->>PKI: 确认保存

    PKI-->>Client: 返回证书信息<br/>{<br/>  cert_id: "cert_xxxxx",<br/>  certificate: "...",<br/>  private_key: "...",<br/>  fingerprint: "sha256:...",<br/>  valid_from: timestamp,<br/>  valid_until: timestamp<br/>}

    Note over Client: 完成！客户端保存证书即可使用
```

**极简方案 API 设计**：

```typescript
// 请求
POST /api/v1/certificate/generate
Content-Type: application/json
Authorization: Bearer <auth_token>

{
    "user_id": "user123",
    "cert_type": "encryption",  // 或 "signing"
    "validity_days": 365        // 可选，默认 365 天
}

// 响应
{
    "cert_id": "cert_xxxxx",
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...",
    "fingerprint": "sha256:abcd1234...",
    "valid_from": 1705334400,
    "valid_until": 1736870400,
    "algorithm": "RSA-4096",
    "key_usage": ["keyEncipherment", "dataEncipherment"]
}
```

**极简方案优势**：

```
✅ 客户端零密码学操作
   - 无需生成密钥对
   - 无需创建 CSR
   - 无需处理证书格式

✅ 一次 API 调用完成
   - 同步返回结果
   - 无需轮询状态
   - 即时可用

✅ 服务器端安全托管
   - 私钥加密存储
   - 统一密钥管理
   - 支持密钥恢复

✅ 简化客户端开发
   - 降低技术门槛
   - 减少错误可能
   - 加快集成速度
```

---

### 方案 2: 标准方案（传统 PKI 流程）

**设计理念**：遵循传统 PKI 标准，客户端管理密钥对。

```mermaid
sequenceDiagram
    participant Client as 客户端
    participant PKI as PKI 服务器
    participant CA as 证书颁发机构 (CA)
    participant Bank as Capsula Bank

    Note over Client: 阶段 1: 密钥对生成
    Client->>Client: 生成 RSA/Ed25519 密钥对<br/>(私钥 + 公钥)
    Client->>Client: 安全存储私钥<br/>(本地加密存储)

    Note over Client: 阶段 2: 创建证书签名请求 (CSR)
    Client->>Client: 生成 CSR<br/>包含：<br/>- 公钥<br/>- 用户身份信息<br/>- 域名/组织信息
    Client->>Client: 使用私钥签名 CSR

    Note over Client,PKI: 阶段 3: 提交 CSR 到 PKI 服务器
    Client->>PKI: POST /api/v1/csr/submit<br/>{<br/>  csr: "-----BEGIN CERTIFICATE REQUEST-----...",<br/>  user_id: "user123",<br/>  cert_type: "signing" | "encryption"<br/>}

    PKI->>PKI: 验证 CSR 格式
    PKI->>PKI: 验证签名
    PKI->>PKI: 验证用户身份

    Note over PKI: 阶段 4: PKI 处理请求
    PKI->>PKI: 检查策略和权限
    PKI->>PKI: 生成证书请求 ID
    PKI-->>Client: 返回请求 ID<br/>{<br/>  request_id: "req_xxxxx",<br/>  status: "pending"<br/>}

    Note over PKI,CA: 阶段 5: PKI 向 CA 请求签名
    PKI->>CA: 提交 CSR 请求<br/>(可能需要管理员审批)
    CA->>CA: 验证请求
    CA->>CA: 使用 CA 私钥签名证书
    CA->>CA: 生成 X.509 证书<br/>包含：<br/>- 公钥<br/>- 证书有效期<br/>- 用途限制<br/>- CA 签名

    CA-->>PKI: 返回签名的证书

    Note over Client,PKI: 阶段 6: 客户端查询证书状态
    Client->>PKI: GET /api/v1/cert/status/{request_id}

    alt 证书已签发
        PKI-->>Client: {<br/>  status: "approved",<br/>  cert_id: "cert_xxxxx"<br/>}

        Client->>PKI: GET /api/v1/cert/download/{cert_id}
        PKI-->>Client: 返回证书链<br/>{<br/>  certificate: "-----BEGIN CERTIFICATE-----...",<br/>  ca_chain: ["-----BEGIN CERTIFICATE-----..."],<br/>  expires_at: 1767235200<br/>}
    else 等待审批
        PKI-->>Client: {<br/>  status: "pending",<br/>  message: "等待管理员审批"<br/>}
    else 被拒绝
        PKI-->>Client: {<br/>  status: "rejected",<br/>  reason: "身份验证失败"<br/>}
    end

    Note over Client: 阶段 7: 客户端存储证书
    Client->>Client: 保存证书到本地<br/>与私钥关联
    Client->>Client: 验证证书<br/>- 检查签名<br/>- 验证有效期<br/>- 验证证书链

    Note over Client,Bank: 阶段 8: 使用证书
    Client->>Client: 加载私钥 + 证书
    Client->>Client: 创建签名/加密操作

    Client->>Bank: 使用证书进行操作<br/>(如创建胶囊时签名)
    Bank->>Bank: 验证证书有效性<br/>- 检查 CA 签名<br/>- 验证有效期<br/>- 检查吊销状态

    alt 证书有效
        Bank-->>Client: 操作成功
    else 证书无效
        Bank-->>Client: 证书验证失败<br/>(需要更新证书)
    end
```

**标准方案特点**：

```
✅ 符合 PKI 标准
   - 遵循 X.509 规范
   - 支持证书链验证
   - 兼容 OpenSSL 工具

✅ 客户端掌控私钥
   - 私钥不离开客户端
   - 符合零信任架构
   - 适合高安全场景

❌ 实现复杂
   - 需要客户端密码学库
   - 需要处理证书格式
   - 需要管理密钥存储

❌ 集成门槛高
   - 需要理解 PKI 概念
   - 需要处理多步流程
   - 容易出错
```

---



### PKI API 端点汇总

#### 极简方案 API

```
POST   /api/v1/certificate/generate      - 一次性生成证书和密钥（推荐）
GET    /api/v1/certificate/{cert_id}     - 获取证书信息
GET    /api/v1/certificate/list          - 列出用户的所有证书
POST   /api/v1/certificate/revoke        - 吊销证书
POST   /api/v1/decrypt                   - 解密 DEK（使用托管私钥）
GET    /api/v1/verify/{fingerprint}      - 验证证书有效性
```

#### 标准方案 API

```
POST   /api/v1/csr/submit                - 提交证书签名请求（CSR）
GET    /api/v1/cert/status/{request_id}  - 查询证书申请状态
GET    /api/v1/cert/download/{cert_id}   - 下载签名的证书
GET    /api/v1/cert/list                 - 列出用户的证书
POST   /api/v1/cert/revoke               - 吊销证书
GET    /api/v1/cert/verify               - 验证证书有效性
GET    /api/v1/ca/chain                  - 获取 CA 证书链
```

#### 通用 API

```
GET    /api/v1/ca/certificate            - 获取 CA 根证书
GET    /api/v1/health                    - 健康检查
GET    /api/v1/info                      - 服务信息
```

### 证书生命周期管理

#### 极简方案生命周期

```mermaid
stateDiagram-v2
    [*] --> Requested: 客户端请求生成
    Requested --> Generated: PKI 生成证书
    Generated --> Active: 证书激活
    Active --> NearExpiry: 即将过期（30天内）
    NearExpiry --> Renewed: 续期
    Active --> Revoked: 吊销
    Revoked --> [*]
    NearExpiry --> Expired: 已过期
    Expired --> [*]
    Renewed --> Active: 新证书激活
```

**极简方案特点**：
- 即时生成，无需等待审批
- 自动续期机制
- 统一密钥管理

#### 标准方案生命周期

```mermaid
stateDiagram-v2
    [*] --> KeyGeneration: 客户端生成密钥对
    KeyGeneration --> CSRCreation: 创建 CSR
    CSRCreation --> Submitted: 提交到 PKI
    Submitted --> Pending: 等待审批
    Pending --> Approved: 审批通过
    Pending --> Rejected: 审批拒绝
    Approved --> Active: 证书激活
    Active --> NearExpiry: 即将过期
    NearExpiry --> Renewed: 续期
    Active --> Revoked: 吊销
    Revoked --> [*]
    Rejected --> [*]
    NearExpiry --> Expired: 已过期
    Expired --> [*]
```

**标准方案特点**：
- 需要审批流程
- 客户端管理密钥
- 符合传统 PKI 标准

### 证书更新流程

#### 极简方案更新流程

```mermaid
sequenceDiagram
    participant Client as 客户端
    participant PKI as PKI 服务器
    participant Bank as Bank 服务

    Note over Client: 证书即将过期（自动检测）
    Client->>PKI: GET /api/v1/certificate/{cert_id}
    PKI-->>Client: 证书将在 30 天后过期

    Note over Client: 自动续期
    Client->>PKI: POST /api/v1/certificate/renew<br/>{cert_id: "cert_xxxxx"}

    PKI->>PKI: 验证旧证书
    PKI->>PKI: 生成新的密钥对
    PKI->>PKI: 创建新证书
    PKI->>PKI: 自动吊销旧证书

    PKI-->>Client: 返回新证书

    Client->>Bank: 使用新证书
    Bank->>Bank: 验证新证书
    Bank-->>Client: 操作成功
```

**极简方案续期 API**：

```typescript
// 续期请求
POST /api/v1/certificate/renew
{
    "cert_id": "cert_xxxxx",
    "validity_days": 365  // 可选
}

// 响应
{
    "old_cert_id": "cert_xxxxx",
    "new_cert_id": "cert_yyyyy",
    "certificate": "-----BEGIN CERTIFICATE-----...",
    "public_key": "-----BEGIN PUBLIC KEY-----...",
    "valid_from": 1705334400,
    "valid_until": 1736870400,
    "revoked_old_cert": true
}
```

#### 标准方案更新流程

```mermaid
sequenceDiagram
    participant Client as 客户端
    participant PKI as PKI 服务器
    participant Bank as Bank 服务

    Note over Client: 证书即将过期
    Client->>PKI: 检查证书状态
    PKI-->>Client: 证书将在 30 天后过期

    Note over Client: 续期流程
    Client->>Client: 生成新的密钥对<br/>(推荐)
    Client->>Client: 创建新的 CSR
    Client->>PKI: 提交续期请求<br/>(关联旧证书)

    PKI->>PKI: 验证旧证书
    PKI->>PKI: 审批续期请求
    PKI-->>Client: 返回新证书

    Client->>Bank: 使用新证书
    Bank->>Bank: 验证新证书
    Bank-->>Client: 操作成功

    Client->>PKI: 可选：吊销旧证书
```

---

## 系统架构概览

### 核心概念

**Capsula Bank** 是一个胶囊管理服务，负责：
1. 接收和管理加密数据胶囊（Capsule）
2. 支持两层数据结构：Cap0（外部存储）+ Cap1（内联元数据）
3. 使用银行系统密钥进行统一加密
4. 提供权限管理和访问控制

---

## 当前实现流程

### V2 Upload API - 完全托管模式

```mermaid
sequenceDiagram
    participant Client as 客户端
    participant API as Bank API
    participant TempFS as 临时文件系统
    participant TextExt as 文本提取器
    participant BNF as BNF 解析器
    participant Meta as 元数据生成器
    participant Storage as 存储服务
    participant Seal as 胶囊封装器
    participant DB as 数据库

    Client->>API: POST /v2/capsule/upload<br/>(multipart file)
    API->>TempFS: 保存临时文件

    par 并行处理
        TempFS->>TextExt: 提取文本内容
        TextExt-->>API: 返回纯文本
    and
        TempFS->>Meta: 生成元数据
        Meta-->>API: 返回元数据<br/>(文件名、大小、哈希)
    end

    API->>BNF: 解析 BNF 结构
    BNF-->>API: 返回结构化数据

    API->>Storage: 上传原始文件
    Storage-->>API: 返回存储 URL

    API->>Seal: 创建 Cap0 + Cap1
    Note over Seal: Cap0: 外部存储引用<br/>Cap1: 元数据 + BNF
    Seal-->>API: 返回封装的胶囊

    API->>DB: 保存胶囊记录
    DB-->>API: 确认保存

    API-->>Client: 返回 Cap0 ID + Cap1 ID
```

### 当前流程的问题

```
❌ 问题 1: 文件中转
   客户端 → Bank 服务器 → S3
   导致带宽浪费和延迟增加

❌ 问题 2: BNF 解析局限
   SimpleBnfParser 只能处理简单语法
   无法理解自然语言文档

❌ 问题 3: 扩展性差
   新增文档类型需要修改 Bank 代码
   PDF、Word 等格式需要重量级依赖

❌ 问题 4: 性能瓶颈
   所有处理都在 Bank 服务器完成
   大文件上传占用服务器资源
```

---

## 推荐架构流程

### 方案 A: 完全外部化（生产推荐）⭐

**使用极简 PKI 方案**：客户端零密码学操作，服务器托管密钥。

```mermaid
sequenceDiagram
    participant Client as 客户端
    participant PKI as PKI 服务器
    participant S3 as S3 存储
    participant LLM as LLM 服务<br/>(OpenAI/Claude)
    participant Bank as Bank API
    participant DB as 数据库

    Note over Client: 阶段 0: 申请证书（首次使用）
    Client->>PKI: POST /api/v1/certificate/generate<br/>{user_id, cert_type}
    PKI->>PKI: 生成密钥对和证书
    PKI-->>Client: 返回证书和公钥<br/>(私钥由 PKI 托管)

    Note over Client: 阶段 1: 获取所有者证书
    Client->>PKI: GET /api/v1/certificate/{cert_id}
    PKI-->>Client: 返回 X.509 证书<br/>(包含公钥)

    Note over Client: 阶段 2: 加密文件
    Client->>Client: 1. 生成临时对称密钥 (DEK)<br/>2. 用 DEK 加密文件 (AES-256-GCM)<br/>3. 用证书公钥加密 DEK (RSA)

    Note over Client: 阶段 3: 上传加密文件
    Client->>S3: 上传加密文件 + 加密的 DEK
    S3-->>Client: 返回 URL

    Note over Client: 阶段 4: LLM 处理（可选）
    Client->>Client: 1. 提取明文内容<br/>2. 发送给 LLM
    Client->>LLM: 发送文本 + 提示词<br/>"提取医疗报告结构"
    LLM-->>Client: 返回结构化数据<br/>(JSON 格式)

    Note over Client: 阶段 5: 创建胶囊
    Client->>Bank: POST /v2/capsule/create<br/>{<br/>  external_url (加密文件),<br/>  encrypted_dek,<br/>  metadata,<br/>  structured_data<br/>}

    Bank->>Bank: 1. 验证数据完整性<br/>2. 封装 Cap0 + Cap1<br/>3. 存储加密的 DEK
    Bank->>DB: 保存胶囊记录

    Bank-->>Client: 返回 Cap0 ID + Cap1 ID

    Note over Client,Bank: 解密流程（读取时）
    Client->>Bank: GET /v2/capsule/{id}
    Bank->>DB: 查询胶囊
    Bank-->>Client: 返回加密的 DEK + S3 URL

    Client->>S3: 下载加密文件
    S3-->>Client: 返回加密数据

    Client->>PKI: POST /api/v1/decrypt<br/>{encrypted_dek, owner_id, capsule_id}
    PKI->>PKI: 用托管私钥解密 DEK
    PKI-->>Client: 返回解密的 DEK

    Client->>Client: 用 DEK 解密文件
```

**方案 A 特点**：
- ✅ 使用极简 PKI 方案（服务器托管密钥）
- ✅ 客户端零密码学操作（除了文件加密）
- ✅ 端到端加密（S3 只存储密文）
- ✅ 快速集成（< 1 小时）
- ✅ 支持密钥恢复

### 方案 B: 混合模式（灵活）

```mermaid
flowchart TD
    Start[客户端请求] --> Choice{选择模式}

    Choice -->|简单场景| Upload[POST /v2/capsule/upload]
    Choice -->|生产场景| Create[POST /v2/capsule/create]

    Upload --> BankProcess[Bank 完全处理]
    BankProcess --> UploadS3[Bank 上传到 S3]
    BankProcess --> Extract[Bank 提取文本]
    BankProcess --> Parse[Bank 解析 BNF]

    Create --> ClientUpload[客户端上传到 S3]
    Create --> ClientLLM[客户端 LLM 处理]
    Create --> BankSeal[Bank 仅封装]

    UploadS3 --> Seal[创建胶囊]
    Extract --> Seal
    Parse --> Seal

    ClientUpload --> Seal
    ClientLLM --> Seal
    BankSeal --> Seal

    Seal --> Save[保存到数据库]
    Save --> End[返回结果]

    style Create fill:#90EE90
    style BankSeal fill:#90EE90
    style Upload fill:#FFD700
    style BankProcess fill:#FFD700
```

---


