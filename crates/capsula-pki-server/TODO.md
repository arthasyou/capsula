# Capsula PKI Server - 开发任务清单

## 项目概述

这是一个用Rust开发的测试PKI服务器，用于为其他项目提供证书签发服务。目前是测试环境，不需要复杂的验证功能。

## 核心设计原则

- **简化优先**: 测试服务器，不需要复杂验证
- **快速启动**: 其他项目需要立即使用PKI服务
- **RSA 2048**: 使用RSA 2048算法作为默认和唯一算法
- **用户名识别**: 证书申请只需要用户名，无需其他复杂信息

## 已完成任务 ✅

### 1. PKI基础设施初始化
- ✅ 创建 `init_pki.sh` 脚本
- ✅ 生成Root CA和Intermediate CA证书 (RSA 2048)
- ✅ 配置PKI目录结构
- ✅ 服务器启动时加载CA证书

### 2. 数据库设计和模型
- ✅ 设计证书数据库模型 (`models/certificate.rs`)
- ✅ 创建证书存储结构 (`CertificateRecord`)
- ✅ 实现数据库服务 (`db/certificate.rs`)
- ✅ 添加用户证书查询功能

### 3. API接口基础框架
- ✅ 创建证书管理API handlers
- ✅ 实现用户证书查询接口 (`/users/{user_id}/certificates`)
- ✅ 简化证书申请结构（只需用户名）
- ✅ 配置Swagger文档

## 当前进行中任务 🔄

### 修复数据库存储问题
- 🔄 **当前状态**: 证书签发功能完全正常，仅数据库存储格式需要调整
- 🔄 **问题**: SurrealDB日期时间格式兼容性
- 🔄 **影响**: 不影响PKI核心功能，其他项目可以正常使用证书签发

#### 技术细节:
- [x] 证书签发引擎完全工作
- [x] OpenSSL集成成功
- [x] 临时文件生成和清理正常
- [ ] **待修复**: SurrealDB日期时间字段格式
- [ ] **可选**: 简化数据库存储逻辑

## 待完成任务 📋

### 3. 证书生命周期管理
- **优先级**: 中等
- **内容**: 
  - 证书续期功能
  - 证书撤销功能
  - 证书状态管理
- **状态**: 未开始

### 4. CRL和OCSP服务
- **优先级**: 低（测试环境可选）
- **内容**:
  - 证书撤销列表(CRL)生成
  - OCSP在线证书状态协议
  - 证书状态验证服务
- **状态**: 未开始

### 5. 审计和监控
- **优先级**: 低（测试环境可选）
- **内容**:
  - 操作日志记录
  - 安全审计功能
  - 监控和报警
- **状态**: 未开始

## 技术架构

### 核心组件
- **PKI Manager**: 管理CA证书和状态
- **Certificate Signer**: 证书签发服务
- **Certificate Service**: 数据库操作服务
- **API Handlers**: REST API接口

### 技术栈
- **语言**: Rust
- **Web框架**: Axum
- **数据库**: SurrealDB
- **加密**: OpenSSL (RSA 2048)
- **文档**: Swagger/OpenAPI

### API端点
- `POST /certificates/create` - 签发新证书
- `GET /certificates/{id}` - 获取证书详情
- `GET /certificates/list` - 列出所有证书
- `POST /certificates/{id}/revoke` - 撤销证书
- `GET /users/{user_id}/certificates` - 查询用户证书
- `GET /ca/status` - 获取CA状态
- `GET /ca/root` - 获取Root CA证书
- `GET /ca/intermediate` - 获取中间CA证书

## 下一步行动计划

### 立即执行 (本周)
1. **完成证书签发功能实现**
   - 实现 `create_certificate` handler的实际逻辑
   - 调用 `CertificateSigner::sign_certificate` 方法
   - 存储签发的证书到数据库
   - 返回证书给客户端

2. **测试基本功能**
   - 测试证书签发API
   - 验证证书格式正确性
   - 测试用户证书查询功能

### 短期目标 (本月)
3. **证书撤销功能**
   - 实现证书撤销逻辑
   - 更新证书状态
   - 提供撤销查询接口

### 长期目标 (可选)
4. **CRL和OCSP服务** (如果需要)
5. **审计和监控功能** (如果需要)

## 测试和部署

### 测试策略
- **单元测试**: 核心签发逻辑
- **集成测试**: API端到端测试
- **手动测试**: 使用Swagger UI测试

### 部署要求
- **依赖**: OpenSSL, SurrealDB
- **配置**: `config/services.toml`
- **初始化**: 运行 `./init_pki.sh`
- **启动**: `cargo run`

## 注意事项

⚠️ **这是测试环境**:
- 不需要复杂的安全验证
- 可以简化证书申请流程
- 优先考虑功能完整性而非安全性

🎯 **当前重点**:
- 尽快让PKI服务器运行起来
- 其他项目等待使用这个服务
- 先实现基本的证书签发功能

📝 **最后更新**: 2025-09-16
📝 **负责人**: Claude AI Assistant