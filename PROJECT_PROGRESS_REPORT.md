# 项目工作进展汇报

## 1. 总体概况

- 已完成“Capsula”工作区的核心组件搭建，包括密码学库、密钥管理、PKI 服务、数据胶囊引擎、跨平台接口等多个 crate。
- 通过 `capsula-key`、`capsula-crypto`、`capsula-core` 等库，已经具备数据胶囊封装、签名、解密的底层能力。
- `capsula-api` 提供标准化的 PKI REST 服务，`capsula-cli`、`capsula-wasm`、`capsula-ffi` 支持命令行、前端和原生系统接入。
- `capsula-bank` 引入上述能力，构建面向数据银行场景的 Axum 服务端，目前处于功能串接与场景落地阶段。

## 2. 各子模块进展

| 模块                 | 功能说明                                                                     | 主要成果                                     | 当前状态                             |
| -------------------- | ---------------------------------------------------------------------------- | -------------------------------------------- | ------------------------------------ |
| `capsula-crypto`     | 提供加密与签名算法基础能力，包括多种非对称/对称算法（RSA、Ed25519、P256 等） | 实现多算法签名与哈希功能，可作为系统底层依赖 | 功能已实现，稳定可用                 |
| `capsula-key`        | 管理密钥的生成、加密存储、导出与轮换，是安全体系的核心支撑                   | 实现多算法密钥管理与安全存储机制             | 功能稳定，为 PKI 与胶囊服务提供支撑  |
| `capsula-core`       | 提供数据胶囊的封装、解封装与验证机制，定义胶囊的分层结构与策略体系           | 完成 Cap0/Cap1/Cap2 结构与策略框架实现       | 可用状态，正与业务服务融合           |
| `capsula-pki`        | 负责数字证书的签发、验证、吊销与证书链管理，构建信任基础设施                 | 构建完整 CA 体系与证书管理流程               | 功能完善，待与数据银行联动           |
| `capsula-api`        | 向外提供统一 REST 接口，支撑证书与密钥等功能的服务化调用                     | 已实现 PKI API 并集成 Swagger 文档           | 可独立部署，支撑外部系统接入         |
| `capsula-cli`        | 提供命令行工具，用于运维、批量操作与离线任务                                 | 实现密钥与证书操作命令                       | 已可用于日常管理与测试               |
| `capsula-wasm`       | 支持在浏览器和 Node.js 环境中使用加密与封装功能                              | 实现 Web 端数据加密与验证接口                | 功能可用，用于前端集成               |
| `capsula-ffi`        | 为 C/C++ 等语言提供接口封装，便于跨语言调用                                  | 实现基础 FFI 接口封装                        | 已具备基本跨语言调用能力             |
| `capsula-bank`       | 面向“数据银行”场景的服务端，整合胶囊管理、授权、审计等功能                   | 实现胶囊 CRUD、令牌管理、流水线封装等        | 与底层库集成中，部分流程待完善       |
| `capsula-pki-server` | 提供 PKI 服务端功能，负责证书签发、验证、吊销与审计接口                      | 已完成证书签发与吊销 API，支持多算法证书生成 | 已可单独运行，与 capsula-bank 联调中 |

## 3. `capsula-bank` 集成进展

- **胶囊管理 V1**：完成 SurrealDB 表结构，支持胶囊创建、按 ID/Owner 查询、组合检索。
- **权限/令牌**：实现令牌生成、验证、撤销及查询流程，内置原子/分子权限矩阵，提供初始化脚本。
- **V2 流水线**：封装服务对接文本提取、BNF 解析、元数据生成、存储写入与 Cap1 创建；Cap0 仍为 TODO。
- **多级视图**：提供 Level0 直接投影与 Level1 LLM 汇总接口，对应 PPT 中的披露等级需求。
- **配置与基础设施**：加载系统私钥、初始化日志、集成 Swagger UI、准备临时文件守卫与本地存储实现。

## 4. 当前存在的主要差距

1. **Cap0 封装与外部存储**：`CapsuleSealer::create_cap0` 尚未实现，仍缺少完整的原始数据加密与引用写入逻辑。
2. **真实存储/预签名 URL**：当前仅提供本地存储与占位预签名 URL，需要接入 S3/MinIO 并完善上传校验。
3. **PKI/证书流程**：`capsula-bank` 尚未与 `capsula-pki` 的证书申请、吊销、审计流程联动。
4. **权限闭环**：胶囊访问接口未全面接入原子/分子权限校验，需结合 token scopes 做细粒度控制。
5. **文本/格式支持**：V2 流程文本提取仅支持文本类型，尚未处理 PDF、影像或 OCR 场景。
6. **文档与自动化**：集成流程缺少系统级文档与自动化测试，需补充部署指南、E2E 测试用例。

## 5. 后续重点计划

1. 完成 Cap0 封装与存储落盘，打通全链路胶囊生成与持久化。
2. 接入对象存储与真实预签名 URL，完善上传流程的配置校验与安全性。
3. 将 PKI 证书生命周期服务整合进 `capsula-bank`，支撑极简/标准两种证书申请模式。
4. 在胶囊访问 API 中引入原子/分子权限判定，形成“授权-使用-审计”的监管闭环。
5. 拓展文本解析与结构化抽取能力，覆盖医疗报告常见格式。
6. 完善文档体系（运行手册、架构图、场景示例）与自动化测试，支撑对外汇报与上线准备。

## 6. 使用示例

### `capsula-cli`

1. 生成一对 ed25519 密钥到 `temp/` 目录：

```bash
cargo run -p capsula-cli -- generate --name demo --output temp
```

2. 使用生成的私钥为本地文件创建签名：

```bash
cargo run -p capsula-cli -- sign --file README.md --key temp/demo.key --output temp/demo.sig
```

### `capsula-pki-server`

1. 准备配置并启动 PKI 服务端：

```bash
cd crates/capsula-pki-server
cp config/services-example.toml config/services.toml
cargo run
```

2. 通过健康检查确认服务正常：

```bash
curl http://127.0.0.1:16021/health
```

### `capsula-bank`

1. 使用仓库内默认配置启动数据银行服务：

```bash
cd crates/capsula-bank
cargo run
```

2. 浏览 Swagger UI 或获取 OpenAPI 描述：

```bash
open http://127.0.0.1:16022/swagger-ui    # macOS 可用 open；其他平台可使用 xdg-open
curl http://127.0.0.1:16022/api-docs/openapi.json | jq '.info.title'
```
