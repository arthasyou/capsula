# 贡献指南

感谢您对 Capsula 项目的关注！我们欢迎各种形式的贡献。

## 如何贡献

### 报告问题

如果您发现了 bug 或有功能建议：

1. 检查 [Issues](https://github.com/ancient/capsula/issues) 中是否已有相关问题
2. 如果没有，创建一个新的 issue，并提供：
   - 清晰的问题描述
   - 复现步骤
   - 预期行为
   - 实际行为
   - 环境信息（操作系统、Rust 版本等）

### 提交代码

1. Fork 本仓库
2. 创建您的功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m '添加某个很棒的功能'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建一个 Pull Request

### 代码规范

- 遵循 Rust 官方编码规范
- 使用 `cargo fmt` 格式化代码
- 使用 `cargo clippy` 检查代码质量
- 编写单元测试和文档测试
- 更新相关文档

### 提交信息规范

使用清晰的提交信息：

- `feat:` 新功能
- `fix:` 修复 bug
- `docs:` 文档更新
- `style:` 代码格式调整
- `refactor:` 代码重构
- `test:` 测试相关
- `chore:` 构建过程或辅助工具的变动

例如：
```
feat: 添加 RSA 密钥支持
fix: 修复证书链验证中的空指针错误
docs: 更新 PKI 模块的 API 文档
```

### 测试

- 确保所有测试通过：`cargo test`
- 为新功能添加测试
- 保持测试覆盖率

### 文档

- 为公共 API 添加文档注释
- 更新 README 如果有必要
- 提供使用示例

## 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/ancient/capsula.git
cd capsula

# 安装依赖并构建
cargo build

# 运行测试
cargo test

# 生成文档
cargo doc --open
```

## 项目结构

```
capsula/
├── crates/
│   ├── capsula-crypto/    # 加密原语
│   ├── capsula-pki/       # PKI 基础设施
│   ├── capsula-core/      # 核心功能
│   ├── capsula-api/       # API 服务
│   └── capsula-cli/       # 命令行工具
├── Cargo.toml             # Workspace 配置
└── README.md              # 项目说明
```

## 许可证

通过贡献代码，您同意您的贡献将按照本项目的 MIT 许可证进行许可。

## 问题咨询

如有任何问题，请通过以下方式联系：

- 在 GitHub 上创建 issue
- 发送邮件至项目维护者

再次感谢您的贡献！