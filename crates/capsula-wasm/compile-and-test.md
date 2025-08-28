# Capsula WASM 编译和测试指南

## 1. 编译 WASM 模块

### 安装 wasm-pack（如果未安装）
```bash
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

### 编译选项

#### 选项 A: 使用构建脚本（推荐）
```bash
cd /Users/ancient/src/rust/capsula/crates/capsula-wasm
chmod +x build.sh
./build.sh
```

#### 选项 B: 手动编译
```bash
cd /Users/ancient/src/rust/capsula/crates/capsula-wasm

# 为 Web 浏览器编译
wasm-pack build --target web --out-dir pkg --no-opt

# 为 Node.js 编译
wasm-pack build --target nodejs --out-dir pkg-node --no-opt

# 为 Webpack/bundler 编译
wasm-pack build --target bundler --out-dir pkg-bundler --no-opt
```

## 2. 测试方法

### 方法 1: 使用示例 HTML 文件

1. 启动本地 HTTP 服务器：
```bash
cd /Users/ancient/src/rust/capsula/crates/capsula-wasm
python3 -m http.server 8000
```

2. 在浏览器中打开：
- 简单测试：http://localhost:8000/test.html
- 完整示例：http://localhost:8000/example.html

### 方法 2: 使用 Node.js 测试

1. 先为 Node.js 编译：
```bash
wasm-pack build --target nodejs --out-dir pkg-node --no-opt
```

2. 创建测试脚本 `test-node.js`：
```javascript
const { KeyPair, sha256Hex } = require('./pkg-node/capsula_wasm.js');

// 生成密钥对
const keyPair = new KeyPair();
console.log('Private Key:', keyPair.exportPrivateKeyPem());

// 计算哈希
const encoder = new TextEncoder();
const data = encoder.encode('Hello, Capsula!');
const hash = sha256Hex(data);
console.log('SHA256:', hash);
```

3. 运行测试：
```bash
node test-node.js
```

### 方法 3: 使用 wasm-pack 测试

```bash
cd /Users/ancient/src/rust/capsula/crates/capsula-wasm
wasm-pack test --chrome --headless
```

## 3. 验证编译结果

编译成功后，pkg 目录应包含以下文件：
- `capsula_wasm.js` - JavaScript 接口
- `capsula_wasm_bg.wasm` - WASM 二进制文件
- `capsula_wasm.d.ts` - TypeScript 定义
- `package.json` - npm 包配置

## 4. 常见问题

### 问题：wasm-opt 下载失败
解决：使用 `--no-opt` 标志禁用优化

### 问题：CORS 错误
解决：必须通过 HTTP 服务器访问，不能直接打开文件

### 问题：Module not found
解决：确保路径正确，使用相对路径 `./pkg/`