# Capsula WASM 使用指南

## 快速开始

### 1. 编译 WASM 模块
```bash
# 使用构建脚本
./build.sh

# 或手动编译
wasm-pack build --target web --out-dir pkg --no-opt
```

### 2. 在浏览器中使用

```html
<!DOCTYPE html>
<html>
<head>
    <script type="module">
        import init, { KeyPair, sha256Hex } from './pkg/capsula_wasm.js';
        
        async function main() {
            await init();
            
            // 生成密钥对
            const keyPair = new KeyPair();
            console.log('公钥:', keyPair.exportPublicKeyPem());
            
            // 计算哈希
            const encoder = new TextEncoder();
            const data = encoder.encode('Hello!');
            console.log('SHA256:', sha256Hex(data));
        }
        
        main();
    </script>
</head>
</html>
```

### 3. 在 Node.js 中使用

```bash
# 为 Node.js 编译
wasm-pack build --target nodejs --out-dir pkg-node --no-opt

# 使用
node test-node.js
```

## 主要功能

### 密钥管理
- 生成 Ed25519 密钥对
- PEM 格式导入/导出
- 获取原始公钥字节

### 哈希计算
- SHA256 和 SHA512
- 返回字节数组或十六进制字符串

### 数字签名
- Ed25519 签名
- 签名验证
- 支持扩展信息（位置、时间戳等）

## API 参考

### KeyPair 类
```javascript
// 生成新密钥对
const keyPair = new KeyPair();

// 从 PEM 导入
const keyPair = KeyPair.fromPrivateKeyPem(pemString);

// 导出密钥
const privateKeyPem = keyPair.exportPrivateKeyPem();
const publicKeyPem = keyPair.exportPublicKeyPem();
const publicKeyBytes = keyPair.publicKeyBytes();

// 签名数据
const signature = keyPair.sign(data);
```

### PublicKey 类
```javascript
// 从 PEM 导入
const publicKey = PublicKey.fromPem(pemString);

// 从字节导入
const publicKey = PublicKey.fromBytes(bytes);

// 导出
const pem = publicKey.toPem();
const bytes = publicKey.toBytes();

// 验证签名
const isValid = publicKey.verify(message, signature);
```

### 哈希函数
```javascript
// SHA256
const hashBytes = sha256(data);
const hashHex = sha256Hex(data);

// SHA512
const hashBytes = sha512(data);
const hashHex = sha512Hex(data);

// 验证哈希
const isValid = verifyHash(data, hashBytes, "sha256");
```

## 测试方法

1. **浏览器测试**
   ```bash
   python3 -m http.server 8000
   # 打开 http://localhost:8000/example.html
   ```

2. **Node.js 测试**
   ```bash
   node test-node.js
   ```

3. **单元测试**
   ```bash
   wasm-pack test --chrome --headless
   ```

## 常见问题

**Q: 为什么不能直接打开 HTML 文件？**
A: WASM 需要通过 HTTP(S) 协议加载，使用本地服务器即可。

**Q: 如何在 TypeScript 中使用？**
A: pkg 目录包含 .d.ts 类型定义文件，可直接导入使用。

**Q: 支持哪些平台？**
A: 支持所有现代浏览器和 Node.js 12+。

**Q: 性能如何？**
A: WASM 性能接近原生代码，适合密码学运算。