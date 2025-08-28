# Capsula WASM

WebAssembly bindings for Capsula key management functionality.

## 功能特性

- Ed25519 密钥对生成和管理
- SHA256/SHA512 哈希计算
- 数字签名和验证（支持扩展信息）
- PEM 格式密钥导入/导出

## 构建

### 安装依赖

```bash
# 安装 wasm-pack
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
```

### 构建 WASM 模块

```bash
# 使用构建脚本
./build.sh

# 或手动构建
wasm-pack build --target web --out-dir pkg
```

## 使用示例

### 在 HTML 中使用

```html
<script type="module">
import init, { KeyPair, sha256Hex } from './pkg/capsula_wasm.js';

async function main() {
    // 初始化 WASM
    await init();
    
    // 生成密钥对
    const keyPair = new KeyPair();
    const publicKeyPem = keyPair.exportPublicKeyPem();
    console.log('Public Key:', publicKeyPem);
    
    // 计算哈希
    const encoder = new TextEncoder();
    const data = encoder.encode('Hello, Capsula!');
    const hash = sha256Hex(data);
    console.log('SHA256:', hash);
}

main();
</script>
```

### 在 Node.js 中使用

需要使用 `--target nodejs` 构建：

```bash
wasm-pack build --target nodejs --out-dir pkg-node
```

```javascript
const { KeyPair, sha256Hex } = require('./pkg-node/capsula_wasm.js');

// 生成密钥对
const keyPair = new KeyPair();
const privateKeyPem = keyPair.exportPrivateKeyPem();
console.log('Private Key:', privateKeyPem);
```

### 在 Webpack/Vite 项目中使用

```bash
wasm-pack build --target bundler --out-dir pkg-bundler
```

```javascript
import init, { KeyPair, sha256Hex } from 'capsula-wasm';

await init();
// 使用功能...
```

## API 文档

### KeyPair

```javascript
// 生成新密钥对
const keyPair = new KeyPair();

// 导入私钥
const keyPair = KeyPair.fromPrivateKeyPem(pemString);

// 导出密钥
const privateKeyPem = keyPair.exportPrivateKeyPem();
const publicKeyPem = keyPair.exportPublicKeyPem();
const publicKeyBytes = keyPair.publicKeyBytes();

// 签名
const signature = keyPair.sign(data);
```

### PublicKey

```javascript
// 从 PEM 导入
const publicKey = PublicKey.fromPem(pemString);

// 从字节导入（32字节）
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

### 签名功能

```javascript
// 创建位置信息
const location = new Location();
location.setAddress("Beijing");
location.setLatitude(39.9042);
location.setLongitude(116.4074);

// 创建扩展签名
const signature = signWithExtendedInfo(
    keyPair,
    data,
    location,
    "Signer Name",
    "Signature Type"
);

// 验证签名
const isValid = verifySignature(data, signature);

// 签名序列化
const json = signatureToJson(signature);
const parsed = parseSignature(json);
```

## 测试示例

打开 `example.html` 文件查看完整的使用示例。

```bash
# 先构建
./build.sh

# 启动本地服务器
python3 -m http.server 8000

# 访问 http://localhost:8000/example.html
```

## 注意事项

1. WASM 需要在支持的环境中运行（现代浏览器或 Node.js）
2. 使用 `--target web` 时需要通过 HTTP(S) 服务器访问，不能直接打开文件
3. 私钥应当安全存储，不要暴露给客户端