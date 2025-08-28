#!/bin/bash

# Capsula WASM 前端打包脚本

set -e

echo "=== Capsula WASM 前端打包 ==="

# 检查是否已经构建
if [ ! -d "pkg" ]; then
    echo "未找到 pkg 目录，正在构建..."
    wasm-pack build --target web --out-dir pkg --no-opt
fi

# 创建发布目录
DIST_DIR="capsula-wasm-frontend"
rm -rf $DIST_DIR
mkdir -p $DIST_DIR

# 复制必需文件
echo "复制核心文件..."
cp pkg/capsula_wasm.js $DIST_DIR/
cp pkg/capsula_wasm_bg.wasm $DIST_DIR/
cp pkg/capsula_wasm.d.ts $DIST_DIR/
cp pkg/package.json $DIST_DIR/

# 复制文档
echo "复制文档..."
cp README.md $DIST_DIR/
cp example.html $DIST_DIR/

# 创建简化的集成示例
cat > $DIST_DIR/quick-start.html << 'EOF'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>Capsula WASM 快速开始</title>
</head>
<body>
    <h1>Capsula WASM 快速开始</h1>
    <button id="generateKey">生成密钥对</button>
    <button id="testHash">测试哈希</button>
    <pre id="output"></pre>

    <script type="module">
        import init, { KeyPair, sha256Hex, version } from './capsula_wasm.js';
        
        const output = document.getElementById('output');
        
        async function setup() {
            await init();
            output.textContent = `Capsula WASM ${version()} 已加载\n`;
        }
        
        document.getElementById('generateKey').onclick = () => {
            try {
                const keyPair = new KeyPair();
                const publicKey = keyPair.exportPublicKeyPem();
                output.textContent += `\n生成的公钥:\n${publicKey}\n`;
            } catch (e) {
                output.textContent += `\n错误: ${e}\n`;
            }
        };
        
        document.getElementById('testHash').onclick = () => {
            const encoder = new TextEncoder();
            const data = encoder.encode('Hello, Capsula!');
            const hash = sha256Hex(data);
            output.textContent += `\nSHA256('Hello, Capsula!') = ${hash}\n`;
        };
        
        setup();
    </script>
</body>
</html>
EOF

# 创建 package.json（如果需要发布到 NPM）
cat > $DIST_DIR/package.json << EOF
{
  "name": "@capsula/wasm",
  "version": "0.1.0",
  "description": "Capsula WASM bindings for key management",
  "main": "capsula_wasm.js",
  "types": "capsula_wasm.d.ts",
  "files": [
    "capsula_wasm.js",
    "capsula_wasm_bg.wasm",
    "capsula_wasm.d.ts",
    "README.md"
  ],
  "keywords": ["capsula", "wasm", "cryptography", "ed25519"],
  "license": "MIT OR Apache-2.0",
  "repository": {
    "type": "git",
    "url": "https://github.com/ancient/capsula"
  }
}
EOF

# 创建使用说明
cat > $DIST_DIR/前端集成说明.md << 'EOF'
# Capsula WASM 前端集成说明

## 文件说明
- `capsula_wasm.js` - JavaScript 接口文件
- `capsula_wasm_bg.wasm` - WebAssembly 二进制文件
- `capsula_wasm.d.ts` - TypeScript 类型定义
- `quick-start.html` - 快速开始示例
- `example.html` - 完整功能示例

## 集成步骤

### 1. 将文件复制到项目
将 `capsula_wasm.js` 和 `capsula_wasm_bg.wasm` 复制到您的项目静态资源目录。

### 2. 在 HTML 中使用
```javascript
import init, { KeyPair, sha256Hex } from './path/to/capsula_wasm.js';

// 初始化 WASM
await init();

// 使用功能
const keyPair = new KeyPair();
```

### 3. 在构建工具中使用（Webpack/Vite）
```javascript
// 安装依赖
npm install @capsula/wasm

// 使用
import init, { KeyPair } from '@capsula/wasm';
```

## 注意事项
1. 必须通过 HTTP(S) 服务器访问，不能直接打开 HTML 文件
2. 确保服务器正确设置 WASM 文件的 MIME 类型为 `application/wasm`
3. 初始化是异步的，使用前必须等待 `init()` 完成
EOF

# 创建压缩包
VERSION="0.1.0"
ZIP_NAME="capsula-wasm-frontend-v${VERSION}.zip"
echo "创建压缩包..."
zip -r $ZIP_NAME $DIST_DIR

echo "✅ 打包完成！"
echo "📦 发布包: $ZIP_NAME"
echo "📁 目录: $DIST_DIR/"
echo ""
echo "前端开发者可以："
echo "1. 解压 $ZIP_NAME"
echo "2. 将文件复制到项目中"
echo "3. 参考 quick-start.html 快速开始"