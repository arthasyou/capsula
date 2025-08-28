# Capsula WASM 前端发布清单

## 必需文件（从 pkg 目录）

### 1. 核心文件
```
pkg/
├── capsula_wasm.js         # JavaScript 接口文件
├── capsula_wasm_bg.wasm    # WASM 二进制文件
├── capsula_wasm.d.ts       # TypeScript 类型定义（可选，但推荐）
└── package.json            # NPM 包配置文件
```

### 2. 文档和示例
```
├── README.md               # 使用说明
├── example.html            # 完整功能示例
└── USAGE.md               # API 文档
```

## 发布方式

### 方案 A：NPM 包（推荐）

1. 发布到 NPM：
```bash
cd pkg
npm publish --access public
```

2. 前端使用：
```bash
npm install capsula-wasm
```

```javascript
import init, { KeyPair, sha256Hex } from 'capsula-wasm';

await init();
// 使用功能...
```

### 方案 B：直接文件分发

创建一个压缩包：
```bash
cd /Users/ancient/src/rust/capsula/crates/capsula-wasm
mkdir capsula-wasm-dist
cp -r pkg/* capsula-wasm-dist/
cp README.md example.html USAGE.md capsula-wasm-dist/
zip -r capsula-wasm-v0.1.0.zip capsula-wasm-dist/
```

### 方案 C：CDN 托管

将文件上传到 CDN，前端直接引用：
```html
<script type="module">
import init, { KeyPair } from 'https://your-cdn.com/capsula-wasm/capsula_wasm.js';

async function main() {
    await init('https://your-cdn.com/capsula-wasm/capsula_wasm_bg.wasm');
    // 使用功能...
}
</script>
```

## 集成指南（提供给前端）

### 1. 原生 JavaScript
```html
<!DOCTYPE html>
<html>
<head>
    <script type="module">
        import init, { KeyPair, sha256Hex } from './capsula_wasm.js';
        
        async function setupCapsula() {
            await init();
            
            // 生成密钥对
            const keyPair = new KeyPair();
            console.log(keyPair.exportPublicKeyPem());
            
            // 计算哈希
            const encoder = new TextEncoder();
            const hash = sha256Hex(encoder.encode('Hello'));
            console.log(hash);
        }
        
        setupCapsula();
    </script>
</head>
</html>
```

### 2. React 项目
```jsx
import { useEffect, useState } from 'react';
import init, { KeyPair, sha256Hex } from 'capsula-wasm';

function App() {
    const [wasm, setWasm] = useState(false);
    
    useEffect(() => {
        init().then(() => setWasm(true));
    }, []);
    
    const generateKey = () => {
        if (!wasm) return;
        const keyPair = new KeyPair();
        console.log(keyPair.exportPublicKeyPem());
    };
    
    return <button onClick={generateKey}>生成密钥</button>;
}
```

### 3. Vue 项目
```vue
<template>
  <button @click="generateKey">生成密钥</button>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import init, { KeyPair } from 'capsula-wasm';

const wasmReady = ref(false);

onMounted(async () => {
    await init();
    wasmReady.value = true;
});

const generateKey = () => {
    if (!wasmReady.value) return;
    const keyPair = new KeyPair();
    console.log(keyPair.exportPublicKeyPem());
};
</script>
```

### 4. TypeScript 支持
```typescript
import init, { KeyPair, PublicKey } from 'capsula-wasm';

async function main() {
    await init();
    
    const keyPair: KeyPair = new KeyPair();
    const pem: string = keyPair.exportPublicKeyPem();
    const publicKey: PublicKey = PublicKey.fromPem(pem);
}
```

## 注意事项

1. **CORS 配置**：WASM 文件需要正确的 MIME 类型 `application/wasm`
2. **文件路径**：确保 `.wasm` 文件与 `.js` 文件在同一目录或指定正确路径
3. **异步初始化**：必须等待 `init()` 完成后才能使用其他功能
4. **浏览器支持**：需要支持 WebAssembly 的现代浏览器

## 最小发布包

如果只需要最基本的功能，至少需要：
- `capsula_wasm.js`
- `capsula_wasm_bg.wasm`
- 简单的使用说明