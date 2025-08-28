#!/bin/bash

# 安装 wasm-pack（如果未安装）
if ! command -v wasm-pack &> /dev/null; then
    echo "Installing wasm-pack..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# 构建 WASM 模块
echo "Building WASM module..."
wasm-pack build --target web --out-dir pkg

echo "Build complete! Output in pkg/"