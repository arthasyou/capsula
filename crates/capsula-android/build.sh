#!/bin/bash
# Android 库构建脚本

set -e

echo "🔨 Building Capsula Android Library"

# 检查环境
if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "❌ Error: ANDROID_NDK_HOME is not set"
    echo "Please set ANDROID_NDK_HOME to your Android NDK installation path"
    echo "Example: export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/25.2.9519653"
    exit 1
fi

echo "✅ ANDROID_NDK_HOME: $ANDROID_NDK_HOME"

# 检查 cargo-ndk
if ! command -v cargo-ndk &> /dev/null; then
    echo "⚠️  cargo-ndk not found. Installing..."
    cargo install cargo-ndk
fi

# 检查目标是否已安装
TARGETS=(
    "aarch64-linux-android"
    "armv7-linux-androideabi"
    "i686-linux-android"
    "x86_64-linux-android"
)

for target in "${TARGETS[@]}"; do
    if ! rustup target list | grep -q "$target (installed)"; then
        echo "📦 Installing target: $target"
        rustup target add "$target"
    fi
done

# 构建参数
BUILD_MODE="${1:-release}"
BUILD_FLAGS=""

if [ "$BUILD_MODE" = "release" ]; then
    BUILD_FLAGS="--release"
    echo "🚀 Building in RELEASE mode"
else
    echo "🔧 Building in DEBUG mode"
fi

# 构建所有架构
echo "🏗️  Building for all Android architectures..."
cargo ndk \
    -t armeabi-v7a \
    -t arm64-v8a \
    -t x86 \
    -t x86_64 \
    build $BUILD_FLAGS

echo ""
echo "✅ Build complete!"
echo ""
echo "📦 Library files:"

# 显示构建产物
if [ "$BUILD_MODE" = "release" ]; then
    BUILD_DIR="release"
else
    BUILD_DIR="debug"
fi

echo "  arm64-v8a:    ../../target/aarch64-linux-android/$BUILD_DIR/libcapsula_android.so"
echo "  armeabi-v7a:  ../../target/armv7-linux-androideabi/$BUILD_DIR/libcapsula_android.so"
echo "  x86:          ../../target/i686-linux-android/$BUILD_DIR/libcapsula_android.so"
echo "  x86_64:       ../../target/x86_64-linux-android/$BUILD_DIR/libcapsula_android.so"

# 可选：复制到输出目录
OUTPUT_DIR="./android-libs"
if [ "$2" = "--copy" ]; then
    echo ""
    echo "📋 Copying libraries to $OUTPUT_DIR..."

    mkdir -p "$OUTPUT_DIR/arm64-v8a"
    mkdir -p "$OUTPUT_DIR/armeabi-v7a"
    mkdir -p "$OUTPUT_DIR/x86"
    mkdir -p "$OUTPUT_DIR/x86_64"

    cp "../../target/aarch64-linux-android/$BUILD_DIR/libcapsula_android.so" "$OUTPUT_DIR/arm64-v8a/"
    cp "../../target/armv7-linux-androideabi/$BUILD_DIR/libcapsula_android.so" "$OUTPUT_DIR/armeabi-v7a/"
    cp "../../target/i686-linux-android/$BUILD_DIR/libcapsula_android.so" "$OUTPUT_DIR/x86/"
    cp "../../target/x86_64-linux-android/$BUILD_DIR/libcapsula_android.so" "$OUTPUT_DIR/x86_64/"

    echo "✅ Libraries copied to $OUTPUT_DIR"
    echo ""
    echo "You can now copy the $OUTPUT_DIR directory to your Android project's src/main/jniLibs/"
fi

echo ""
echo "🎉 Done!"
