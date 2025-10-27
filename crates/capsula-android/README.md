# Capsula Android 库

Android 平台的密钥管理和数据封装库，通过 JNI 接口提供 Rust 实现的高性能加密功能。

## 功能特性

- ✅ 密钥对生成（Ed25519、X25519、P256、RSA2048、RSA4096）
- 🔐 高性能加密实现
- 📱 Android 原生集成
- 🛡️ 类型安全的 JNI 接口

## 构建要求

### 工具链安装

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 添加 Android 目标
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android
```

### Android NDK

需要安装 Android NDK。推荐通过 Android Studio 安装，或者：

```bash
# macOS/Linux
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/25.2.9519653

# 配置环境变量
export PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH
```

## 构建步骤

### 1. 使用 cargo-ndk 构建（推荐）

```bash
# 安装 cargo-ndk
cargo install cargo-ndk

# 构建所有架构
cd crates/capsula-android
cargo ndk -t armeabi-v7a -t arm64-v8a -t x86 -t x86_64 build --release

# 输出路径：
# target/aarch64-linux-android/release/libcapsula_android.so
# target/armv7-linux-androideabi/release/libcapsula_android.so
# target/i686-linux-android/release/libcapsula_android.so
# target/x86_64-linux-android/release/libcapsula_android.so
```

### 2. 手动配置构建

创建 `.cargo/config.toml`:

```toml
[target.aarch64-linux-android]
ar = "$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android30-clang"

[target.armv7-linux-androideabi]
ar = "$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi30-clang"

[target.i686-linux-android]
ar = "$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android30-clang"

[target.x86_64-linux-android]
ar = "$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar"
linker = "$NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android30-clang"
```

然后构建：

```bash
cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target i686-linux-android --release
cargo build --target x86_64-linux-android --release
```

## Android 集成

### 1. 复制库文件到 Android 项目

```bash
# 项目结构
your-android-app/
├── app/
│   └── src/
│       └── main/
│           ├── jniLibs/
│           │   ├── arm64-v8a/
│           │   │   └── libcapsula_android.so
│           │   ├── armeabi-v7a/
│           │   │   └── libcapsula_android.so
│           │   ├── x86/
│           │   │   └── libcapsula_android.so
│           │   └── x86_64/
│           │       └── libcapsula_android.so
│           └── java/
│               └── com/
│                   └── capsula/
│                       └── android/
│                           └── KeyManager.java
```

### 2. 创建 Java 包装类

```java
package com.capsula.android;

public class KeyManager {
    static {
        System.loadLibrary("capsula_android");
    }

    /**
     * 创建密钥对
     *
     * @param algorithm 算法名称 ("Ed25519", "X25519", "P256", "RSA2048", "RSA4096")
     * @return JSON 字符串包含公钥和私钥
     */
    public static native String createKeyPair(String algorithm);

    /**
     * 获取支持的算法列表
     *
     * @return JSON 字符串包含算法列表
     */
    public static native String getSupportedAlgorithms();
}
```

### 3. Kotlin 使用示例

```kotlin
package com.capsula.android

import org.json.JSONObject

class CapsulaKeyManager {
    companion object {
        init {
            System.loadLibrary("capsula_android")
        }

        @JvmStatic
        external fun createKeyPair(algorithm: String): String

        @JvmStatic
        external fun getSupportedAlgorithms(): String
    }

    data class KeyPairResult(
        val publicKey: String,
        val privateKey: String,
        val algorithm: String
    )

    fun generateKeyPair(algorithm: String = "Ed25519"): KeyPairResult {
        val jsonStr = createKeyPair(algorithm)
        val json = JSONObject(jsonStr)

        return KeyPairResult(
            publicKey = json.getString("public_key"),
            privateKey = json.getString("private_key"),
            algorithm = json.getString("algorithm")
        )
    }

    fun listSupportedAlgorithms(): List<String> {
        val jsonStr = getSupportedAlgorithms()
        val json = JSONObject(jsonStr)
        val array = json.getJSONArray("algorithms")

        return List(array.length()) { index ->
            array.getString(index)
        }
    }
}

// 使用示例
fun example() {
    val manager = CapsulaKeyManager()

    // 生成 Ed25519 密钥对
    val keyPair = manager.generateKeyPair("Ed25519")
    println("Public Key: ${keyPair.publicKey}")
    println("Private Key: ${keyPair.privateKey}")

    // 获取支持的算法
    val algorithms = manager.listSupportedAlgorithms()
    println("Supported algorithms: $algorithms")
}
```

## API 参考

### createKeyPair

创建新的密钥对。

**参数：**
- `algorithm`: String - 算法名称（"Ed25519", "X25519", "P256", "RSA2048", "RSA4096"）

**返回：**
JSON 字符串：
```json
{
  "public_key": "base64编码的公钥",
  "private_key": "base64编码的私钥",
  "algorithm": "算法名称"
}
```

### getSupportedAlgorithms

获取支持的算法列表。

**返回：**
JSON 字符串：
```json
{
  "algorithms": [
    "Ed25519",
    "X25519",
    "P256",
    "RSA2048",
    "RSA4096"
  ]
}
```

## 支持的算法

| 算法 | 类型 | 用途 | 密钥大小 |
|------|------|------|----------|
| Ed25519 | 签名 | 数字签名 | 256 bits |
| X25519 | 密钥交换 | ECDH | 256 bits |
| P256 | 签名/加密 | ECDSA | 256 bits |
| RSA2048 | 签名/加密 | RSA | 2048 bits |
| RSA4096 | 签名/加密 | RSA | 4096 bits |

## 性能优化

1. **使用 release 模式构建**：性能提升 10-100 倍
2. **启用 LTO**：在 Cargo.toml 中配置链接时优化
3. **选择合适的算法**：Ed25519 比 RSA 快得多

## 故障排查

### UnsatisfiedLinkError

```
java.lang.UnsatisfiedLinkError: dlopen failed: library "libcapsula_android.so" not found
```

**解决方法：**
1. 确认 `.so` 文件在正确的 `jniLibs` 目录
2. 检查架构匹配（arm64-v8a vs armeabi-v7a）
3. 清理并重新构建 Android 项目

### 符号未找到

```
java.lang.UnsatisfiedLinkError: No implementation found for ...
```

**解决方法：**
1. 确认 JNI 函数名称正确（包名、类名、方法名）
2. 使用 `nm` 检查符号：`nm -D libcapsula_android.so | grep Java`

## 许可证

MIT OR Apache-2.0
