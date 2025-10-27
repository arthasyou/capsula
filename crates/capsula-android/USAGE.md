# Capsula Android 库使用指南

## ✅ 编译完成

Android .so 库已成功编译，使用统一的 `capsula-api` 层，确保跨语言功能对齐。

## 📦 库文件

已生成以下架构的 .so 库：

```
android-libs/
├── arm64-v8a/libcapsula_android.so       (835KB)
├── armeabi-v7a/libcapsula_android.so     (664KB)
├── x86/libcapsula_android.so             (1.0MB)
└── x86_64/libcapsula_android.so          (974KB)
```

## 🚀 集成到 Android 项目

### 1. 复制 .so 库

将 `android-libs` 目录复制到您的 Android 项目：

```bash
cp -r android-libs/* <your-android-project>/src/main/jniLibs/
```

### 2. 创建 Java/Kotlin 包装类

创建 `com.capsula.android.KeyManager.java`:

```java
package com.capsula.android;

import org.json.JSONObject;

public class KeyManager {
    static {
        System.loadLibrary("capsula_android");
    }

    // 支持的算法
    public enum Algorithm {
        CURVE25519("Curve25519"),
        P256("P256"),
        RSA2048("RSA2048"),
        RSA4096("RSA4096");

        private final String value;

        Algorithm(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * 生成密钥对
     * @param algorithm 算法名称
     * @return JSON 字符串，包含 public_key, private_key, algorithm
     */
    public static native String createKeyPair(String algorithm);

    /**
     * 从 JSON 导入密钥对
     * @param json KeyPair JSON 格式
     * @return 导入结果 JSON
     */
    public static native String importKeyPair(String json);

    /**
     * 对消息进行签名
     * @param privateKeyBase64 Base64 编码的私钥
     * @param messageBase64 Base64 编码的消息
     * @return JSON 字符串，包含 signature
     */
    public static native String sign(String privateKeyBase64, String messageBase64);

    /**
     * 导出密钥对为 JSON
     * @param privateKeyBase64 Base64 编码的私钥
     * @return KeyPair JSON 格式（可跨语言传输）
     */
    public static native String exportToJson(String privateKeyBase64);

    /**
     * 获取支持的算法列表
     * @return JSON 数组
     */
    public static native String getSupportedAlgorithms();
}
```

### 3. Kotlin 版本（推荐）

创建 `KeyManager.kt`:

```kotlin
package com.capsula.android

import android.util.Base64
import org.json.JSONObject

object KeyManager {
    init {
        System.loadLibrary("capsula_android")
    }

    enum class Algorithm(val value: String) {
        CURVE25519("Curve25519"),
        P256("P256"),
        RSA2048("RSA2048"),
        RSA4096("RSA4096")
    }

    /**
     * 生成密钥对
     */
    external fun createKeyPair(algorithm: String): String

    /**
     * 从 JSON 导入密钥对
     */
    external fun importKeyPair(json: String): String

    /**
     * 对消息进行签名
     */
    external fun sign(privateKeyBase64: String, messageBase64: String): String

    /**
     * 导出密钥对为 JSON
     */
    external fun exportToJson(privateKeyBase64: String): String

    /**
     * 获取支持的算法列表
     */
    external fun getSupportedAlgorithms(): String

    // 辅助方法
    fun createKeyPair(algorithm: Algorithm): JSONObject {
        val result = createKeyPair(algorithm.value)
        return JSONObject(result)
    }

    fun signMessage(privateKeyBase64: String, message: ByteArray): ByteArray {
        val messageBase64 = Base64.encodeToString(message, Base64.NO_WRAP)
        val result = sign(privateKeyBase64, messageBase64)
        val json = JSONObject(result)
        val signatureBase64 = json.getString("signature")
        return Base64.decode(signatureBase64, Base64.NO_WRAP)
    }
}
```

## 💡 使用示例

### Kotlin 示例

```kotlin
import com.capsula.android.KeyManager
import android.util.Base64
import org.json.JSONObject

class CryptoExample {
    fun example() {
        // 1. 生成密钥对
        val keyPair = KeyManager.createKeyPair(KeyManager.Algorithm.CURVE25519)
        val publicKey = keyPair.getString("public_key")
        val privateKey = keyPair.getString("private_key")

        println("算法: ${keyPair.getString("algorithm")}")
        println("公钥: $publicKey")

        // 2. 对消息签名
        val message = "Hello, Android!".toByteArray()
        val signature = KeyManager.signMessage(privateKey, message)

        println("签名: ${Base64.encodeToString(signature, Base64.NO_WRAP)}")

        // 3. 导出为 JSON（跨语言传输）
        val json = KeyManager.exportToJson(privateKey)
        println("JSON 导出: $json")

        // 4. 从 JSON 导入
        val imported = KeyManager.importKeyPair(json)
        println("导入结果: $imported")

        // 5. 查看支持的算法
        val algorithms = KeyManager.getSupportedAlgorithms()
        println("支持的算法: $algorithms")
    }
}
```

### Java 示例

```java
import com.capsula.android.KeyManager;
import android.util.Base64;
import org.json.JSONObject;

public class CryptoExample {
    public void example() throws Exception {
        // 1. 生成密钥对
        String keyPairJson = KeyManager.createKeyPair(
            KeyManager.Algorithm.CURVE25519.getValue()
        );
        JSONObject keyPair = new JSONObject(keyPairJson);

        String publicKey = keyPair.getString("public_key");
        String privateKey = keyPair.getString("private_key");

        System.out.println("算法: " + keyPair.getString("algorithm"));
        System.out.println("公钥: " + publicKey);

        // 2. 对消息签名
        byte[] message = "Hello, Android!".getBytes();
        String messageBase64 = Base64.encodeToString(message, Base64.NO_WRAP);

        String signatureJson = KeyManager.sign(privateKey, messageBase64);
        JSONObject signResult = new JSONObject(signatureJson);
        String signature = signResult.getString("signature");

        System.out.println("签名: " + signature);

        // 3. 导出为 JSON
        String json = KeyManager.exportToJson(privateKey);
        System.out.println("JSON 导出: " + json);
    }
}
```

## 🔐 功能特性

### 1. 密钥生成
- ✅ Curve25519 (Ed25519 签名 + X25519 密钥交换)
- ✅ P256 (NIST secp256r1)
- ✅ RSA 2048-bit
- ✅ RSA 4096-bit

### 2. 数字签名
- ✅ 自动算法检测
- ✅ Ed25519 签名（64 字节）
- ✅ ECDSA P-256 签名
- ✅ RSA-PSS 签名

### 3. 跨语言互操作
- ✅ JSON 序列化/反序列化
- ✅ Base64 编码
- ✅ 标准 PKCS#8/SPKI 格式
- ✅ 与 Python、Java、JavaScript 等语言兼容

## 📝 API 参考

### createKeyPair(algorithm: String)
生成新的密钥对。

**参数**：
- `algorithm`: "Curve25519" | "P256" | "RSA2048" | "RSA4096"

**返回**：
```json
{
  "public_key": "base64编码的公钥",
  "private_key": "base64编码的私钥",
  "algorithm": "算法名称",
  "format": "SPKI/PKCS8"
}
```

### sign(privateKeyBase64: String, messageBase64: String)
使用私钥对消息进行签名。

**参数**：
- `privateKeyBase64`: Base64 编码的私钥 (PKCS#8 DER)
- `messageBase64`: Base64 编码的消息

**返回**：
```json
{
  "signature": "base64编码的签名"
}
```

### exportToJson(privateKeyBase64: String)
导出密钥对为标准 JSON 格式（可跨语言传输）。

**返回**：
```json
{
  "algorithm": "Curve25519",
  "private_key": "base64编码的私钥",
  "public_key": "base64编码的公钥"
}
```

### importKeyPair(json: String)
从 JSON 导入密钥对。

**参数**：
- `json`: KeyPair JSON 格式

## 🔧 重新编译

如需重新编译，运行：

```bash
cd crates/capsula-android

# Debug 版本
./build.sh debug --copy

# Release 版本（推荐）
./build.sh release --copy
```

## 📱 Gradle 配置

在 `app/build.gradle` 中添加：

```gradle
android {
    // ...

    defaultConfig {
        // ...
        ndk {
            abiFilters 'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'
        }
    }

    sourceSets {
        main {
            jniLibs.srcDirs = ['src/main/jniLibs']
        }
    }
}
```

## ✅ 测试

库已通过以下测试：
- ✅ Curve25519 密钥生成和签名
- ✅ P256 密钥生成和签名
- ✅ RSA 密钥生成和签名
- ✅ JSON 序列化/反序列化
- ✅ 跨语言互操作性

## 🎉 完成

您现在可以在 Android 项目中使用 Capsula 加密库，享受与其他语言（Python、Java、JavaScript）的完全互操作性！
