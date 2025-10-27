# Capsula Android Native Libraries

## 📦 包含的架构

这个目录包含了为所有主要 Android 架构编译的 Capsula 原生库：

```
android-libs/
├── arm64-v8a/libcapsula_android.so       # ARM 64-bit (现代手机)
├── armeabi-v7a/libcapsula_android.so     # ARM 32-bit (旧手机)
├── x86/libcapsula_android.so             # x86 32-bit (模拟器)
└── x86_64/libcapsula_android.so          # x86 64-bit (模拟器)
```

## 🚀 使用方法

### 1. 复制到 Android 项目

```bash
cp -r * <your-android-project>/src/main/jniLibs/
```

复制后的目录结构：
```
<your-android-project>/
└── src/
    └── main/
        └── jniLibs/
            ├── arm64-v8a/
            │   └── libcapsula_android.so
            ├── armeabi-v7a/
            │   └── libcapsula_android.so
            ├── x86/
            │   └── libcapsula_android.so
            └── x86_64/
                └── libcapsula_android.so
```

### 2. 在 Kotlin/Java 中加载

```kotlin
object KeyManager {
    init {
        System.loadLibrary("capsula_android")
    }

    external fun createKeyPair(algorithm: String): String
    external fun sign(privateKeyBase64: String, messageBase64: String): String
    // ... 其他方法
}
```

## 🔐 功能

- ✅ 密钥生成 (Curve25519, P256, RSA)
- ✅ 数字签名
- ✅ JSON 序列化/反序列化
- ✅ 跨语言互操作

## 📚 详细文档

请查看 `../USAGE.md` 获取完整的使用指南和示例代码。

## 🔧 重新编译

如需重新编译这些库：

```bash
cd ..
./build.sh release --copy
```

## ⚙️ 版本信息

- **编译时间**: 2025-10-27
- **使用 API**: capsula-api (统一 API 层)
- **编译模式**: Release (优化)
- **NDK 版本**: 29.0.14206865
