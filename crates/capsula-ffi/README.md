# Capsula FFI

简单的FFI接口，用于capsula-key密码学操作。

## 功能

- **生成密钥**: 支持 Curve25519、RSA-2048、P256
- **文件导入/导出**: PEM格式私钥文件操作  
- **数字签名**: 消息签名功能

## 构建

```bash
cargo build --release -p capsula-ffi
```

生成的文件：
- 静态库: `target/release/libcapsula_ffi.a`
- 动态库: `target/release/libcapsula_ffi.dylib` 
- C头文件: `target/release/include/capsula-ffi/capsula.h`

## API 函数

### 基本操作

```c
// 生成密钥 (返回PKCS8 DER格式)
CapsulaResult* capsula_key_generate(CapsulaAlgorithm algorithm);

// 从PEM文件导入私钥 (自动检测算法)
CapsulaResult* capsula_key_import_from_file(const char* file_path);

// 导出私钥到PEM文件 (自动检测算法)
CapsulaResult* capsula_key_export_to_file(const unsigned char* private_key_der,
                                          unsigned int key_len,
                                          const char* file_path);

// 签名消息 (自动检测算法)
CapsulaResult* capsula_sign(const unsigned char* private_key_der,
                            unsigned int key_len,
                            const unsigned char* message,
                            unsigned int message_len);
```

> **为什么需要长度参数？**
> - `key_len`: DER格式是二进制数据，没有null终止符
> - `message_len`: 消息可能包含null字节，不能依赖字符串长度
> 
> 这是C语言FFI的要求，Rust需要知道数据的确切长度。

### 内存管理

```c
// 释放结果
void capsula_free_result(CapsulaResult* result);

// 释放字符串
void capsula_free_string(char* s);
```

### 工具函数

```c
// 获取版本
char* capsula_get_version(void);
```

## 支持的算法

```c
typedef enum {
    Curve25519 = 0,  // Ed25519签名
    Rsa2048 = 1,     // RSA-2048签名
    P256 = 2         // P256 ECDSA签名
} CapsulaAlgorithm;
```

## 错误处理

所有函数返回 `CapsulaResult*`：

```c
typedef struct {
    CapsulaError error_code;      // 错误码 (0=成功)
    unsigned char* data;          // 结果数据
    unsigned int data_len;        // 数据长度
    char* error_message;          // 错误信息
} CapsulaResult;
```

## 使用示例

### 极简示例 ⭐

```c
#include "capsula.h"
#include <stdio.h>

int main() {
    // 1. 生成密钥 (只需选择算法一次)
    CapsulaResult* key = capsula_key_generate(Curve25519);
    
    // 2. 签名 - 完全自动！
    const char* message = "Hello!";
    CapsulaResult* signature = capsula_sign(
        key->data, key->data_len,
        (unsigned char*)message, strlen(message));
    
    printf("签名成功! (%u 字节)\n", signature->data_len);
    
    // 3. 清理
    capsula_free_result(key);
    capsula_free_result(signature);
    
    return 0;
}
```

### 文件操作示例

```c
#include "capsula.h"
#include <stdio.h>

int main() {
    // 生成密钥
    CapsulaResult* key = capsula_key_generate(P256);
    
    // 导出到文件 (自动检测算法)
    capsula_key_export_to_file(key->data, key->data_len, "my_key.pem");
    
    // 从文件导入 (自动检测算法)
    CapsulaResult* imported_key = capsula_key_import_from_file("my_key.pem");
    
    // 签名 (自动检测算法)
    const char* message = "Hello!";
    CapsulaResult* signature = capsula_sign(
        imported_key->data, imported_key->data_len,
        (unsigned char*)message, strlen(message));
    
    // 清理
    capsula_free_result(key);
    capsula_free_result(imported_key);
    capsula_free_result(signature);
    
    return 0;
}
```

## 编译示例

```bash
gcc -o demo demo.c -I target/release/include/capsula-ffi -L target/release -lcapsula_ffi
```

## 代码结构

```
src/
├── lib.rs          # 模块声明和导出
├── types.rs        # FFI类型定义  
├── utils.rs        # 工具函数 (算法检测)
├── key_ops.rs      # 密钥生成/导入/导出
├── signing.rs      # 签名操作
└── memory.rs       # 内存管理和版本信息
```

## 注意事项

- 所有返回的 `CapsulaResult*` 必须用 `capsula_free_result()` 释放
- 私钥内部使用PKCS#8 DER格式存储
- 文件格式为PEM (PKCS#8)
- 线程安全