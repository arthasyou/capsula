/*
 * 简单的capsula-ffi使用示例
 * 
 * 编译:
 * gcc -o simple_demo examples/simple_demo.c -I target/release/include/capsula-ffi -L target/release -lcapsula_ffi
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capsula.h"

void print_hex(const unsigned char* data, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("=== Capsula FFI 简单示例 ===\n\n");
    
    // 1. 生成 Curve25519 密钥
    printf("1. 生成 Curve25519 密钥...\n");
    CapsulaResult* key_result = capsula_key_generate(Curve25519);
    if (key_result->error_code != Success) {
        printf("   错误: %s\n", key_result->error_message);
        capsula_free_result(key_result);
        return 1;
    }
    printf("   ✓ 成功生成密钥 (%u 字节)\n", key_result->data_len);
    
    // 2. 导出密钥到文件
    printf("2. 导出密钥到 private_key.pem...\n");
    CapsulaResult* export_result = capsula_key_export_to_file(
        Curve25519, 
        key_result->data, 
        key_result->data_len, 
        "private_key.pem"
    );
    if (export_result->error_code != Success) {
        printf("   错误: %s\n", export_result->error_message);
        capsula_free_result(key_result);
        capsula_free_result(export_result);
        return 1;
    }
    printf("   ✓ 密钥已导出到 private_key.pem\n");
    
    // 3. 从文件导入密钥
    printf("3. 从文件导入密钥...\n");
    CapsulaResult* import_result = capsula_key_import_from_file(Curve25519, "private_key.pem");
    if (import_result->error_code != Success) {
        printf("   错误: %s\n", import_result->error_message);
        capsula_free_result(key_result);
        capsula_free_result(export_result);
        capsula_free_result(import_result);
        return 1;
    }
    printf("   ✓ 密钥导入成功 (%u 字节)\n", import_result->data_len);
    
    // 4. 签名消息
    printf("4. 签名消息...\n");
    const char* message = "Hello, Capsula!";
    CapsulaResult* sig_result = capsula_key_sign(
        Curve25519,
        import_result->data, 
        import_result->data_len,
        (const unsigned char*)message, 
        strlen(message)
    );
    if (sig_result->error_code != Success) {
        printf("   错误: %s\n", sig_result->error_message);
        capsula_free_result(key_result);
        capsula_free_result(export_result);
        capsula_free_result(import_result);
        capsula_free_result(sig_result);
        return 1;
    }
    printf("   ✓ 签名成功 (%u 字节)\n", sig_result->data_len);
    printf("   签名: ");
    print_hex(sig_result->data, sig_result->data_len);
    
    // 清理内存
    capsula_free_result(key_result);
    capsula_free_result(export_result);
    capsula_free_result(import_result);
    capsula_free_result(sig_result);
    
    printf("\n✅ 示例完成!\n");
    return 0;
}