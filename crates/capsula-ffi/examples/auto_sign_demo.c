/*
 * 自动检测算法签名示例
 * 
 * 编译:
 * gcc -o auto_sign_demo examples/auto_sign_demo.c -I target/release/include/capsula-ffi -L target/release -lcapsula_ffi
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

void test_algorithm(CapsulaAlgorithm alg, const char* name) {
    printf("\n=== 测试 %s ===\n", name);
    
    // 1. 生成密钥
    printf("1. 生成%s密钥...\n", name);
    CapsulaResult* key = capsula_key_generate(alg);
    if (key->error_code != Success) {
        printf("   错误: %s\n", key->error_message);
        capsula_free_result(key);
        return;
    }
    printf("   ✓ 密钥生成成功 (%u 字节)\n", key->data_len);
    
    // 2. 使用自动检测算法签名 - 不需要指定算法类型！
    printf("2. 自动检测并签名...\n");
    const char* message = "Hello, Auto Detection!";
    CapsulaResult* signature = capsula_sign(
        key->data, key->data_len,
        (const unsigned char*)message, strlen(message)
    );
    
    if (signature->error_code != Success) {
        printf("   错误: %s\n", signature->error_message);
        capsula_free_result(key);
        capsula_free_result(signature);
        return;
    }
    
    printf("   ✓ 签名成功 (%u 字节)\n", signature->data_len);
    printf("   签名: ");
    print_hex(signature->data, signature->data_len);
    
    // 清理
    capsula_free_result(key);
    capsula_free_result(signature);
}

int main() {
    printf("=== 自动检测算法签名示例 ===\n");
    printf("使用 capsula_sign() 函数自动检测密钥类型并签名\n");
    
    // 测试所有支持的算法
    test_algorithm(Curve25519, "Curve25519");
    test_algorithm(Rsa2048, "RSA-2048");
    test_algorithm(P256, "P256");
    
    printf("\n✅ 所有测试完成!\n");
    printf("\n💡 使用 capsula_sign() 无需指定算法，它会自动检测！\n");
    
    return 0;
}