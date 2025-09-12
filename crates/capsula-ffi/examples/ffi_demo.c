/*
 * Simple demo of capsula-ffi usage
 * 
 * Compile with:
 * gcc -o ffi_demo examples/ffi_demo.c -I target/release/include/capsula-ffi -L target/release -lcapsula_ffi -lm -ldl -lpthread
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
    printf("=== Capsula FFI Demo ===\n\n");
    
    // Get version
    char* version = capsula_get_version();
    if (version) {
        printf("Library version: %s\n\n", version);
        capsula_free_string(version);
    }
    
    // Generate Curve25519 key
    printf("1. Generating Curve25519 key...\n");
    CapsulaResult* key_result = capsula_curve25519_generate();
    if (key_result->error_code != Success) {
        printf("   ERROR: %s\n", key_result->error_message);
        capsula_free_result(key_result);
        return 1;
    }
    printf("   ✓ Generated private key (%u bytes)\n", key_result->data_len);
    
    // Get key ID
    printf("2. Getting key ID...\n");
    CapsulaResult* id_result = capsula_curve25519_key_id(key_result->data, key_result->data_len);
    if (id_result->error_code != Success) {
        printf("   ERROR: %s\n", id_result->error_message);
        capsula_free_result(key_result);
        capsula_free_result(id_result);
        return 1;
    }
    printf("   ✓ Key ID: ");
    print_hex(id_result->data, id_result->data_len);
    
    // Sign a message
    printf("3. Signing message...\n");
    const char* message = "Hello from capsula-ffi!";
    CapsulaResult* sig_result = capsula_curve25519_sign(
        key_result->data, key_result->data_len,
        (const unsigned char*)message, strlen(message)
    );
    if (sig_result->error_code != Success) {
        printf("   ERROR: %s\n", sig_result->error_message);
        capsula_free_result(key_result);
        capsula_free_result(id_result);
        capsula_free_result(sig_result);
        return 1;
    }
    printf("   ✓ Signature generated (%u bytes)\n", sig_result->data_len);
    printf("   Signature: ");
    print_hex(sig_result->data, sig_result->data_len);
    
    // Export keys to files
    printf("4. Exporting keys to ./keys/...\n");
    CapsulaResult* export_result = capsula_curve25519_export_all_keys(
        key_result->data, key_result->data_len,
        "./keys", "demo_key"
    );
    if (export_result->error_code != Success) {
        printf("   ERROR: %s\n", export_result->error_message);
    } else {
        printf("   ✓ Keys exported successfully\n");
        printf("   Export info (%u bytes): %.*s\n", 
               export_result->data_len, 
               export_result->data_len, 
               (char*)export_result->data);
    }
    
    printf("\n=== RSA Demo ===\n");
    
    // Generate RSA key
    printf("5. Generating RSA-2048 key...\n");
    CapsulaResult* rsa_key_result = capsula_rsa_generate_2048();
    if (rsa_key_result->error_code != Success) {
        printf("   ERROR: %s\n", rsa_key_result->error_message);
    } else {
        printf("   ✓ Generated RSA private key (%u bytes)\n", rsa_key_result->data_len);
        
        // Sign with RSA
        CapsulaResult* rsa_sig_result = capsula_rsa_sign(
            rsa_key_result->data, rsa_key_result->data_len,
            (const unsigned char*)message, strlen(message)
        );
        if (rsa_sig_result->error_code != Success) {
            printf("   ERROR: %s\n", rsa_sig_result->error_message);
        } else {
            printf("   ✓ RSA signature generated (%u bytes)\n", rsa_sig_result->data_len);
        }
        capsula_free_result(rsa_sig_result);
    }
    
    printf("\n=== P256 Demo ===\n");
    
    // Generate P256 key
    printf("6. Generating P256 key...\n");
    CapsulaResult* p256_key_result = capsula_p256_generate();
    if (p256_key_result->error_code != Success) {
        printf("   ERROR: %s\n", p256_key_result->error_message);
    } else {
        printf("   ✓ Generated P256 private key (%u bytes)\n", p256_key_result->data_len);
        
        // Sign with P256
        CapsulaResult* p256_sig_result = capsula_p256_sign(
            p256_key_result->data, p256_key_result->data_len,
            (const unsigned char*)message, strlen(message)
        );
        if (p256_sig_result->error_code != Success) {
            printf("   ERROR: %s\n", p256_sig_result->error_message);
        } else {
            printf("   ✓ P256 signature generated (%u bytes)\n", p256_sig_result->data_len);
        }
        capsula_free_result(p256_sig_result);
    }
    
    // Cleanup
    capsula_free_result(key_result);
    capsula_free_result(id_result);
    capsula_free_result(sig_result);
    capsula_free_result(export_result);
    capsula_free_result(rsa_key_result);
    capsula_free_result(p256_key_result);
    
    printf("\n✅ Demo completed successfully!\n");
    return 0;
}