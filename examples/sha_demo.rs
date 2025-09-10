//! SHA Hash Functions Demo
//! 
//! Demonstrates the usage of SHA-256 and SHA-512 hash functions.

use capsula_crypto::{
    hash, hash_hex, verify, HashAlgorithm,
    sha256, sha256_hex, sha256_verify, 
    sha512, sha512_hex, sha512_verify,
    quick_hash, quick_hash_hex
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SHA Hash Functions Demo ===\n");

    // Test data
    let data = b"Hello, Capsula Crypto!";
    
    // ============================================================================
    // SHA-256 Demo
    // ============================================================================
    println!("1. SHA-256 Hashing:");
    println!("   Data: {:?}", std::str::from_utf8(data)?);
    
    // Compute SHA-256 hash
    let hash256 = sha256(data);
    println!("   SHA-256 (bytes): {} bytes", hash256.len());
    
    // Get hex representation
    let hex256 = sha256_hex(data);
    println!("   SHA-256 (hex): {}", hex256);
    
    // Verify hash
    let is_valid256 = sha256_verify(data, &hash256);
    println!("   Verification: {}", if is_valid256 { "✓ Valid" } else { "✗ Invalid" });
    
    // ============================================================================
    // SHA-512 Demo
    // ============================================================================
    println!("\n2. SHA-512 Hashing:");
    println!("   Data: {:?}", std::str::from_utf8(data)?);
    
    // Compute SHA-512 hash
    let hash512 = sha512(data);
    println!("   SHA-512 (bytes): {} bytes", hash512.len());
    
    // Get hex representation
    let hex512 = sha512_hex(data);
    println!("   SHA-512 (hex):\n      {}", hex512);
    
    // Verify hash
    let is_valid512 = sha512_verify(data, &hash512);
    println!("   Verification: {}", if is_valid512 { "✓ Valid" } else { "✗ Invalid" });
    
    // ============================================================================
    // Comparison
    // ============================================================================
    println!("\n3. Hash Comparison:");
    println!("   SHA-256 output size: {} bytes ({} hex chars)", 32, 64);
    println!("   SHA-512 output size: {} bytes ({} hex chars)", 64, 128);
    
    // Different data produces different hashes
    let different_data = b"Different data";
    let different_hash256 = sha256_hex(different_data);
    let different_hash512 = sha512_hex(different_data);
    
    println!("\n   Different data produces different hashes:");
    println!("   Original SHA-256: {}", &hex256[..16]);
    println!("   Modified SHA-256: {}", &different_hash256[..16]);
    println!("   Original SHA-512: {}", &hex512[..16]);
    println!("   Modified SHA-512: {}", &different_hash512[..16]);
    
    // ============================================================================
    // New Generic API with Algorithm Parameter
    // ============================================================================
    println!("\n4. Generic Hash API:");
    println!("   Using hash() with algorithm parameter:");
    
    let test_data = b"Generic API test";
    
    // Using generic hash function with algorithm
    let generic_256 = hash(test_data, HashAlgorithm::Sha256);
    let generic_512 = hash(test_data, HashAlgorithm::Sha512);
    
    println!("   SHA-256 via hash(): {} bytes", generic_256.len());
    println!("   SHA-512 via hash(): {} bytes", generic_512.len());
    
    // Using generic hex function
    let hex_256 = hash_hex(test_data, HashAlgorithm::Sha256);
    let hex_512 = hash_hex(test_data, HashAlgorithm::Sha512);
    
    println!("   SHA-256 hex (first 16 chars): {}", &hex_256[..16]);
    println!("   SHA-512 hex (first 16 chars): {}", &hex_512[..16]);
    
    // Using generic verify
    let is_valid = verify(test_data, &generic_256, HashAlgorithm::Sha256);
    println!("   Generic verify: {}", if is_valid { "✓ Valid" } else { "✗ Invalid" });
    
    // Quick functions (use default algorithm - SHA-256)
    let quick = quick_hash(test_data);
    let quick_hex = quick_hash_hex(test_data);
    println!("\n   Quick hash (default SHA-256): {} bytes", quick.len());
    println!("   Quick hex (first 16 chars): {}", &quick_hex[..16]);
    
    // ============================================================================
    // Use Cases
    // ============================================================================
    println!("\n5. Common Use Cases:");
    println!("   • SHA-256: Password hashing, blockchain, file integrity");
    println!("   • SHA-512: Higher security requirements, larger hash space");
    println!("   • Both: HMAC, key derivation (HKDF), digital signatures");
    
    Ok(())
}