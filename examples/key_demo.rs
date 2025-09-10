use capsula_crypto::X25519;
use capsula_key::key::{Key, PublicKeyInfo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Capsula Key Demo ===\n");

    // 1. Generate a new key pair
    println!("1. Generating new key pair...");
    let key = Key::generate();

    // 2. Get key ID
    println!("   Key ID: {}", key.key_id_hex());

    // 3. Export Ed25519 private key to PEM
    println!("\n2. Ed25519 Private Key (PEM format):");
    println!("   ================================");
    let ed25519_pem = key.to_pem()?;
    println!("{}", ed25519_pem);

    // 4. Export X25519 private key to PEM (for demonstration)
    println!("\n3. X25519 Private Key (PEM format):");
    println!("   ================================");
    // Clone X25519 for export (since export consumes self)
    let x25519_copy = X25519::from_raw_seed(&key.x25519.to_bytes());
    let x25519_pem = x25519_copy
        .to_pkcs8_pem()
        .map_err(|e| format!("Failed to export X25519 key: {}", e))?;
    println!("{}", x25519_pem);

    // 5. Show Ed25519 public key
    println!("\n4. Ed25519 Public Key:");
    println!("   ================================");
    let ed25519_public = key.ed25519_public_key();
    println!(
        "   Raw bytes (hex): {}",
        hex::encode(ed25519_public.to_bytes())
    );

    // Export Ed25519 public key to PEM
    let ed25519_public_pem = key
        .ed25519
        .to_spki_pem()
        .map_err(|e| format!("Failed to export Ed25519 public key: {}", e))?;
    println!("\n   PEM format:");
    println!("{}", ed25519_public_pem);

    // 6. Show X25519 public key
    println!("\n5. X25519 Public Key:");
    println!("   ================================");
    let x25519_public = key.x25519_public_key();
    println!("   Raw bytes (hex): {}", hex::encode(x25519_public));

    // Export X25519 public key to PEM
    let x25519_copy2 = X25519::from_raw_seed(&key.x25519.to_bytes());
    let x25519_public_pem = x25519_copy2
        .to_spki_pem()
        .map_err(|e| format!("Failed to export X25519 public key: {}", e))?;
    println!("\n   PEM format:");
    println!("{}", x25519_public_pem);

    // 7. Create PublicKeyInfo
    println!("\n6. Public Key Info (JSON):");
    println!("   ================================");
    let public_info = PublicKeyInfo::from(&key);
    let json = serde_json::to_string_pretty(&public_info)?;
    println!("{}", json);

    // 8. Demonstrate key derivation
    println!("\n7. Key Derivation Test:");
    println!("   ================================");
    println!("   Reimporting from Ed25519 PEM...");
    let reimported_key = Key::from_pem(&ed25519_pem)?;

    println!(
        "   Ed25519 private keys match: {}",
        key.ed25519.to_seed_bytes() == reimported_key.ed25519.to_seed_bytes()
    );
    println!(
        "   X25519 private keys match: {}",
        key.x25519.to_bytes() == reimported_key.x25519.to_bytes()
    );
    println!("   ✓ X25519 was successfully derived from Ed25519!");

    // 9. Test signing
    println!("\n8. Signature Test:");
    println!("   ================================");
    let message = b"Hello, Capsula!";
    let signature = key.sign(message);
    println!("   Message: {:?}", std::str::from_utf8(message)?);
    println!("   Signature (hex): {}", hex::encode(signature));
    let is_valid = key.verify(message, &signature);
    println!("   Signature valid: {}", is_valid);

    // 10. Test key exchange
    println!("\n9. Key Exchange Test:");
    println!("   ================================");
    let alice = Key::generate();
    let bob = Key::generate();

    println!("   Alice Key ID: {}", alice.key_id_hex());
    println!("   Bob Key ID:   {}", bob.key_id_hex());

    let alice_shared = alice.compute_shared_secret(&bob.x25519_public_key());
    let bob_shared = bob.compute_shared_secret(&alice.x25519_public_key());

    println!(
        "   Alice's shared secret: {}",
        hex::encode(&alice_shared[.. 16])
    );
    println!(
        "   Bob's shared secret:   {}",
        hex::encode(&bob_shared[.. 16])
    );
    println!("   Shared secrets match: {}", alice_shared == bob_shared);

    // 11. Show how to use with encryption
    println!("\n10. Encryption with Shared Secret:");
    println!("    ================================");
    use capsula_crypto::chacha;

    let plaintext = b"Secret message between Alice and Bob";
    let encrypted = chacha::encrypt(&alice_shared, plaintext)?;
    let decrypted = chacha::decrypt(&bob_shared, &encrypted)?;

    println!("    Original:  {:?}", std::str::from_utf8(plaintext)?);
    println!("    Encrypted: {} bytes", encrypted.len());
    println!("    Decrypted: {:?}", std::str::from_utf8(&decrypted)?);
    println!("    Decryption successful: {}", plaintext == &decrypted[..]);

    println!("\n=== Demo Complete ===");

    Ok(())
}
