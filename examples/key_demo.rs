//! Capsula Key Management Demo
//!
//! Demonstrates the unified key management capabilities including:
//! - Key generation and derivation
//! - Ed25519 signing and verification
//! - X25519 key exchange
//! - Key import/export (PEM and DER formats)
//! - Encryption key derivation

use capsula_key::key::{verify, Key, KeyMetadata, PublicKeyInfo};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Capsula Key Management Demo ===\n");

    // ============================================================================
    // 1. Key Generation
    // ============================================================================
    println!("1. Key Generation:");
    println!("   ---------------");

    let alice = Key::generate()?;
    let bob = Key::generate()?;

    println!("   Alice Key ID: {}", alice.key_id_hex());
    println!("   Bob Key ID:   {}", bob.key_id_hex());

    // ============================================================================
    // 2. Digital Signatures (Ed25519)
    // ============================================================================
    println!("\n2. Digital Signatures (Ed25519):");
    println!("   -----------------------------");

    let message = b"Hello, Capsula Crypto!";
    let signature = alice.sign(message);

    println!("   Message: {:?}", std::str::from_utf8(message)?);
    println!("   Signature (hex): {}", &hex::encode(&signature)[.. 32]);

    // Verify with Alice's key
    let valid = verify(&alice.ed25519_public_key_bytes(), message, &signature);
    println!(
        "   Self-verification: {}",
        if valid { "✓ Valid" } else { "✗ Invalid" }
    );

    // Verify with public key directly
    let alice_public = alice.ed25519_public_key_bytes();
    let valid = verify(&alice_public, message, &signature);
    println!(
        "   Public key verification: {}",
        if valid { "✓ Valid" } else { "✗ Invalid" }
    );

    // ============================================================================
    // 3. Key Exchange (X25519)
    // ============================================================================
    println!("\n3. Key Exchange (X25519):");
    println!("   ----------------------");

    let alice_shared = alice.compute_shared_secret(&bob.x25519_public_key());
    let bob_shared = bob.compute_shared_secret(&alice.x25519_public_key());

    println!(
        "   Alice's shared secret: {}",
        &hex::encode(&alice_shared)[.. 32]
    );
    println!(
        "   Bob's shared secret:   {}",
        &hex::encode(&bob_shared)[.. 32]
    );
    println!(
        "   Secrets match: {}",
        if alice_shared == bob_shared {
            "✓ Yes"
        } else {
            "✗ No"
        }
    );

    // ============================================================================
    // 4. Encryption Key Derivation
    // ============================================================================
    println!("\n4. Encryption Key Derivation (HKDF):");
    println!("   ---------------------------------");

    let salt = b"capsula-v1";
    let info = b"capsula-encryption-2024";

    let alice_enc_key = alice.derive_session_key_hkdf(&bob.x25519_public_key(), salt, info);
    let bob_enc_key = bob.derive_session_key_hkdf(&alice.x25519_public_key(), salt, info);

    println!("   Salt: {:?}", std::str::from_utf8(salt)?);
    println!("   Info: {:?}", std::str::from_utf8(info)?);
    println!(
        "   Alice's encryption key: {}",
        &hex::encode(&alice_enc_key)[.. 32]
    );
    println!(
        "   Bob's encryption key:   {}",
        &hex::encode(&bob_enc_key)[.. 32]
    );
    println!(
        "   Keys match: {}",
        if alice_enc_key == bob_enc_key {
            "✓ Yes"
        } else {
            "✗ No"
        }
    );

    // ============================================================================
    // 5. Key Import/Export (PEM)
    // ============================================================================
    println!("\n5. Key Import/Export (PEM):");
    println!("   -----------------------");

    // Export to PEM
    let pem = alice.to_pkcs8_pem()?;
    println!("   Exported PEM length: {} bytes", pem.len());

    // Import from PEM
    let imported = Key::from_pkcs8_pem(&pem)?;
    println!("   Import successful: ✓");
    println!(
        "   Key IDs match: {}",
        if alice.key_id() == imported.key_id() {
            "✓ Yes"
        } else {
            "✗ No"
        }
    );

    // ============================================================================
    // 6. Key Import/Export (DER)
    // ============================================================================
    println!("\n6. Key Import/Export (DER):");
    println!("   -----------------------");

    // Export to DER
    let der = alice.to_pkcs8_der()?;
    println!("   Exported DER length: {} bytes", der.len());

    // Import from DER
    let imported = Key::from_pkcs8_der(&der)?;
    println!("   Import successful: ✓");
    println!(
        "   Key IDs match: {}",
        if alice.key_id() == imported.key_id() {
            "✓ Yes"
        } else {
            "✗ No"
        }
    );

    // ============================================================================
    // 7. Public Key Info with Metadata
    // ============================================================================
    println!("\n7. Public Key Info with Metadata:");
    println!("   ------------------------------");

    let metadata = KeyMetadata {
        name: Some("Alice's Key".to_string()),
        email: Some("alice@example.com".to_string()),
        created_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        ),
        expires_at: None,
    };

    let alice_info = PublicKeyInfo::with_metadata(&alice, metadata);

    println!("   Key ID: {}", alice_info.key_id);
    println!(
        "   Name: {}",
        alice_info.metadata.as_ref().unwrap().name.as_ref().unwrap()
    );
    println!(
        "   Email: {}",
        alice_info
            .metadata
            .as_ref()
            .unwrap()
            .email
            .as_ref()
            .unwrap()
    );

    // Verify signature using PublicKeyInfo
    let valid = alice_info.verify(message, &signature);
    println!(
        "   Can verify signatures: {}",
        if valid { "✓ Yes" } else { "✗ No" }
    );

    // ============================================================================
    // 8. Deterministic Key Generation
    // ============================================================================
    println!("\n8. Deterministic Key Generation:");
    println!("   -----------------------------");

    let seed = [42u8; 32];
    let key1 = Key::from_seed(&seed);
    let key2 = Key::from_seed(&seed);

    println!("   Same seed produces same keys:");
    println!("   Key 1 ID: {}", key1.key_id_hex());
    println!("   Key 2 ID: {}", key2.key_id_hex());
    println!(
        "   IDs match: {}",
        if key1.key_id() == key2.key_id() {
            "✓ Yes"
        } else {
            "✗ No"
        }
    );

    // ============================================================================
    // 9. Cross-Key Signature Verification
    // ============================================================================
    println!("\n9. Cross-Key Signature Verification:");
    println!("   ---------------------------------");

    // Bob tries to verify Alice's signature
    let valid_by_bob = verify(&bob.ed25519_public_key_bytes(), message, &signature);
    println!(
        "   Bob verifies Alice's signature: {}",
        if valid_by_bob {
            "✗ Invalid (unexpected!)"
        } else {
            "✓ Invalid (expected)"
        }
    );

    // But Bob can verify using Alice's public key
    let valid_with_pub = verify(&alice_public, message, &signature);
    println!(
        "   Bob verifies with Alice's public key: {}",
        if valid_with_pub {
            "✓ Valid"
        } else {
            "✗ Invalid"
        }
    );

    println!("\n✅ All demonstrations completed successfully!");

    Ok(())
}
