use capsula_crypto::X25519;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== X25519 Advanced Features Demo ===\n");

    // 1. Generate keys with new API
    println!("1. Key Generation:");
    let alice = X25519::generate()?;
    let bob = X25519::generate()?;
    println!("   ✓ Alice's key generated");
    println!("   ✓ Bob's key generated\n");

    // 2. Export to various formats
    println!("2. Key Export Formats:");
    
    // PKCS8 PEM
    let alice_pem = alice.to_pkcs8_pem()?;
    println!("   Alice's Private Key (PEM):");
    println!("{}", alice_pem);
    
    // SPKI PEM (public key)
    let alice_public_pem = alice.to_spki_pem()?;
    println!("   Alice's Public Key (PEM):");
    println!("{}", alice_public_pem);
    
    // JWK format
    let alice_jwk = alice.to_jwk()?;
    println!("   Alice's Public Key (JWK):");
    println!("{}\n", alice_jwk);

    // 3. Import from PEM
    println!("3. Key Import:");
    let alice_imported = X25519::from_pem(&alice_pem)?;
    println!("   ✓ Successfully imported Alice's key from PEM");
    
    // Verify imported key matches
    assert_eq!(alice.to_bytes(), alice_imported.to_bytes());
    println!("   ✓ Imported key matches original\n");

    // 4. SPKI fingerprint
    println!("4. Key Fingerprints:");
    let alice_fingerprint = alice.spki_sha256_fingerprint()?;
    let bob_fingerprint = bob.spki_sha256_fingerprint()?;
    println!("   Alice's fingerprint: {}", hex::encode(&alice_fingerprint[..8]));
    println!("   Bob's fingerprint:   {}\n", hex::encode(&bob_fingerprint[..8]));

    // 5. Key exchange
    println!("5. X25519 Key Exchange:");
    let alice_public = alice.public_key().to_bytes();
    let bob_public = bob.public_key().to_bytes();
    
    let alice_shared = alice.compute_shared_secret(&bob_public);
    let bob_shared = bob.compute_shared_secret(&alice_public);
    
    assert_eq!(alice_shared, bob_shared);
    println!("   Shared secret: {}", hex::encode(&alice_shared[..16]));
    println!("   ✓ Both parties computed the same shared secret\n");

    // 6. Deterministic key generation from seed
    println!("6. Deterministic Key Generation:");
    let seed = [42u8; 32];
    let key1 = X25519::from_raw_seed(&seed);
    let key2 = X25519::from_raw_seed(&seed);
    
    assert_eq!(key1.to_bytes(), key2.to_bytes());
    assert_eq!(key1.public_key().to_bytes(), key2.public_key().to_bytes());
    println!("   ✓ Same seed produces identical keys");
    println!("   Public key: {}\n", hex::encode(&key1.public_key().to_bytes()[..8]));

    // 7. DER format support
    println!("7. DER Format Support:");
    let alice_der = alice.to_pkcs8_der()?;
    println!("   Private key DER: {} bytes", alice_der.len());
    
    let alice_public_der = alice.to_spki_der()?;
    println!("   Public key DER: {} bytes", alice_public_der.len());
    
    let alice_from_der = X25519::from_pkcs8_der(&alice_der)?;
    assert_eq!(alice.to_bytes(), alice_from_der.to_bytes());
    println!("   ✓ Successfully round-tripped through DER format\n");

    // 8. Public key import
    println!("8. Public Key Import:");
    let public_key = capsula_crypto::asymmetric::x25519::public_key_from_spki_pem(&alice_public_pem)?;
    assert_eq!(alice.public_key().to_bytes(), public_key.to_bytes());
    println!("   ✓ Successfully imported public key from PEM");
    
    let public_key_der = capsula_crypto::asymmetric::x25519::public_key_from_spki_der(&alice_public_der)?;
    assert_eq!(alice.public_key().to_bytes(), public_key_der.to_bytes());
    println!("   ✓ Successfully imported public key from DER\n");

    println!("=== All X25519 features working correctly! ===");

    Ok(())
}