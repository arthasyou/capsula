use std::{fs, path::Path};

use capsula_key::key::Key;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Capsula Key File Operations Demo ===\n");

    // Create a directory for our keys
    let key_dir = Path::new("keys");
    if !key_dir.exists() {
        fs::create_dir(key_dir)?;
        println!("Created 'keys' directory");
    }

    // File paths
    let private_key_path = key_dir.join("my_key.pem");
    let public_key_path = key_dir.join("my_key.pub.json");

    // Step 1: Generate and save a new key
    println!("1. Generating new key pair...");
    let key = Key::generate();
    println!("   Key ID: {}", key.key_id_hex());

    // Save private key to file
    println!("\n2. Saving private key to: {}", private_key_path.display());
    key.save_to_file(&private_key_path)?;
    println!("   ✓ Private key saved");

    // Save public key info to file
    println!("\n3. Saving public key to: {}", public_key_path.display());
    key.save_public_key_info_to_file(&public_key_path)?;
    println!("   ✓ Public key info saved");

    // Display the saved files
    println!("\n4. File contents:");
    println!("   Private key ({})", private_key_path.display());
    println!("   ================================");
    let private_pem = fs::read_to_string(&private_key_path)?;
    println!("{}", private_pem);

    println!("   Public key info ({})", public_key_path.display());
    println!("   ================================");
    let public_json = fs::read_to_string(&public_key_path)?;
    println!("{}", public_json);

    // Step 2: Load the key back from file
    println!("\n5. Loading key from file...");
    let loaded_key = Key::load_from_file(&private_key_path)?;
    println!("   ✓ Private key loaded");
    println!("   Key ID: {}", loaded_key.key_id_hex());

    // Load public key info
    let loaded_public = Key::load_public_key_info_from_file(&public_key_path)?;
    println!("   ✓ Public key info loaded");
    println!("   Public Key ID: {}", loaded_public.key_id);

    // Step 3: Verify the loaded keys work correctly
    println!("\n6. Verifying loaded keys...");

    // Test signing
    let message = b"Test message for signing";
    let signature = loaded_key.sign(message);
    let is_valid = loaded_key.verify(message, &signature);
    println!(
        "   Signature verification: {}",
        if is_valid { "✓ PASS" } else { "✗ FAIL" }
    );

    // Verify key IDs match
    let original_id = key.key_id_hex();
    let loaded_id = loaded_key.key_id_hex();
    println!(
        "   Key ID match: {} (original: {}, loaded: {})",
        if original_id == loaded_id {
            "✓ PASS"
        } else {
            "✗ FAIL"
        },
        original_id,
        loaded_id
    );

    // Verify keys are identical
    println!(
        "   Ed25519 keys match: {}",
        if key.ed25519.to_seed_bytes() == loaded_key.ed25519.to_seed_bytes() {
            "✓ PASS"
        } else {
            "✗ FAIL"
        }
    );
    println!(
        "   X25519 keys match: {}",
        if key.x25519.to_bytes() == loaded_key.x25519.to_bytes() {
            "✓ PASS"
        } else {
            "✗ FAIL"
        }
    );

    // Step 4: Demonstrate key exchange with saved keys
    println!("\n7. Key exchange with saved keys:");

    // Create Bob's key and save it
    let bob_key_path = key_dir.join("bob.pem");
    let bob_public_path = key_dir.join("bob.pub.json");

    let bob = Key::generate();
    bob.save_to_file(&bob_key_path)?;
    bob.save_public_key_info_to_file(&bob_public_path)?;
    println!("   Created and saved Bob's key");

    // Alice loads her key and Bob's public key
    let alice = Key::load_from_file(&private_key_path)?;
    let bob_public = Key::load_public_key_info_from_file(&bob_public_path)?;

    // Bob loads his key and Alice's public key
    let bob_loaded = Key::load_from_file(&bob_key_path)?;
    let alice_public = Key::load_public_key_info_from_file(&public_key_path)?;

    // Compute shared secrets
    let alice_shared = alice.compute_shared_secret(&bob_public.x25519);
    let bob_shared = bob_loaded.compute_shared_secret(&alice_public.x25519);

    println!(
        "   Alice's shared secret: {}",
        hex::encode(&alice_shared[.. 16])
    );
    println!(
        "   Bob's shared secret:   {}",
        hex::encode(&bob_shared[.. 16])
    );
    println!(
        "   Shared secrets match: {}",
        if alice_shared == bob_shared {
            "✓ PASS"
        } else {
            "✗ FAIL"
        }
    );

    // Step 5: Clean up demonstration
    println!("\n8. File organization summary:");
    println!("   Private keys:");
    println!("     - keys/my_key.pem    (Alice's private key)");
    println!("     - keys/bob.pem       (Bob's private key)");
    println!("   Public keys:");
    println!("     - keys/my_key.pub.json (Alice's public key)");
    println!("     - keys/bob.pub.json    (Bob's public key)");

    println!("\n=== Demo Complete ===");
    println!("\nNote: The 'keys' directory contains the generated key files.");
    println!("In production, ensure proper file permissions (e.g., chmod 600 for private keys).");

    Ok(())
}
