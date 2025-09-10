use std::{fs, path::Path};

use capsula_key::key::Key;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Capsula Key PEM Format Demo ===\n");

    // Create a directory for our keys
    let key_dir = Path::new("keys");
    if !key_dir.exists() {
        fs::create_dir(key_dir)?;
        println!("Created 'keys' directory");
    }

    // Generate a new key
    println!("1. Generating new key pair...");
    let key = Key::generate();
    println!("   Key ID: {}\n", key.key_id_hex());

    // Define file paths
    let private_key_path = key_dir.join("private.pem");
    let ed25519_pub_path = key_dir.join("ed25519_public.pem");
    let x25519_pub_path = key_dir.join("x25519_public.pem");

    // Save all keys in PEM format
    println!("2. Saving keys in PEM format:");

    // Save private key
    key.save_to_file(&private_key_path)?;
    println!("   ✓ Private key saved to: {}", private_key_path.display());

    // Save Ed25519 public key
    key.save_ed25519_public_key_to_file(&ed25519_pub_path)?;
    println!(
        "   ✓ Ed25519 public key saved to: {}",
        ed25519_pub_path.display()
    );

    // Save X25519 public key
    key.save_x25519_public_key_to_file(&x25519_pub_path)?;
    println!(
        "   ✓ X25519 public key saved to: {}",
        x25519_pub_path.display()
    );

    // Display the file contents
    println!("\n3. File Contents:");
    println!("{}", "=".repeat(60));

    println!(
        "\n📝 Private Key (Ed25519) - {}",
        private_key_path.display()
    );
    println!("{}", "-".repeat(60));
    let private_pem = fs::read_to_string(&private_key_path)?;
    println!("{}", private_pem);

    println!("📝 Ed25519 Public Key - {}", ed25519_pub_path.display());
    println!("{}", "-".repeat(60));
    let ed25519_pub_pem = fs::read_to_string(&ed25519_pub_path)?;
    println!("{}", ed25519_pub_pem);

    println!("📝 X25519 Public Key - {}", x25519_pub_path.display());
    println!("{}", "-".repeat(60));
    let x25519_pub_pem = fs::read_to_string(&x25519_pub_path)?;
    println!("{}", x25519_pub_pem);

    // Explain the key structure
    println!("4. Key Structure Explanation:");
    println!("{}", "=".repeat(60));
    println!();
    println!("🔐 Private Key (private.pem):");
    println!("   - Contains ONLY the Ed25519 private key");
    println!("   - X25519 private key is derived from this");
    println!("   - This is the ONLY file you need to backup");
    println!();
    println!("🔓 Public Keys:");
    println!("   - ed25519_public.pem: For signature verification");
    println!("   - x25519_public.pem: For key exchange");
    println!("   - Both can be safely shared with others");
    println!();

    // Demonstrate key usage
    println!("5. Usage Demonstration:");
    println!("{}", "=".repeat(60));

    // Load the private key
    let loaded_key = Key::load_from_file(&private_key_path)?;
    println!("   ✓ Private key loaded successfully");

    // Test signing
    let message = b"Hello, Capsula!";
    let signature = loaded_key.sign(message);
    println!("   ✓ Message signed");

    // Verify signature
    let is_valid = loaded_key.verify(message, &signature);
    println!("   ✓ Signature verified: {}", is_valid);

    // Create another key for key exchange demo
    let bob = Key::generate();
    let bob_private_path = key_dir.join("bob_private.pem");
    let bob_x25519_pub_path = key_dir.join("bob_x25519_public.pem");

    bob.save_to_file(&bob_private_path)?;
    bob.save_x25519_public_key_to_file(&bob_x25519_pub_path)?;

    // Compute shared secrets
    let alice_shared = loaded_key.compute_shared_secret(&bob.x25519_public_key());
    let bob_shared = bob.compute_shared_secret(&loaded_key.x25519_public_key());

    println!("   ✓ Key exchange successful");
    println!(
        "   Alice's shared secret: {}",
        hex::encode(&alice_shared[.. 8])
    );
    println!(
        "   Bob's shared secret:   {}",
        hex::encode(&bob_shared[.. 8])
    );

    // File organization summary
    println!("\n6. File Organization:");
    println!("{}", "=".repeat(60));
    println!("keys_pem/");
    println!("├── private.pem           # Your private key (keep secret!)");
    println!("├── ed25519_public.pem    # Ed25519 public key (for signatures)");
    println!("├── x25519_public.pem     # X25519 public key (for key exchange)");
    println!("├── bob_private.pem       # Bob's private key");
    println!("└── bob_x25519_public.pem # Bob's X25519 public key");

    println!("\n7. Why PEM Format?");
    println!("{}", "=".repeat(60));
    println!("✅ Industry standard format");
    println!("✅ Compatible with OpenSSL and other tools");
    println!("✅ Human-readable with clear boundaries");
    println!("✅ Base64 encoded for easy transmission");
    println!("✅ Self-describing with header/footer");

    println!("\n=== Demo Complete ===");

    Ok(())
}
