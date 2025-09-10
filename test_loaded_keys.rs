use capsula_crypto::{utils::load_pem_from_file, ed25519::{sign, verify}};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the keys from PEM files
    let (private_key_vec, private_label) = load_pem_from_file("demo_keys/p256_private.pem")?;
    let (public_key_vec, public_label) = load_pem_from_file("demo_keys/p256_public.pem")?;
    
    println!("Private key label: {}", private_label);
    println!("Private key size: {} bytes", private_key_vec.len());
    println!("Public key label: {}", public_label);
    println!("Public key size: {} bytes", public_key_vec.len());
    
    // Convert to arrays
    let private_key: [u8; 32] = private_key_vec.as_slice().try_into()?;
    let public_key: [u8; 32] = public_key_vec.as_slice().try_into()?;
    
    // Test signing and verification
    let message = b"Test message for Ed25519";
    let signature = sign(&private_key, message);
    
    println!("\nSigning message: '{}'", std::str::from_utf8(message)?);
    println!("Signature length: {} bytes", signature.len());
    
    let is_valid = verify(&public_key, message, &signature);
    println!("Signature verification: {}", if is_valid { "✓ VALID" } else { "✗ INVALID" });
    
    // Test with wrong message
    let wrong_message = b"Wrong message";
    let is_valid_wrong = verify(&public_key, wrong_message, &signature);
    println!("Wrong message verification: {}", if !is_valid_wrong { "✓ CORRECTLY REJECTED" } else { "✗ SHOULD BE INVALID" });
    
    Ok(())
}