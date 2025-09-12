//! CSR (Certificate Signing Request) Demo
//!
//! This example demonstrates how to create, save, load, and verify CSRs using capsula-key.

use capsula_key::Key;
use capsula_pki::csr::{create_csr, Csr, CsrSubject};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Capsula CSR Demo ===\n");

    // Generate a new key pair
    println!("1. Generating Ed25519 key pair...");
    let key = Key::generate()?;
    println!("   Key ID: {}", key.key_id_hex());
    println!("   Key fingerprint: {}", key.fingerprint_hex());

    // Create CSR subject information
    println!("\n2. Creating CSR subject...");
    let subject = CsrSubject {
        common_name: "example.com".to_string(),
        organization: Some("Example Corporation".to_string()),
        organizational_unit: Some("IT Department".to_string()),
        country: Some("US".to_string()),
        state: Some("California".to_string()),
        locality: Some("San Francisco".to_string()),
    };
    println!("   Subject: CN={}", subject.common_name);
    if let Some(ref org) = subject.organization {
        println!("           O={}", org);
    }
    if let Some(ref country) = subject.country {
        println!("           C={}", country);
    }

    // Create a CSR
    println!("\n3. Creating CSR...");
    let csr = create_csr(&key, subject.clone())?;
    println!("   ✓ CSR created successfully");

    // Verify the CSR signature
    println!("\n4. Verifying CSR signature...");
    match csr.verify_signature() {
        Ok(()) => println!("   ✓ CSR signature is valid"),
        Err(e) => println!("   ✗ CSR signature invalid: {}", e),
    }

    // Extract Ed25519 public key
    let public_key_bytes = csr.ed25519_public_key_bytes()?;
    println!("   Ed25519 public key: {}", hex::encode(public_key_bytes));

    // Export CSR to PEM format
    println!("\n5. Exporting CSR to PEM format...");
    let pem = csr.to_pem()?;
    println!("   PEM CSR length: {} characters", pem.len());
    println!("   PEM preview (first 100 chars):");
    println!("   {}", &pem[..100.min(pem.len())]);

    // Export CSR to DER format
    println!("\n6. Exporting CSR to DER format...");
    let der = csr.to_der()?;
    println!("   DER CSR length: {} bytes", der.len());
    println!("   DER preview (hex, first 32 bytes): {}", 
             hex::encode(&der[..32.min(der.len())]));

    // Save CSR to files
    println!("\n7. Saving CSR to files...");
    std::fs::write("example.csr", &pem)?;
    std::fs::write("example.der", &der)?;
    println!("   ✓ Saved: example.csr (PEM format)");
    println!("   ✓ Saved: example.der (DER format)");

    // Load CSR from file and verify
    println!("\n8. Loading and verifying CSR from file...");
    let pem_data = std::fs::read_to_string("example.csr")?;
    let loaded_csr = Csr::from_pem(&pem_data)?;
    
    match loaded_csr.verify_signature() {
        Ok(()) => println!("   ✓ Loaded CSR signature is valid"),
        Err(e) => println!("   ✗ Loaded CSR signature invalid: {}", e),
    }

    // Compare original and loaded CSRs
    let original_der = csr.to_der()?;
    let loaded_der = loaded_csr.to_der()?;
    println!("   CSRs match: {}", original_der == loaded_der);

    // Load from DER format
    println!("\n9. Testing DER format loading...");
    let der_data = std::fs::read("example.der")?;
    let der_loaded_csr = Csr::from_der(&der_data)?;
    match der_loaded_csr.verify_signature() {
        Ok(()) => println!("   ✓ DER loaded CSR signature is valid"),
        Err(e) => println!("   ✗ DER loaded CSR signature invalid: {}", e),
    }

    // Create CSR with different subject for comparison
    println!("\n10. Creating different CSR for comparison...");
    let different_subject = CsrSubject {
        common_name: "different.example.com".to_string(),
        organization: Some("Different Corp".to_string()),
        organizational_unit: None,
        country: Some("CA".to_string()),
        state: Some("Ontario".to_string()),
        locality: Some("Toronto".to_string()),
    };
    
    let different_csr = create_csr(&key, different_subject)?;
    println!("   ✓ Created CSR with different subject");
    
    // Compare subjects
    let original_subject = csr.subject()?;
    let different_subject_parsed = different_csr.subject()?;
    
    println!("   Original CN: {}", original_subject.common_name);
    println!("   Different CN: {}", different_subject_parsed.common_name);
    println!("   Subjects are different: {}", 
             original_subject.common_name != different_subject_parsed.common_name);

    // Performance test: create multiple CSRs
    println!("\n11. Performance test: Creating 10 CSRs...");
    let start = std::time::Instant::now();
    
    for i in 0..10 {
        let test_subject = CsrSubject {
            common_name: format!("test{}.example.com", i),
            organization: Some("Test Corp".to_string()),
            organizational_unit: None,
            country: Some("US".to_string()),
            state: None,
            locality: None,
        };
        let _test_csr = create_csr(&key, test_subject)?;
    }
    
    let elapsed = start.elapsed();
    println!("   Created 10 CSRs in {:?} ({:.2} CSRs/sec)", 
             elapsed, 10.0 / elapsed.as_secs_f64());

    println!("\n=== Demo completed successfully! ===");
    println!("\nFiles created:");
    println!("  - example.csr (PEM format CSR)");
    println!("  - example.der (DER format CSR)");
    println!("\nClean up with: rm example.csr example.der");

    Ok(())
}