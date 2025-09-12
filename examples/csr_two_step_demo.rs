//! CSR Two-Step API Demo
//!
//! This example demonstrates the new two-step CSR creation API:
//! 1. build_unsigned() - Create unsigned CSR info
//! 2. assemble() - Combine with signature to create complete CSR

use capsula_key::Key;
use capsula_pki::csr::{build_unsigned, create_csr, Csr, CsrSubject};
use der::Encode;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Capsula CSR Two-Step API Demo ===\n");

    // Generate a key pair
    println!("1. Generating Ed25519 key pair...");
    let key = Key::generate()?;
    println!("   Key ID: {}", key.key_id_hex());

    // Create subject
    println!("\n2. Creating CSR subject...");
    let subject = CsrSubject {
        common_name: "two-step.example.com".to_string(),
        organization: Some("Two-Step Demo Corp".to_string()),
        organizational_unit: Some("Engineering".to_string()),
        country: Some("US".to_string()),
        state: Some("California".to_string()),
        locality: Some("San Francisco".to_string()),
    };
    println!("   Subject: CN={}", subject.common_name);

    // Get public key in SPKI format
    println!("\n3. Getting public key in SPKI format...");
    let spki_der = key.ed25519_spki_der()?;
    println!("   SPKI DER length: {} bytes", spki_der.len());

    // Step 1: Build unsigned CSR info
    println!("\n4. Step 1: Building unsigned CSR info...");
    let cert_req_info = build_unsigned(subject.clone(), &spki_der)?;
    println!("   ✓ Unsigned CSR info created");

    // Encode the CSR info for signing (this is what you'd sign with your HSM/external signer)
    println!("\n5. Encoding CSR info for external signing...");
    let info_der = cert_req_info.to_der()?;
    println!("   Info DER length: {} bytes", info_der.len());
    println!("   This is what you would send to an external signer (HSM, etc.)");

    // Simulate external signing (in practice, this would be done by an HSM or external service)
    println!("\n6. Simulating external signing...");
    let signature = key.sign(&info_der);
    println!("   Ed25519 signature length: {} bytes", signature.len());
    println!("   In practice, this signature would come from your HSM/external signer");

    // Step 2: Assemble the complete CSR
    println!("\n7. Step 2: Assembling complete CSR...");
    let csr = Csr::assemble(cert_req_info, &signature)?;
    println!("   ✓ Complete CSR assembled");

    // Verify the assembled CSR
    println!("\n8. Verifying assembled CSR signature...");
    match csr.verify_signature() {
        Ok(()) => println!("   ✓ CSR signature is valid"),
        Err(e) => println!("   ✗ CSR signature invalid: {}", e),
    }

    // Compare with traditional one-step method
    println!("\n9. Comparing with traditional new() method...");
    let traditional_csr = create_csr(&key, subject.clone())?;
    
    // Both should have the same subject
    let assembled_subject = csr.subject()?;
    let traditional_subject = traditional_csr.subject()?;
    
    println!("   Two-step method CN: {}", assembled_subject.common_name);
    println!("   Traditional method CN: {}", traditional_subject.common_name);
    println!("   Subjects match: {}", assembled_subject.common_name == traditional_subject.common_name);

    // Both should have valid signatures
    match traditional_csr.verify_signature() {
        Ok(()) => println!("   ✓ Traditional CSR signature is also valid"),
        Err(e) => println!("   ✗ Traditional CSR signature invalid: {}", e),
    }

    // Export both CSRs
    println!("\n10. Exporting CSRs to PEM format...");
    let two_step_pem = csr.to_pem()?;
    let traditional_pem = traditional_csr.to_pem()?;
    
    println!("   Two-step CSR PEM length: {} chars", two_step_pem.len());
    println!("   Traditional CSR PEM length: {} chars", traditional_pem.len());

    // Save the two-step CSR to file
    std::fs::write("two_step.csr", &two_step_pem)?;
    println!("   ✓ Saved two-step CSR to: two_step.csr");

    println!("\n=== Two-Step API Demo completed successfully! ===");
    println!("\nBenefits of the two-step API:");
    println!("  1. Separation of concerns: CSR creation vs signing");
    println!("  2. HSM/external signer support: build_unsigned() + external signature + assemble()");
    println!("  3. Better testability: can test CSR structure without private keys");
    println!("  4. Backward compatibility: new() method still works as before");
    println!("\nFiles created:");
    println!("  - two_step.csr (PEM format CSR created with two-step API)");
    println!("\nClean up with: rm two_step.csr");

    Ok(())
}