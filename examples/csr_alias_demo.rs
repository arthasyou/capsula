//! CSR Type Alias Demo
//!
//! This example demonstrates the new Csr type alias for shorter code

use capsula_key::Key;
use capsula_pki::csr::{build_unsigned, create_csr, Csr, CsrSubject};
use der::Encode;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Capsula CSR Type Alias Demo ===\n");

    // Generate a key pair
    println!("1. Generating key pair...");
    let key = Key::generate()?;

    // Create subject
    let subject = CsrSubject {
        common_name: "alias.example.com".to_string(),
        organization: Some("Alias Demo Corp".to_string()),
        organizational_unit: None,
        country: Some("US".to_string()),
        state: None,
        locality: None,
    };

    println!("2. Using the new Csr type alias and module functions...");
    
    // Example 1: Using the Csr type alias with traditional create_csr() function
    let csr_traditional: Csr = create_csr(&key, subject.clone())?;
    println!("   ✓ Created CSR using Csr type alias: {}", csr_traditional.subject()?.common_name);

    // Example 2: Using module-level functions with type alias
    let spki_der = key.ed25519_spki_der()?;
    let cert_req_info = build_unsigned(subject.clone(), &spki_der)?;
    let info_der = cert_req_info.to_der()?;
    let signature = key.sign(&info_der);
    let csr_modular: Csr = Csr::assemble(cert_req_info, &signature)?;
    println!("   ✓ Created CSR using module functions: {}", csr_modular.subject()?.common_name);

    // Verify both CSRs work the same way
    csr_traditional.verify_signature()?;
    csr_modular.verify_signature()?;
    println!("   ✓ Both CSRs have valid signatures");

    println!("\n=== Type Alias Demo completed successfully! ===");
    println!("\nBenefits:");
    println!("  - Csr is shorter than CertificateSigningRequest");
    println!("  - Module-level functions: build_unsigned() and create_csr()");
    println!("  - Instance method: Csr::assemble()");
    println!("  - Type alias provides backwards compatibility");
    println!("  - Same functionality, cleaner API");

    Ok(())
}