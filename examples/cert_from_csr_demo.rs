//! Certificate from CSR Demo
//!
//! This example demonstrates how to generate X.509 certificates from CSRs using the new cert API.

use capsula_key::Key;
use capsula_pki::cert::{create_certificate, create_self_signed_certificate, CertificateInfo, CertificateSubject, X509Certificate};
use capsula_pki::csr::{create_csr, CsrSubject};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== Certificate from CSR Demo ===\n");

    // 1. Create a self-signed CA certificate
    println!("1. Creating self-signed CA certificate...");
    let ca_key = Key::generate()?;
    
    let ca_subject = CertificateSubject {
        common_name: "Capsula Root CA".to_string(),
        organization: Some("Capsula Corp".to_string()),
        organizational_unit: Some("PKI Division".to_string()),
        country: Some("US".to_string()),
        state: Some("California".to_string()),
        locality: Some("San Francisco".to_string()),
    };

    let ca_cert_info = CertificateInfo {
        subject: ca_subject.clone(),
        validity_seconds: 365 * 24 * 60 * 60, // 1 year
        serial_number: Some(vec![1]),
        is_ca: true,
        key_usage: vec!["digitalSignature".to_string(), "keyCertSign".to_string()],
    };

    let ca_cert = create_self_signed_certificate(&ca_key, ca_subject.clone(), ca_cert_info)?;
    println!("   ✓ CA certificate created");
    println!("   CA Subject: {}", ca_cert.subject()?.common_name);
    println!("   Serial: {:02x?}", ca_cert.serial_number());
    println!("   Valid: {}", ca_cert.is_currently_valid());

    // 2. Create a server key and CSR
    println!("\n2. Creating server key and CSR...");
    let server_key = Key::generate()?;
    
    let server_subject = CsrSubject {
        common_name: "server.example.com".to_string(),
        organization: Some("Example Corp".to_string()),
        organizational_unit: Some("IT Department".to_string()),
        country: Some("US".to_string()),
        state: Some("California".to_string()),
        locality: Some("San Jose".to_string()),
    };

    let server_csr = create_csr(&server_key, server_subject.clone())?;
    println!("   ✓ Server CSR created");
    println!("   CSR Subject: {}", server_csr.subject()?.common_name);

    // Verify CSR signature
    server_csr.verify_signature()?;
    println!("   ✓ CSR signature verified");

    // 3. Sign the CSR with the CA to create a server certificate
    println!("\n3. Signing CSR to create server certificate...");
    
    let server_cert_info = CertificateInfo {
        subject: server_subject.clone(),
        validity_seconds: 30 * 24 * 60 * 60, // 30 days
        serial_number: Some(vec![2, 0, 0, 1]),
        is_ca: false,
        key_usage: vec!["digitalSignature".to_string(), "keyEncipherment".to_string()],
    };

    let server_cert = create_certificate(&server_csr, &ca_key, &ca_cert, server_cert_info)?;
    println!("   ✓ Server certificate created");
    println!("   Server Subject: {}", server_cert.subject()?.common_name);
    println!("   Server Issuer: {}", server_cert.issuer()?.common_name);
    println!("   Serial: {:02x?}", server_cert.serial_number());
    
    // 4. Verify server certificate signature using CA public key
    println!("\n4. Verifying server certificate signature...");
    let ca_public_key = ca_key.ed25519_public_key_bytes();
    server_cert.verify_signature(&ca_public_key)?;
    println!("   ✓ Server certificate signature verified with CA key");

    // 5. Export certificates to PEM format
    println!("\n5. Exporting certificates to PEM format...");
    let ca_pem = ca_cert.to_pem()?;
    let server_pem = server_cert.to_pem()?;
    
    println!("   CA Certificate PEM (first 100 chars):");
    println!("   {}", &ca_pem[..100.min(ca_pem.len())]);
    
    println!("   Server Certificate PEM (first 100 chars):");
    println!("   {}", &server_pem[..100.min(server_pem.len())]);

    // 6. Save certificates to files
    println!("\n6. Saving certificates to files...");
    ca_cert.save_pem_file("ca_cert.pem")?;
    server_cert.save_pem_file("server_cert.pem")?;
    println!("   ✓ Saved: ca_cert.pem");
    println!("   ✓ Saved: server_cert.pem");

    // 7. Test loading certificates from files
    println!("\n7. Loading certificates from files...");
    let loaded_ca = X509Certificate::load_pem_file("ca_cert.pem")?;
    let loaded_server = X509Certificate::load_pem_file("server_cert.pem")?;
    
    // Verify loaded certificates match original ones
    assert_eq!(loaded_ca.to_der()?, ca_cert.to_der()?);
    assert_eq!(loaded_server.to_der()?, server_cert.to_der()?);
    println!("   ✓ Loaded certificates match originals");

    // 8. Certificate chain verification simulation
    println!("\n8. Certificate chain verification simulation...");
    
    // Verify server cert was signed by CA
    let ca_public_key_from_cert = loaded_ca.ed25519_public_key_bytes()?;
    loaded_server.verify_signature(&ca_public_key_from_cert)?;
    println!("   ✓ Server certificate verified against loaded CA certificate");
    
    // Verify CA is self-signed
    loaded_ca.verify_self_signed()?;
    println!("   ✓ CA certificate is properly self-signed");

    // 9. Display certificate validity information
    println!("\n9. Certificate validity information...");
    println!("   CA Certificate valid: {}", loaded_ca.is_currently_valid());
    println!("   Server Certificate valid: {}", loaded_server.is_currently_valid());
    
    // Get public keys for comparison
    let ca_public_key_extracted = loaded_ca.ed25519_public_key_bytes()?;
    let server_public_key_extracted = loaded_server.ed25519_public_key_bytes()?;
    let original_ca_public_key = ca_key.ed25519_public_key_bytes();
    let original_server_public_key = server_key.ed25519_public_key_bytes();
    
    assert_eq!(ca_public_key_extracted, original_ca_public_key);
    assert_eq!(server_public_key_extracted, original_server_public_key);
    println!("   ✓ Extracted public keys match original keys");

    println!("\n=== Demo completed successfully! ===");
    println!("\nKey Benefits of CSR-based Certificate Generation:");
    println!("  1. Standard X.509 certificate creation from CSRs");
    println!("  2. Proper CA certificate hierarchy support");
    println!("  3. Ed25519 signature algorithm support");
    println!("  4. PEM/DER format import/export");
    println!("  5. Certificate validity checking");
    println!("  6. Signature verification with issuer keys");
    println!("  7. File I/O operations for certificate storage");
    
    println!("\nFiles created:");
    println!("  - ca_cert.pem (CA certificate)");
    println!("  - server_cert.pem (Server certificate)");
    println!("\nClean up with: rm ca_cert.pem server_cert.pem");

    Ok(())
}