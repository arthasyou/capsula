# Capsula - Data Capsule Encryption Library

[English](README.md) | [中文](README-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)

Capsula is a data capsule encryption library written in Rust, providing a complete cryptographic infrastructure including key management, digital signatures, and PKI infrastructure.

## Project Structure

This project uses a Rust workspace structure with the following crates:

- **`capsula-crypto`** - Basic cryptographic primitives library
  - Ed25519 key pair generation and management
  - Digital signatures (with location info and timestamps)
  - Hash functions (SHA-256, SHA-512)

- **`capsula-pki`** - PKI infrastructure library
  - X.509 certificate management
  - Certificate Authority (CA)
  - Certificate Revocation List (CRL)
  - Certificate chain validation
  - Certificate storage

- **`capsula-core`** - Core functionality library (in development)
  - Data encryption and decryption
  - Access control
  - Data integrity verification

- **`capsula-api`** - API service library (in development)
  - RESTful API interface
  - Authentication and authorization
  - Request handling

- **`capsula-cli`** - Command-line tool (in development)
  - User interface
  - Command implementations

## Features

### 🔐 Cryptographic Features
- **Ed25519 Key Management**: Secure key generation, import/export (PEM, DER, HEX formats)
- **Digital Signatures**: Support for signatures with location information and timestamps
- **Hash Algorithms**: SHA-256 and SHA-512 support

### 🏛️ PKI Infrastructure
- **X.509 Certificates**: Create, sign, and verify certificates
- **Certificate Authority**: Complete CA functionality, supporting root and intermediate CAs
- **Certificate Revocation**: CRL management and validation
- **Certificate Chain Validation**: Complete certificate chain building and validation

### 🏥 Medical Scenario Support
- Support for medical institution certificates
- Location-based signatures (hospital, department information)
- Audit trails

## Quick Start

### Requirements

- Rust 1.70 or higher
- Cargo

### Build the Project

```bash
git clone https://github.com/ancient/capsula.git
cd capsula
cargo build --release
```

### Run Tests

```bash
# Run all tests in the workspace
cargo test --workspace

# Run tests for a specific crate
cargo test -p capsula-crypto
cargo test -p capsula-pki
```

## Usage Examples

### Generate Key Pair

```rust
use capsula_crypto::EccKeyPair;

// Generate a new Ed25519 key pair
let keypair = EccKeyPair::generate_keypair()?;

// Export private key in PEM format
let private_key_pem = keypair.export_private_key()?;

// Export public key
let public_key_bytes = keypair.get_public_key_bytes();
```

### Digital Signature

```rust
use capsula_crypto::{EccKeyPair, LocationInfo};

let keypair = EccKeyPair::generate_keypair()?;

// Create location information
let location = LocationInfo {
    latitude: Some(31.2304),
    longitude: Some(121.4737),
    address: Some("Shanghai First People's Hospital".to_string()),
    institution_id: Some("HOSPITAL_001".to_string()),
    department: Some("Cardiology".to_string()),
};

// Sign data
let data = b"patient medical record";
let signature = keypair.sign_data(
    data,
    location,
    Some("Dr. Smith".to_string()),
    Some("Diagnosis Record".to_string()),
)?;

// Verify signature
let is_valid = keypair.verify_signature(data, &signature)?;
```

### Create Certificate

```rust
use capsula_crypto::EccKeyPair;
use capsula_pki::{create_certificate, CertificateSubject};

let keypair = EccKeyPair::generate_keypair()?;

// Create certificate subject
let subject = CertificateSubject::medical_institution(
    "Shanghai First People's Hospital".to_string(),
    Some("Cardiology".to_string()),
    "Shanghai".to_string(),
    "Shanghai".to_string(),
    "CN".to_string(),
);

// Create certificate (valid for 365 days)
let cert = create_certificate(&keypair, subject, None, 365, false)?;
```

### Create CA and Issue Certificates

```rust
use capsula_pki::{CertificateAuthority, CAConfig};

// Create root CA
let ca_config = CAConfig::default();
let mut root_ca = CertificateAuthority::new_root_ca(ca_config)?;

// Issue certificate for end entity
let entity_keypair = EccKeyPair::generate_keypair()?;
let entity_subject = CertificateSubject::new("Medical Device-001".to_string());

let entity_cert = root_ca.issue_certificate(
    entity_subject,
    &entity_keypair,
    Some(365),  // Valid for 365 days
    false,      // Not a CA certificate
)?;
```

## Running Examples

The project includes several example programs demonstrating different features:

```bash
# Basic cryptography example
cargo run --example basic_crypto

# PKI infrastructure example
cargo run --example pki_demo

# Comprehensive demonstration
cargo run --example full_demo
```

## API Documentation

Generate detailed API documentation with:

```bash
cargo doc --open
```

## Project Status

- ✅ **capsula-crypto** - Complete
- ✅ **capsula-pki** - Complete
- 🚧 **capsula-core** - In development
- 🚧 **capsula-api** - In development
- 🚧 **capsula-cli** - In development

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

- Project Homepage: [https://github.com/ancient/capsula](https://github.com/ancient/capsula)
- Issue Tracker: [Issues](https://github.com/ancient/capsula/issues)

## Acknowledgments

Thanks to the following open-source projects:

- [ed25519-dalek](https://github.com/dalek-cryptography/ed25519-dalek) - Ed25519 signature algorithm implementation
- [rcgen](https://github.com/rustls/rcgen) - X.509 certificate generation
- [x509-cert](https://github.com/RustCrypto/x509-cert) - X.509 certificate parsing

---

**Note**: This project is under active development and APIs may change. Please evaluate carefully before using in production environments.