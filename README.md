# Capsula - Secure Data Capsule & PKI Infrastructure

[English](README.md) | [中文](README-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org)

Capsula is a comprehensive cryptographic infrastructure library written in Rust, providing secure data encapsulation, PKI management, and multi-platform cryptographic operations with support for medical and institutional use cases.

## 🏗️ Project Architecture

This project uses a modular Rust workspace structure with the following components:

### Core Cryptographic Libraries
- **`capsula-crypto`** - Fundamental cryptographic primitives
  - Ed25519, RSA-2048, P256 ECDSA key management
  - Digital signatures with location and timestamp metadata
  - Hash functions (SHA-256, SHA-512)

- **`capsula-key`** - Advanced key management system
  - Multi-algorithm key generation (Ed25519, RSA, P256)
  - Secure key storage with encryption
  - Key derivation and rotation
  - PEM/DER format support

- **`capsula-pki`** - Enterprise PKI infrastructure
  - X.509 certificate management and validation
  - Certificate Authority (CA) with hierarchical support
  - Certificate Revocation List (CRL) management
  - Certificate chain building and validation
  - Medical institution certificate templates

### Data Management & APIs
- **`capsula-core`** - Secure data encapsulation engine
  - Data capsule creation and verification  
  - Policy-based access control
  - Audit trail management
  - Data integrity and authenticity verification

- **`capsula-api`** - REST API server (PKI Server)
  - Certificate Authority management endpoints
  - Certificate lifecycle operations
  - OpenAPI documentation with Swagger UI
  - Production-ready with Axum framework

### Multi-Platform Support
- **`capsula-cli`** - Command-line interface
  - Certificate and key management operations
  - Batch processing capabilities
  - Administrative tools

- **`capsula-wasm`** - WebAssembly bindings
  - Browser and Node.js compatibility
  - Key generation and cryptographic operations
  - Suitable for web applications and frontend security

- **`capsula-ffi`** - Foreign Function Interface
  - C/C++ language bindings
  - Cross-platform library integration
  - Memory-safe API design

## ✨ Key Features

### 🔐 Advanced Cryptography
- **Multi-Algorithm Support**: Ed25519, RSA-2048, P256 ECDSA with automatic algorithm detection
- **Enhanced Digital Signatures**: Context-aware signatures with location, timestamp, and metadata
- **Secure Key Storage**: Encrypted key storage with multiple export formats (PEM, DER, PKCS#8)
- **Cryptographic Hash Functions**: SHA-256, SHA-512 with verification capabilities

### 🏛️ Enterprise PKI Infrastructure
- **Full Certificate Lifecycle**: Generation, signing, validation, and revocation
- **Hierarchical Certificate Authority**: Root and intermediate CA support with delegation
- **Certificate Revocation Lists**: Complete CRL management and validation
- **Chain of Trust**: Automated certificate chain building and validation
- **REST API Server**: Production-ready PKI services with OpenAPI documentation

### 🌐 Multi-Platform Integration  
- **WebAssembly**: Browser and Node.js support for web applications
- **C/C++ FFI**: Native integration for systems programming
- **Command-line Tools**: Administrative and batch processing capabilities
- **Cross-platform**: Windows, macOS, and Linux support

### 🏥 Specialized Use Cases
- **Medical Institution Certificates**: Specialized templates for healthcare
- **Location-based Signatures**: Geographic and institutional context in signatures
- **Audit Trail Management**: Comprehensive logging and verification
- **Data Capsule System**: Secure data encapsulation with access policies

## Quick Start

### Requirements

- Rust 1.70 or higher
- Cargo (included with Rust)
- For WASM: `wasm-pack` (install via `curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh`)

### Quick Installation

```bash
git clone https://github.com/ancient/capsula.git
cd capsula
cargo build --release
```

### Running Tests

```bash
# Run all workspace tests
cargo test --workspace

# Test specific components
cargo test -p capsula-crypto    # Cryptographic primitives
cargo test -p capsula-pki       # PKI infrastructure  
cargo test -p capsula-key       # Key management
cargo test -p capsula-core      # Data capsule system
```

### Start PKI Server

```bash
# Start the REST API server (default port: 19878)
cargo run -p capsula-api

# Access Swagger UI at: http://localhost:19878/swagger-ui
# API documentation at: http://localhost:19878/api-docs/openapi.json
```

## 📋 Usage Examples

### Basic Key Generation

```rust
use capsula_key::{KeyPair, Algorithm};

// Generate Ed25519 key pair
let keypair = KeyPair::generate(Algorithm::Ed25519)?;

// Export in different formats
let private_pem = keypair.export_private_key_pem()?;
let public_pem = keypair.export_public_key_pem()?;
let private_der = keypair.export_private_key_der()?;
```

### Multi-Algorithm Support

```rust
use capsula_key::{KeyPair, Algorithm};

// Support for multiple algorithms
let ed25519_key = KeyPair::generate(Algorithm::Ed25519)?;
let rsa_key = KeyPair::generate(Algorithm::Rsa2048)?;
let p256_key = KeyPair::generate(Algorithm::P256)?;

// Automatic algorithm detection from imported keys
let imported_key = KeyPair::import_from_pem_file("my_key.pem")?;
println!("Detected algorithm: {:?}", imported_key.algorithm());
```

### Enhanced Digital Signatures

```rust
use capsula_crypto::{EccKeyPair, LocationInfo};

let keypair = EccKeyPair::generate_keypair()?;

// Create enhanced location context
let location = LocationInfo {
    latitude: Some(31.2304),
    longitude: Some(121.4737),
    address: Some("Shanghai First People's Hospital".to_string()),
    institution_id: Some("HOSPITAL_001".to_string()),
    department: Some("Cardiology Department".to_string()),
};

// Sign with rich context
let data = b"Patient medical record - ID: 12345";
let signature = keypair.sign_data(
    data,
    location,
    Some("Dr. Sarah Smith".to_string()),
    Some("Medical Diagnosis".to_string()),
)?;

// Verify with context validation
let is_valid = keypair.verify_signature(data, &signature)?;
assert!(is_valid);
```

### PKI Certificate Management

```rust
use capsula_pki::{CertificateAuthority, CAConfig, CertificateSubject};
use capsula_key::{KeyPair, Algorithm};

// Create Certificate Authority
let ca_keypair = KeyPair::generate(Algorithm::Ed25519)?;
let ca_config = CAConfig::default();
let mut ca = CertificateAuthority::new_root_ca(ca_config)?;

// Issue certificate for medical institution  
let entity_keypair = KeyPair::generate(Algorithm::Ed25519)?;
let subject = CertificateSubject::medical_institution(
    "Beijing Hospital".to_string(),
    Some("Radiology Department".to_string()),
    "Beijing".to_string(),
    "Beijing".to_string(),
    "CN".to_string(),
);

let certificate = ca.issue_certificate(
    subject,
    &entity_keypair,
    Some(365), // 1 year validity
    false,     // End entity certificate
)?;
```

### Data Capsule Operations

```rust
use capsula_core::{DataCapsule, EncryptionPolicy, AccessControl};

// Create secure data capsule
let data = b"Confidential medical data";
let policy = EncryptionPolicy::default()
    .with_access_control(AccessControl::Medical)
    .with_audit_trail(true);

let capsule = DataCapsule::create(data, policy)?;

// Verify and extract data
let verified_data = capsule.verify_and_extract()?;
assert_eq!(data, verified_data.as_slice());
```

### WebAssembly Integration

```javascript
// In browser or Node.js
import init, { KeyPair, sha256Hex } from './pkg/capsula_wasm.js';

async function cryptoDemo() {
    await init(); // Initialize WASM module
    
    // Generate key pair
    const keyPair = new KeyPair();
    const publicKeyPem = keyPair.exportPublicKeyPem();
    
    // Hash computation  
    const data = new TextEncoder().encode('Hello, Capsula!');
    const hash = sha256Hex(data);
    
    console.log('Public Key:', publicKeyPem);
    console.log('SHA256:', hash);
}
```

### C/C++ FFI Integration

```c
#include "capsula.h"

int main() {
    // Generate key with automatic algorithm selection
    CapsulaResult* key = capsula_key_generate(Curve25519);
    if (key->error_code != 0) {
        printf("Error: %s\n", key->error_message);
        return 1;
    }
    
    // Sign data
    const char* message = "Hello from C!";
    CapsulaResult* signature = capsula_sign(
        key->data, key->data_len,
        (unsigned char*)message, strlen(message)
    );
    
    printf("Signature created: %u bytes\n", signature->data_len);
    
    // Cleanup
    capsula_free_result(key);
    capsula_free_result(signature);
    return 0;
}
```

## 🚀 Running Examples

The project includes comprehensive example programs demonstrating key features:

```bash
# Core functionality demonstration
cargo run --example core_demo

# Key management and usage
cargo run --example key_usage_demo
cargo run --example key_export_demo

# Key store functionality with encryption
cargo run --example key_store_demo

# PKI Server API testing
curl http://localhost:19878/health
curl http://localhost:19878/api/v1/ca/status
```

### WebAssembly Examples

```bash
# Build WASM module for web
cd crates/capsula-wasm
wasm-pack build --target web --out-dir pkg

# Start local server and test
python3 -m http.server 8000
# Visit: http://localhost:8000/example.html
```

### FFI Examples

```bash
# Build FFI library  
cargo build --release -p capsula-ffi

# Compile and run C example
gcc -o demo demo.c \
    -I target/release/include/capsula-ffi \
    -L target/release \
    -lcapsula_ffi
./demo
```

## 📚 Documentation

Generate comprehensive API documentation:

```bash
# Generate documentation for all crates
cargo doc --open --workspace

# Generate documentation for specific crate
cargo doc -p capsula-pki --open
```

## 📊 Development Status

| Component | Status | Description |
|-----------|--------|-------------|
| **capsula-crypto** | ✅ **Stable** | Cryptographic primitives and enhanced signatures |
| **capsula-key** | ✅ **Stable** | Multi-algorithm key management system |
| **capsula-pki** | ✅ **Stable** | Complete PKI infrastructure and CA |  
| **capsula-core** | 🚧 **Active** | Data capsule system and access control |
| **capsula-api** | ✅ **Beta** | REST API server with OpenAPI support |
| **capsula-wasm** | ✅ **Stable** | WebAssembly bindings for web platforms |
| **capsula-ffi** | ✅ **Stable** | C/C++ foreign function interface |
| **capsula-cli** | 🚧 **Planning** | Command-line administrative tools |

### Recent Updates
- ✅ Enhanced multi-algorithm key support (Ed25519, RSA, P256)
- ✅ Production-ready PKI REST API server with Swagger documentation
- ✅ WebAssembly bindings with browser and Node.js compatibility
- ✅ C/C++ FFI with memory-safe API design
- 🚧 Data capsule system with policy-based access control

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