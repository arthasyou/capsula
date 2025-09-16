#!/bin/bash

# Capsula PKI Initialization Script
# Creates minimal directory structure and generates CA certificates for PKI server

set -euo pipefail

# Configuration
PKI_BASE_DIR="./pki_data"
CA_DIR="$PKI_BASE_DIR/ca"
ROOT_CA_DIR="$CA_DIR/root"
INTERMEDIATE_CA_DIR="$CA_DIR/intermediate"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Create directory structure
create_directories() {
    log "Creating PKI directory structure..."
    
    mkdir -p "$PKI_BASE_DIR"
    mkdir -p "$ROOT_CA_DIR"/{private,certs}
    mkdir -p "$INTERMEDIATE_CA_DIR"/{private,certs}
    
    log "Directory structure created successfully"
}

# Set proper permissions
set_permissions() {
    log "Setting proper permissions..."
    
    # Root CA private directory - highly restricted
    chmod 700 "$ROOT_CA_DIR/private"
    
    # Intermediate CA private directory - restricted
    chmod 700 "$INTERMEDIATE_CA_DIR/private"
    
    # Public directories
    chmod 755 "$ROOT_CA_DIR/certs"
    chmod 755 "$INTERMEDIATE_CA_DIR/certs"
    
    log "Permissions set successfully"
}

# Create OpenSSL config for Root CA
create_root_ca_config() {
    log "Creating Root CA configuration..."
    
    cat > "$ROOT_CA_DIR/openssl.cnf" << 'EOF'
[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF
    
    log "Root CA configuration created"
}

# Create OpenSSL config for Intermediate CA
create_intermediate_ca_config() {
    log "Creating Intermediate CA configuration..."
    
    cat > "$INTERMEDIATE_CA_DIR/openssl.cnf" << 'EOF'
[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
EOF
    
    log "Intermediate CA configuration created"
}

# Generate Root CA private key and certificate
generate_root_ca() {
    log "Generating Root CA private key and certificate..."
    
    # Generate private key (RSA 2048)
    openssl genrsa -out "$ROOT_CA_DIR/private/ca.key.pem" 2048
    chmod 400 "$ROOT_CA_DIR/private/ca.key.pem"
    
    # Generate self-signed certificate
    openssl req -config "$ROOT_CA_DIR/openssl.cnf" \
        -key "$ROOT_CA_DIR/private/ca.key.pem" \
        -new -x509 -days 7300 -sha256 -extensions v3_ca \
        -out "$ROOT_CA_DIR/certs/ca.cert.pem" \
        -subj "/C=US/ST=California/L=San Francisco/O=Capsula PKI/OU=Root CA/CN=Capsula Root CA"
    
    chmod 444 "$ROOT_CA_DIR/certs/ca.cert.pem"
    
    log "Root CA generated successfully"
}

# Generate Intermediate CA private key and certificate
generate_intermediate_ca() {
    log "Generating Intermediate CA private key and certificate..."
    
    # Generate private key
    openssl genrsa -out "$INTERMEDIATE_CA_DIR/private/intermediate.key.pem" 2048
    chmod 400 "$INTERMEDIATE_CA_DIR/private/intermediate.key.pem"
    
    # Generate certificate request
    openssl req -config "$INTERMEDIATE_CA_DIR/openssl.cnf" \
        -new -sha256 \
        -key "$INTERMEDIATE_CA_DIR/private/intermediate.key.pem" \
        -out "$INTERMEDIATE_CA_DIR/certs/intermediate.csr.pem" \
        -subj "/C=US/ST=California/L=San Francisco/O=Capsula PKI/OU=Intermediate CA/CN=Capsula Intermediate CA"
    
    # Sign with Root CA
    openssl x509 -req -in "$INTERMEDIATE_CA_DIR/certs/intermediate.csr.pem" \
        -CA "$ROOT_CA_DIR/certs/ca.cert.pem" \
        -CAkey "$ROOT_CA_DIR/private/ca.key.pem" \
        -CAcreateserial \
        -out "$INTERMEDIATE_CA_DIR/certs/intermediate.cert.pem" \
        -days 3650 -sha256 \
        -extensions v3_intermediate_ca \
        -extfile "$ROOT_CA_DIR/openssl.cnf"
    
    chmod 444 "$INTERMEDIATE_CA_DIR/certs/intermediate.cert.pem"
    
    # Create certificate chain
    cat "$INTERMEDIATE_CA_DIR/certs/intermediate.cert.pem" \
        "$ROOT_CA_DIR/certs/ca.cert.pem" > \
        "$INTERMEDIATE_CA_DIR/certs/ca-chain.cert.pem"
    
    chmod 444 "$INTERMEDIATE_CA_DIR/certs/ca-chain.cert.pem"
    
    # Clean up CSR
    rm "$INTERMEDIATE_CA_DIR/certs/intermediate.csr.pem"
    
    log "Intermediate CA generated successfully"
}

# Verify certificates
verify_certificates() {
    log "Verifying certificates..."
    
    # Verify Intermediate CA certificate against Root CA
    if openssl verify -CAfile "$ROOT_CA_DIR/certs/ca.cert.pem" \
        "$INTERMEDIATE_CA_DIR/certs/intermediate.cert.pem" > /dev/null 2>&1; then
        log "Certificate verification successful"
    else
        error "Certificate verification failed"
        exit 1
    fi
}

# Create initialization marker
create_init_marker() {
    cat > "$PKI_BASE_DIR/.initialized" << EOF
PKI initialization completed at $(date)
Root CA: $(openssl x509 -noout -subject -in "$ROOT_CA_DIR/certs/ca.cert.pem")
Intermediate CA: $(openssl x509 -noout -subject -in "$INTERMEDIATE_CA_DIR/certs/intermediate.cert.pem")
EOF
    
    log "Initialization completed successfully"
}

# Main function
main() {
    log "Starting Capsula PKI initialization..."
    
    # Check if already initialized
    if [[ -f "$PKI_BASE_DIR/.initialized" ]]; then
        warn "PKI already initialized. Use --force to reinitialize."
        if [[ "${1:-}" != "--force" ]]; then
            exit 1
        fi
        log "Force flag detected, proceeding with reinitialization..."
        rm -rf "$PKI_BASE_DIR"
    fi
    
    create_directories
    set_permissions
    create_root_ca_config
    create_intermediate_ca_config
    generate_root_ca
    generate_intermediate_ca
    verify_certificates
    create_init_marker
    
    log "Root CA certificate: $ROOT_CA_DIR/certs/ca.cert.pem"
    log "Intermediate CA certificate: $INTERMEDIATE_CA_DIR/certs/intermediate.cert.pem"
    log "Certificate chain: $INTERMEDIATE_CA_DIR/certs/ca-chain.cert.pem"
}

# Run main function with all arguments
main "$@"