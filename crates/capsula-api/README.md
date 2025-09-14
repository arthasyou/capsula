# Capsula PKI Server

A REST API server for Certificate Authority and PKI management, built with Axum and using the Capsula PKI crate.

## Features

- **Certificate Authority Management**
  - Initialize CA
  - Get CA status and certificate
  - Health check endpoints

- **Certificate Management**
  - Generate new certificates with RSA, P256, or Ed25519 keys
  - Retrieve certificates by ID
  - List certificates with filtering
  - Revoke certificates with reason codes

- **OpenAPI Documentation**
  - Swagger UI at `/swagger-ui`
  - API documentation at `/api-docs/openapi.json`

## Configuration

Configure the server using `config/services.toml`:

```toml
[http]
port = 19878

[pki]
ca_storage_path = "./storage/ca"
cert_storage_path = "./storage/certificates"
default_validity_days = 365
```

## API Endpoints

### Certificate Authority
- `GET /api/v1/ca/status` - Get CA status
- `GET /api/v1/ca/certificate` - Get CA certificate
- `POST /api/v1/ca/init` - Initialize CA
- `GET /health` - Health check

### Certificate Management
- `POST /api/v1/certificates` - Generate new certificate
- `GET /api/v1/certificates/{id}` - Get certificate by ID
- `GET /api/v1/certificates` - List certificates
- `POST /api/v1/certificates/{id}/revoke` - Revoke certificate

## Running the Server

```bash
cargo run --package capsula-pki-server
```

The server will start on the configured port (default: 19878) and the Swagger UI will be available at `http://localhost:19878/swagger-ui`.

## Development Status

This is a work in progress. Current implementation includes:

- ✅ REST API structure and routing
- ✅ OpenAPI documentation
- ✅ Request/response models
- 🚧 Certificate generation (using capsula-pki)
- 🚧 CA initialization and management
- 🚧 Certificate storage
- 🚧 Certificate revocation and CRL

## Dependencies

- `capsula-pki` - PKI operations and certificate management
- `capsula-key` - Cryptographic key operations
- `capsula-crypto` - Cryptographic primitives
- `axum` - Web framework
- `utoipa` - OpenAPI documentation generation