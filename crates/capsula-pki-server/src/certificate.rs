use std::{fs, path::Path, process::Command};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    error::{AppError, Result},
    settings::PkiCfg,
};

/// Simplified certificate signing request information for test PKI server
#[derive(Debug, Deserialize)]
pub struct CertificateRequest {
    /// Username for certificate identification
    pub username: String,
    /// Key algorithm for the certificate
    pub algorithm: crate::models::certificate::CertificateAlgorithm,
}

/// Certificate usage types
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum CertificateUsageType {
    /// Server certificate (TLS/SSL)
    Server,
    /// Client certificate (client authentication)
    Client,
    /// Code signing certificate
    CodeSigning,
    /// Email certificate (S/MIME)
    Email,
}

/// Issued certificate information
#[derive(Debug, Serialize)]
pub struct IssuedCertificate {
    /// Certificate serial number
    pub serial_number: String,
    /// Certificate in PEM format
    pub certificate_pem: String,
    /// Private key in PEM format
    pub private_key_pem: String,
    /// Subject DN
    pub subject: String,
    /// Issuer DN
    pub issuer: String,
    /// Not valid before
    pub not_before: DateTime<Utc>,
    /// Not valid after
    pub not_after: DateTime<Utc>,
    /// Key algorithm
    pub key_algorithm: String,
    /// Key size in bits
    pub key_size: Option<u32>,
    /// Usage type
    pub usage_type: CertificateUsageType,
    /// Issue timestamp
    pub issued_at: DateTime<Utc>,
}

/// Certificate signer using OpenSSL
pub struct CertificateSigner {
    config: PkiCfg,
}

impl CertificateSigner {
    pub fn new(config: PkiCfg) -> Self {
        Self { config }
    }

    /// Sign a certificate using the intermediate CA
    pub async fn sign_certificate(
        &self,
        request: &CertificateRequest,
        validity_days: Option<u32>,
    ) -> Result<IssuedCertificate> {
        info!("Signing certificate for user: {}", request.username);

        // Validate intermediate CA availability
        self.validate_intermediate_ca()?;

        // Generate serial number
        let serial_number = self.generate_serial_number()?;

        // Create subject DN
        let _subject = self.create_subject_dn(request);

        // Generate private key for the certificate
        let (key_path, cert_path) = self.generate_key_and_csr(request, &serial_number).await?;

        // Sign the certificate with intermediate CA
        let signed_cert_path = self
            .sign_with_intermediate_ca(&cert_path, &serial_number, request, validity_days)
            .await?;

        // Read the signed certificate (end entity only)
        let certificate_pem = fs::read_to_string(&signed_cert_path)?;

        // Read the private key
        let private_key_pem = fs::read_to_string(&key_path)?;

        // Extract certificate information (store only end entity certificate)
        let certificate_info = self.extract_certificate_info(
            &certificate_pem,
            &private_key_pem,
            request,
            validity_days,
        )?;

        // Clean up temporary files
        self.cleanup_temp_files(&[key_path, cert_path, signed_cert_path])?;

        info!(
            "Certificate signed successfully with serial: {}",
            serial_number
        );

        Ok(certificate_info)
    }

    /// Validate that intermediate CA is available and ready
    fn validate_intermediate_ca(&self) -> Result<()> {
        let intermediate_key_path = format!(
            "{}/private/intermediate.key.pem",
            self.config.intermediate_ca_path
        );
        let intermediate_cert_path = format!(
            "{}/certs/intermediate.cert.pem",
            self.config.intermediate_ca_path
        );

        if !Path::new(&intermediate_key_path).exists() {
            return Err(AppError::PkiError(format!(
                "Intermediate CA private key not found: {}",
                intermediate_key_path
            )));
        }

        if !Path::new(&intermediate_cert_path).exists() {
            return Err(AppError::PkiError(format!(
                "Intermediate CA certificate not found: {}",
                intermediate_cert_path
            )));
        }

        Ok(())
    }

    /// Generate a unique serial number for the certificate
    fn generate_serial_number(&self) -> Result<String> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AppError::Internal(format!("Time error: {}", e)))?
            .as_secs();

        let random_part: u32 = rand::random();
        Ok(format!("{:x}{:08x}", timestamp, random_part))
    }

    /// Create simplified subject DN from certificate request
    fn create_subject_dn(&self, request: &CertificateRequest) -> String {
        format!("/CN={}/O=Capsula Test PKI/OU=Test Users", request.username)
    }

    /// Generate private key and certificate signing request
    async fn generate_key_and_csr(
        &self,
        request: &CertificateRequest,
        serial_number: &str,
    ) -> Result<(String, String)> {
        let temp_dir = format!("{}/temp", self.config.data_dir);
        fs::create_dir_all(&temp_dir)?;

        let key_path = format!("{}/cert_{}.key.pem", temp_dir, serial_number);
        let csr_path = format!("{}/cert_{}.csr.pem", temp_dir, serial_number);

        let key_algorithm = "RSA"; // Use RSA by default for test PKI
        let key_size = 2048; // Use RSA 2048 as configured

        // Generate private key
        info!("Generating {} key with {} bits", key_algorithm, key_size);
        let key_output = Command::new("openssl")
            .args(&["genrsa", "-out", &key_path, &key_size.to_string()])
            .output()
            .map_err(|e| AppError::Internal(format!("Failed to generate private key: {}", e)))?;

        if !key_output.status.success() {
            return Err(AppError::Internal(format!(
                "OpenSSL key generation failed: {}",
                String::from_utf8_lossy(&key_output.stderr)
            )));
        }

        // Generate CSR
        let subject = self.create_subject_dn(request);
        info!("Generating CSR for subject: {}", subject);

        let csr_output = Command::new("openssl")
            .args(&[
                "req", "-new", "-key", &key_path, "-out", &csr_path, "-subj", &subject,
            ])
            .output()
            .map_err(|e| AppError::Internal(format!("Failed to generate CSR: {}", e)))?;

        if !csr_output.status.success() {
            return Err(AppError::Internal(format!(
                "OpenSSL CSR generation failed: {}",
                String::from_utf8_lossy(&csr_output.stderr)
            )));
        }

        Ok((key_path, csr_path))
    }

    /// Sign the CSR with intermediate CA
    async fn sign_with_intermediate_ca(
        &self,
        csr_path: &str,
        serial_number: &str,
        _request: &CertificateRequest,
        validity_days: Option<u32>,
    ) -> Result<String> {
        let temp_dir = format!("{}/temp", self.config.data_dir);
        let cert_path = format!("{}/cert_{}.cert.pem", temp_dir, serial_number);

        let intermediate_key_path = format!(
            "{}/private/intermediate.key.pem",
            self.config.intermediate_ca_path
        );
        let intermediate_cert_path = format!(
            "{}/certs/intermediate.cert.pem",
            self.config.intermediate_ca_path
        );
        let openssl_config_path = format!("{}/openssl.cnf", self.config.intermediate_ca_path);

        let cert_validity_days = validity_days.unwrap_or(self.config.default_validity_days); // Use custom or default validity
        let extensions = "usr_cert"; // Use default user certificate extensions

        info!(
            "Signing certificate with intermediate CA, validity: {} days",
            cert_validity_days
        );

        let sign_output = Command::new("openssl")
            .args(&[
                "x509",
                "-req",
                "-in",
                csr_path,
                "-CA",
                &intermediate_cert_path,
                "-CAkey",
                &intermediate_key_path,
                "-CAcreateserial",
                "-out",
                &cert_path,
                "-days",
                &cert_validity_days.to_string(),
                "-sha256",
                "-extensions",
                &extensions,
                "-extfile",
                &openssl_config_path,
            ])
            .output()
            .map_err(|e| AppError::Internal(format!("Failed to sign certificate: {}", e)))?;

        if !sign_output.status.success() {
            return Err(AppError::Internal(format!(
                "OpenSSL certificate signing failed: {}",
                String::from_utf8_lossy(&sign_output.stderr)
            )));
        }

        Ok(cert_path)
    }

    /// Get appropriate certificate extensions based on usage type
    fn get_certificate_extensions(&self, usage_type: &CertificateUsageType) -> String {
        match usage_type {
            CertificateUsageType::Server => "server_cert".to_string(),
            CertificateUsageType::Client => "usr_cert".to_string(),
            CertificateUsageType::CodeSigning => "usr_cert".to_string(), /* TODO: Add code signing extensions */
            CertificateUsageType::Email => "usr_cert".to_string(),       /* TODO: Add email
                                                                           * extensions */
        }
    }

    /// Extract certificate information from PEM
    fn extract_certificate_info(
        &self,
        certificate_pem: &str,
        private_key_pem: &str,
        request: &CertificateRequest,
        validity_days: Option<u32>,
    ) -> Result<IssuedCertificate> {
        // Extract certificate information for test PKI
        let now = Utc::now();
        let validity_days = validity_days.unwrap_or(self.config.default_validity_days);
        let not_after = now + chrono::Duration::days(validity_days as i64);

        let serial_number = self.generate_serial_number()?;
        let subject = self.create_subject_dn(request);

        // Determine key algorithm from request
        let (key_algorithm, key_size) = match &request.algorithm {
            crate::models::certificate::CertificateAlgorithm::Ed25519 => {
                ("Ed25519".to_string(), None)
            }
            crate::models::certificate::CertificateAlgorithm::RSA { key_size } => {
                (format!("RSA-{}", key_size), Some(*key_size))
            }
            crate::models::certificate::CertificateAlgorithm::ECDSA { curve } => {
                (format!("ECDSA-{}", curve), None)
            }
        };

        Ok(IssuedCertificate {
            serial_number,
            certificate_pem: certificate_pem.to_string(),
            private_key_pem: private_key_pem.to_string(),
            subject,
            issuer: "CN=Capsula Intermediate CA, O=Capsula Test PKI, OU=Intermediate CA"
                .to_string(),
            not_before: now,
            not_after,
            key_algorithm,
            key_size,
            usage_type: CertificateUsageType::Client, // Default to client certificates for test
            issued_at: now,
        })
    }

    /// Renew a certificate by creating a new one with the same subject
    pub async fn renew_certificate(
        &self,
        username: &str,
        validity_days: Option<u32>,
    ) -> Result<IssuedCertificate> {
        info!("Starting certificate renewal for user: {}", username);

        // Create a certificate request for renewal (same as new certificate)
        let request = CertificateRequest {
            username: username.to_string(),
            algorithm: crate::models::certificate::CertificateAlgorithm::Ed25519,
        };

        // Sign the new certificate with custom validity or default
        self.sign_certificate(&request, validity_days).await
    }

    /// Build certificate chain by combining end entity cert with intermediate CA cert
    fn build_certificate_chain(&self, end_entity_cert_pem: &str) -> Result<String> {
        let intermediate_cert_path = format!(
            "{}/certs/intermediate.cert.pem",
            self.config.intermediate_ca_path
        );

        if !Path::new(&intermediate_cert_path).exists() {
            warn!(
                "Intermediate CA certificate not found at {}, returning single certificate",
                intermediate_cert_path
            );
            return Ok(end_entity_cert_pem.to_string());
        }

        // Read intermediate CA certificate
        let intermediate_cert_pem = fs::read_to_string(&intermediate_cert_path).map_err(|e| {
            AppError::PkiError(format!("Failed to read intermediate CA certificate: {}", e))
        })?;

        // Build certificate chain: end entity certificate first, then intermediate CA certificate
        // This follows the standard chain order for TLS and PKI applications
        let mut chain = String::new();
        chain.push_str(end_entity_cert_pem);

        // Ensure there's a newline between certificates
        if !end_entity_cert_pem.ends_with('\n') {
            chain.push('\n');
        }

        chain.push_str(&intermediate_cert_pem);

        info!(
            "Built certificate chain with {} certificates (end entity + intermediate CA)",
            2
        );

        Ok(chain)
    }

    /// Clean up temporary files
    fn cleanup_temp_files(&self, file_paths: &[String]) -> Result<()> {
        for path in file_paths {
            if Path::new(path).exists() {
                if let Err(e) = fs::remove_file(path) {
                    warn!("Failed to clean up temporary file {}: {}", path, e);
                }
            }
        }
        Ok(())
    }
}
