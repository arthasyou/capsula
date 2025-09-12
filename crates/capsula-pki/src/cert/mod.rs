//! Certificate module
//!
//! This module provides X.509 certificate functionality using CSR-based generation.

use std::time::{Duration, SystemTime};

use capsula_key::Key;
use der::{Decode, Encode};
use getrandom;
use pkcs8::spki::AlgorithmIdentifierOwned;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use x509_cert::{
    certificate::{Certificate as X509CertificateInner, TbsCertificate, Version},
    ext::{pkix::KeyUsage, Extension, Extensions},
    serial_number::SerialNumber,
    time::{Time, Validity},
};

use crate::{
    csr::{Csr, CsrSubject},
    error::PkiError,
    Result,
};

/// X.509 Certificate with Capsula Key integration
#[derive(Debug, Clone)]
pub struct X509Certificate {
    inner: X509CertificateInner,
}

/// Certificate subject information (same as CsrSubject for compatibility)
pub type CertificateSubject = CsrSubject;

/// Certificate information for creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Subject information
    pub subject: CertificateSubject,
    /// Validity duration in seconds (default: 1 year)
    pub validity_seconds: u64,
    /// Serial number (optional, will be generated if None)
    pub serial_number: Option<Vec<u8>>,
    /// Is CA certificate
    pub is_ca: bool,
    /// Key usage extensions
    pub key_usage: Vec<String>,
}

impl Default for CertificateInfo {
    fn default() -> Self {
        Self {
            subject: CertificateSubject {
                common_name: String::new(),
                organization: None,
                organizational_unit: None,
                country: None,
                state: None,
                locality: None,
            },
            validity_seconds: 365 * 24 * 60 * 60, // 1 year
            serial_number: None,
            is_ca: false,
            key_usage: vec![
                "digitalSignature".to_string(),
                "keyEncipherment".to_string(),
            ],
        }
    }
}

/// Create a certificate from a CSR
///
/// This function signs a CSR to create a certificate using the issuer's key.
///
/// # Arguments
/// * `csr` - The Certificate Signing Request to be signed
/// * `issuer_key` - The private key of the certificate issuer
/// * `ca_cert` - The CA certificate to extract issuer DN from
/// * `cert_info` - Certificate configuration information
///
/// # Returns
/// Returns a signed X.509 certificate
pub fn create_certificate(
    csr: &Csr,
    issuer_key: &Key,
    ca_cert: &X509Certificate,
    cert_info: CertificateInfo,
) -> Result<X509Certificate> {
    // Get subject and SPKI directly from CSR (no rebuilding)
    let csr_der = csr.to_der()?;
    let parsed_csr = x509_cert::request::CertReq::from_der(&csr_der)
        .map_err(|e| PkiError::CertError(format!("Failed to parse CSR DER: {}", e)))?;

    let subject_name = parsed_csr.info.subject.clone();
    let public_key_info = parsed_csr.info.public_key.clone();

    // Get issuer DN from CA certificate
    let issuer_name = ca_cert.inner.tbs_certificate.subject.clone();

    // Get CA's SKI for AKI extension
    let ca_ski = extract_subject_key_identifier(ca_cert)?;

    create_certificate_internal(
        subject_name,
        issuer_name,
        public_key_info,
        issuer_key,
        cert_info,
        Some(ca_ski),
    )
}

/// Create a self-signed certificate from a key and subject
pub fn create_self_signed_certificate(
    key: &Key,
    subject: CertificateSubject,
    cert_info: CertificateInfo,
) -> Result<X509Certificate> {
    // Create a CSR first
    let csr = crate::csr::create_csr(key, subject.clone())?;

    // For self-signed certificates, we need special logic since there's no CA cert yet
    create_self_signed_certificate_internal(&csr, key, cert_info)
}

/// Sign a CSR to create a certificate (alias for create_certificate)
pub fn sign_certificate(
    csr: &Csr,
    issuer_key: &Key,
    ca_cert: &X509Certificate,
    cert_info: CertificateInfo,
) -> Result<X509Certificate> {
    create_certificate(csr, issuer_key, ca_cert, cert_info)
}

/// Internal function to create self-signed certificate (special case)
fn create_self_signed_certificate_internal(
    csr: &Csr,
    key: &Key,
    cert_info: CertificateInfo,
) -> Result<X509Certificate> {
    // Get subject and SPKI directly from CSR (no rebuilding)
    let csr_der = csr.to_der()?;
    let parsed_csr = x509_cert::request::CertReq::from_der(&csr_der)
        .map_err(|e| PkiError::CertError(format!("Failed to parse CSR DER: {}", e)))?;

    let subject_name = parsed_csr.info.subject.clone();
    let public_key_info = parsed_csr.info.public_key.clone();

    // For self-signed, issuer = subject
    let issuer_name = subject_name.clone();

    // For self-signed, no CA SKI (will use own SKI for AKI)
    create_certificate_internal(
        subject_name,
        issuer_name,
        public_key_info,
        key,
        cert_info,
        None, // No CA SKI for self-signed
    )
}


impl X509Certificate {
    /// Parse certificate from PEM format
    pub fn from_pem(pem: &str) -> Result<Self> {
        let der = pem::parse(pem)
            .map_err(|e| PkiError::CertError(format!("Failed to parse PEM: {}", e)))?;

        if der.tag() != "CERTIFICATE" {
            return Err(PkiError::CertError(
                "Invalid PEM tag, expected CERTIFICATE".to_string(),
            ));
        }

        Self::from_der(der.contents())
    }

    /// Parse certificate from DER format
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let inner = X509CertificateInner::from_der(der)
            .map_err(|e| PkiError::CertError(format!("Failed to parse DER: {}", e)))?;

        Ok(Self { inner })
    }

    /// Export certificate to PEM format
    pub fn to_pem(&self) -> Result<String> {
        let der = self.to_der()?;
        let pem = pem::encode(&pem::Pem::new("CERTIFICATE", der));
        Ok(pem)
    }

    /// Export certificate to DER format
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| PkiError::CertError(format!("Failed to encode DER: {}", e)))
    }

    /// Get the subject of the certificate
    pub fn subject(&self) -> Result<CertificateSubject> {
        Csr::parse_distinguished_name(&self.inner.tbs_certificate.subject)
    }

    /// Get the issuer of the certificate
    pub fn issuer(&self) -> Result<CertificateSubject> {
        Csr::parse_distinguished_name(&self.inner.tbs_certificate.issuer)
    }

    /// Extract Ed25519 public key bytes from certificate
    pub fn ed25519_public_key_bytes(&self) -> Result<[u8; 32]> {
        let spki = &self.inner.tbs_certificate.subject_public_key_info;

        // Verify this is an Ed25519 key
        if spki.algorithm.oid != const_oid::db::rfc8410::ID_ED_25519 {
            return Err(PkiError::CertError("Not an Ed25519 public key".to_string()));
        }

        // Get the public key bytes
        let key_bytes = spki.subject_public_key.raw_bytes();
        if key_bytes.len() != 32 {
            return Err(PkiError::CertError(format!(
                "Invalid Ed25519 public key length: {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key_bytes);
        Ok(key_array)
    }

    /// Verify certificate signature
    pub fn verify_signature(&self, issuer_public_key: &[u8; 32]) -> Result<()> {
        // Encode the TbsCertificate for verification
        let tbs_der = self.inner.tbs_certificate.to_der().map_err(|e| {
            PkiError::CertError(format!("Failed to encode TBS for verification: {}", e))
        })?;

        // Get signature bytes
        let signature = self.inner.signature.raw_bytes();
        if signature.len() != 64 {
            return Err(PkiError::CertError(
                "Invalid signature length for Ed25519".to_string(),
            ));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature);

        // Verify using the issuer's public key
        if capsula_key::verify(issuer_public_key, &tbs_der, &sig_array) {
            Ok(())
        } else {
            Err(PkiError::CertError(
                "Certificate signature verification failed".to_string(),
            ))
        }
    }

    /// Verify self-signed certificate
    pub fn verify_self_signed(&self) -> Result<()> {
        let public_key_bytes = self.ed25519_public_key_bytes()?;
        self.verify_signature(&public_key_bytes)
    }

    /// Check if certificate is valid at given time
    pub fn is_valid_at(&self, time: SystemTime) -> bool {
        let validity = &self.inner.tbs_certificate.validity;

        let not_before = match &validity.not_before {
            Time::GeneralTime(gt) => gt.to_system_time(),
            _ => return false,
        };

        let not_after = match &validity.not_after {
            Time::GeneralTime(gt) => gt.to_system_time(),
            _ => return false,
        };

        time >= not_before && time <= not_after
    }

    /// Check if certificate is currently valid
    pub fn is_currently_valid(&self) -> bool {
        self.is_valid_at(SystemTime::now())
    }

    /// Get certificate serial number
    pub fn serial_number(&self) -> Vec<u8> {
        self.inner.tbs_certificate.serial_number.as_bytes().to_vec()
    }

    // ========================================================================
    // File I/O Operations
    // ========================================================================

    /// Save certificate to PEM file
    pub fn save_pem_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let pem = self.to_pem()?;
        std::fs::write(path, pem).map_err(PkiError::IoError)
    }

    /// Load certificate from PEM file
    pub fn load_pem_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let pem = std::fs::read_to_string(path).map_err(PkiError::IoError)?;
        Self::from_pem(&pem)
    }

    /// Save certificate to DER file
    pub fn save_der_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let der = self.to_der()?;
        std::fs::write(path, der).map_err(PkiError::IoError)
    }

    /// Load certificate from DER file
    pub fn load_der_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let der = std::fs::read(path).map_err(PkiError::IoError)?;
        Self::from_der(&der)
    }
}

/// Internal function to create certificate with common logic
/// 
/// # Arguments
/// * `subject_name` - Subject DN from CSR
/// * `issuer_name` - Issuer DN (from CA cert or same as subject for self-signed)
/// * `public_key_info` - SPKI from CSR
/// * `signing_key` - Key to sign the certificate
/// * `cert_info` - Certificate configuration
/// * `ca_ski` - CA's SKI for AKI extension (None for self-signed)
fn create_certificate_internal(
    subject_name: x509_cert::name::Name,
    issuer_name: x509_cert::name::Name,
    public_key_info: pkcs8::spki::SubjectPublicKeyInfoOwned,
    signing_key: &Key,
    cert_info: CertificateInfo,
    ca_ski: Option<Vec<u8>>,
) -> Result<X509Certificate> {
    // Generate serial number if not provided
    let serial_number = if let Some(serial) = cert_info.serial_number {
        SerialNumber::new(&serial)
            .map_err(|e| PkiError::CertError(format!("Invalid serial number: {}", e)))?
    } else {
        // Generate random serial number if not provided
        let mut random_bytes = [0u8; 16];
        getrandom::fill(&mut random_bytes)
            .map_err(|e| PkiError::CertError(format!("Failed to generate random bytes: {}", e)))?;
        SerialNumber::new(&random_bytes)
            .map_err(|e| PkiError::CertError(format!("Failed to create serial number: {}", e)))?
    };

    // Set validity period
    let now = SystemTime::now();
    let not_before = Time::try_from(now)
        .map_err(|e| PkiError::CertError(format!("Failed to create not_before time: {}", e)))?;

    let not_after_time = now
        + Duration::from_secs(cert_info.validity_seconds)
            .min(Duration::from_secs(u32::MAX as u64));
    let not_after = Time::try_from(not_after_time)
        .map_err(|e| PkiError::CertError(format!("Failed to create not_after time: {}", e)))?;

    let validity = Validity {
        not_before,
        not_after,
    };

    // Create extensions
    let mut extensions = Vec::new();

    // 1. Basic Constraints extension
    let basic_constraints = x509_cert::ext::pkix::BasicConstraints {
        ca: cert_info.is_ca,
        path_len_constraint: None,
    };

    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
        critical: true,
        extn_value: der::asn1::OctetString::new(basic_constraints.to_der().map_err(|e| {
            PkiError::CertError(format!("Failed to encode basic constraints: {}", e))
        })?)
        .map_err(|e| PkiError::CertError(format!("Failed to create extension: {}", e)))?,
    });

    // 2. Key Usage extension
    if !cert_info.key_usage.is_empty() {
        let mut key_usage_flags: Option<der::flagset::FlagSet<x509_cert::ext::pkix::KeyUsages>> =
            None;

        for usage in &cert_info.key_usage {
            let flag = match usage.as_str() {
                "digitalSignature" => x509_cert::ext::pkix::KeyUsages::DigitalSignature,
                "keyEncipherment" => x509_cert::ext::pkix::KeyUsages::KeyEncipherment,
                "keyCertSign" => x509_cert::ext::pkix::KeyUsages::KeyCertSign,
                "cRLSign" => x509_cert::ext::pkix::KeyUsages::CRLSign,
                _ => continue, // Ignore unknown key usage
            };

            key_usage_flags = Some(key_usage_flags.map_or(flag.into(), |existing| existing | flag));
        }

        // Only add extension if we have valid key usage bits
        if let Some(flags) = key_usage_flags {
            let key_usage_ext = KeyUsage(flags);
            extensions.push(Extension {
                extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
                critical: true,
                extn_value: der::asn1::OctetString::new(key_usage_ext.to_der().map_err(|e| {
                    PkiError::CertError(format!("Failed to encode key usage: {}", e))
                })?)
                .map_err(|e| {
                    PkiError::CertError(format!("Failed to create key usage extension: {}", e))
                })?,
            });
        }
    }

    // 3. Subject Key Identifier (SKI) - SHA-1(SPKI DER)
    let spki_der = public_key_info
        .to_der()
        .map_err(|e| PkiError::CertError(format!("Failed to encode SPKI: {}", e)))?;
    let mut sha1 = Sha1::new();
    sha1.update(&spki_der);
    let ski = sha1.finalize().to_vec();

    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
        critical: false,
        extn_value: der::asn1::OctetString::new(ski.clone())
            .map_err(|e| PkiError::CertError(format!("Failed to create SKI extension: {}", e)))?,
    });

    // 4. Authority Key Identifier (AKI)
    let aki_ski = ca_ski.unwrap_or_else(|| ski.clone()); // Use CA's SKI or self SKI for self-signed
    let aki_ext = x509_cert::ext::pkix::AuthorityKeyIdentifier {
        key_identifier: Some(der::asn1::OctetString::new(aki_ski).map_err(|e| {
            PkiError::CertError(format!("Failed to create AKI key identifier: {}", e))
        })?),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    };

    extensions.push(Extension {
        extn_id: const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
        critical: false,
        extn_value: der::asn1::OctetString::new(
            aki_ext
                .to_der()
                .map_err(|e| PkiError::CertError(format!("Failed to encode AKI: {}", e)))?,
        )
        .map_err(|e| PkiError::CertError(format!("Failed to create AKI extension: {}", e)))?,
    });

    let extensions_vec = Some(Extensions::from(extensions));

    // Create TbsCertificate
    let tbs_certificate = TbsCertificate {
        version: Version::V3,
        serial_number,
        signature: AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc8410::ID_ED_25519,
            parameters: None,
        },
        issuer: issuer_name,
        validity,
        subject: subject_name,
        subject_public_key_info: public_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: extensions_vec,
    };

    // Encode TbsCertificate for signing
    let tbs_der = tbs_certificate
        .to_der()
        .map_err(|e| PkiError::CertError(format!("Failed to encode TbsCertificate: {}", e)))?;

    // Sign the certificate
    let signature_bytes = signing_key.sign(&tbs_der);

    // Create signature algorithm identifier
    let signature_algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc8410::ID_ED_25519,
        parameters: None,
    };

    // Create the complete certificate
    let signature_bits = der::asn1::BitString::from_bytes(&signature_bytes)
        .map_err(|e| PkiError::CertError(format!("Failed to create signature bits: {}", e)))?;

    let certificate = X509CertificateInner {
        tbs_certificate,
        signature_algorithm,
        signature: signature_bits,
    };

    Ok(X509Certificate {
        inner: certificate,
    })
}

// Helper function to extract Subject Key Identifier from a certificate
fn extract_subject_key_identifier(cert: &X509Certificate) -> Result<Vec<u8>> {
    if let Some(extensions) = &cert.inner.tbs_certificate.extensions {
        for ext in extensions.iter() {
            if ext.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER {
                // The SKI extension value is a single OCTET STRING
                return Ok(ext.extn_value.as_bytes().to_vec());
            }
        }
    }

    // If no SKI extension found, compute it from the certificate's SPKI
    let spki_der = cert
        .inner
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| PkiError::CertError(format!("Failed to encode certificate SPKI: {}", e)))?;
    let mut sha1 = Sha1::new();
    sha1.update(&spki_der);
    Ok(sha1.finalize().to_vec())
}

// Convenience functions (aliases for backward compatibility)

/// Import certificate from PEM (alias for from_pem)
pub fn import_certificate(pem: &str) -> Result<X509Certificate> {
    X509Certificate::from_pem(pem)
}

/// Export certificate to PEM (alias for to_pem)
pub fn export_certificate(cert: &X509Certificate) -> Result<String> {
    cert.to_pem()
}

/// Parse certificate from PEM (alias for from_pem)
pub fn parse_certificate(pem: &str) -> Result<X509Certificate> {
    X509Certificate::from_pem(pem)
}

/// Verify certificate signature (convenience function)
pub fn verify_certificate(cert: &X509Certificate, issuer_public_key: &[u8; 32]) -> Result<()> {
    cert.verify_signature(issuer_public_key)
}

#[cfg(test)]
mod tests {
    use capsula_key::Key;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_create_self_signed_certificate() {
        let key = Key::generate().unwrap();

        let subject = CertificateSubject {
            common_name: "test.example.com".to_string(),
            organization: Some("Test Org".to_string()),
            organizational_unit: None,
            country: Some("US".to_string()),
            state: Some("CA".to_string()),
            locality: Some("San Francisco".to_string()),
        };

        let cert_info = CertificateInfo {
            subject: subject.clone(),
            validity_seconds: 365 * 24 * 60 * 60,
            serial_number: None,
            is_ca: true,
            key_usage: vec!["digitalSignature".to_string(), "keyCertSign".to_string()],
        };

        let cert = create_self_signed_certificate(&key, subject.clone(), cert_info).unwrap();

        // Test subject parsing
        let parsed_subject = cert.subject().unwrap();
        assert_eq!(parsed_subject.common_name, subject.common_name);
        assert_eq!(parsed_subject.organization, subject.organization);
        assert_eq!(parsed_subject.country, subject.country);

        // Test self-signed verification
        cert.verify_self_signed().unwrap();

        // Test validity
        assert!(cert.is_currently_valid());
    }

    #[test]
    fn test_certificate_from_csr() {
        let key = Key::generate().unwrap();
        let ca_key = Key::generate().unwrap();

        let subject = CertificateSubject {
            common_name: "server.example.com".to_string(),
            organization: Some("Server Corp".to_string()),
            organizational_unit: None,
            country: Some("US".to_string()),
            state: None,
            locality: None,
        };

        let ca_subject = CertificateSubject {
            common_name: "CA Root".to_string(),
            organization: Some("CA Corp".to_string()),
            organizational_unit: None,
            country: Some("US".to_string()),
            state: None,
            locality: None,
        };

        // Create CA certificate first
        let ca_cert_info = CertificateInfo {
            subject: ca_subject.clone(),
            validity_seconds: 365 * 24 * 60 * 60, // 1 year
            serial_number: Some(vec![1]),
            is_ca: true,
            key_usage: vec!["digitalSignature".to_string(), "keyCertSign".to_string()],
        };
        let ca_cert =
            create_self_signed_certificate(&ca_key, ca_subject.clone(), ca_cert_info).unwrap();

        // Create CSR
        let csr = crate::csr::create_csr(&key, subject.clone()).unwrap();

        // Create certificate from CSR using CA cert
        let cert_info = CertificateInfo {
            subject: subject.clone(),
            validity_seconds: 30 * 24 * 60 * 60, // 30 days
            serial_number: Some(vec![1, 2, 3, 4]),
            is_ca: false,
            key_usage: vec!["digitalSignature".to_string()],
        };

        let cert = create_certificate(&csr, &ca_key, &ca_cert, cert_info).unwrap();

        // Verify certificate properties
        let cert_subject = cert.subject().unwrap();
        assert_eq!(cert_subject.common_name, subject.common_name);

        let cert_issuer = cert.issuer().unwrap();
        assert_eq!(cert_issuer.common_name, ca_subject.common_name);

        // Verify signature with CA public key
        let ca_public_key = ca_key.ed25519_public_key_bytes();
        cert.verify_signature(&ca_public_key).unwrap();

        // Check serial number
        assert_eq!(cert.serial_number(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_certificate_pem_roundtrip() {
        let key = Key::generate().unwrap();

        let subject = CertificateSubject {
            common_name: "roundtrip.example.com".to_string(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        };

        let cert_info = CertificateInfo {
            subject: subject.clone(),
            ..Default::default()
        };

        let original_cert = create_self_signed_certificate(&key, subject, cert_info).unwrap();
        let pem = original_cert.to_pem().unwrap();
        let parsed_cert = X509Certificate::from_pem(&pem).unwrap();

        // Compare DER representations
        let original_der = original_cert.to_der().unwrap();
        let parsed_der = parsed_cert.to_der().unwrap();
        assert_eq!(original_der, parsed_der);
    }

    #[test]
    fn test_certificate_file_operations() {
        let dir = tempdir().unwrap();
        let pem_path = dir.path().join("test.pem");
        let der_path = dir.path().join("test.der");

        let key = Key::generate().unwrap();
        let subject = CertificateSubject {
            common_name: "file-test.example.com".to_string(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        };

        let cert_info = CertificateInfo {
            subject: subject.clone(),
            ..Default::default()
        };

        let original_cert = create_self_signed_certificate(&key, subject, cert_info).unwrap();

        // Test PEM file operations
        original_cert.save_pem_file(&pem_path).unwrap();
        let loaded_pem = X509Certificate::load_pem_file(&pem_path).unwrap();
        assert_eq!(
            loaded_pem.to_der().unwrap(),
            original_cert.to_der().unwrap()
        );

        // Test DER file operations
        original_cert.save_der_file(&der_path).unwrap();
        let loaded_der = X509Certificate::load_der_file(&der_path).unwrap();
        assert_eq!(
            loaded_der.to_der().unwrap(),
            original_cert.to_der().unwrap()
        );
    }

    #[test]
    fn test_certificate_validity() {
        let key = Key::generate().unwrap();

        let subject = CertificateSubject {
            common_name: "validity.example.com".to_string(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        };

        let cert_info = CertificateInfo {
            subject: subject.clone(),
            validity_seconds: 60, // 1 minute
            ..Default::default()
        };

        let cert = create_self_signed_certificate(&key, subject, cert_info).unwrap();

        // Should be valid now
        assert!(cert.is_currently_valid());

        // Test validity at specific time
        let now = SystemTime::now();
        assert!(cert.is_valid_at(now));

        // Should be invalid in the future (beyond validity period)
        let future = now + std::time::Duration::from_secs(3600); // 1 hour later
        assert!(!cert.is_valid_at(future));
    }
}
