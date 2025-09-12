//! Certificate Signing Request (CSR) module
//!
//! This module provides functionality for creating, parsing, and managing Certificate Signing
//! Requests using the capsula-key library for cryptographic operations.

use std::str::FromStr;

use capsula_key::{Key, KeySign};
use der::{
    asn1::{ObjectIdentifier, SetOfVec, Utf8StringRef},
    Decode, Encode,
};
use pkcs8::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use serde::{Deserialize, Serialize};
use x509_cert::{
    attr::AttributeTypeAndValue,
    name::{RdnSequence, RelativeDistinguishedName},
    request::CertReq,
};

use crate::{error::PkiError, Result};

/// Certificate Signing Request (CSR) with Capsula Key integration
#[derive(Debug, Clone)]
pub struct Csr {
    inner: CertReq,
}

/// CSR Subject information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CsrSubject {
    /// Common Name (CN)
    pub common_name: String,
    /// Organization (O)
    pub organization: Option<String>,
    /// Organizational Unit (OU)
    pub organizational_unit: Option<String>,
    /// Country (C)
    pub country: Option<String>,
    /// State or Province (ST)
    pub state: Option<String>,
    /// Locality (L)
    pub locality: Option<String>,
}

/// Build an unsigned CertReqInfo from subject and public key
///
/// This function creates the unsigned portion of a CSR that needs to be signed.
///
/// # Arguments
/// * `subject` - The subject information for the CSR
/// * `spki_der` - The public key in SPKI DER format
///
/// # Returns
/// Returns the unsigned CertReqInfo structure that can be encoded and signed
pub fn build_unsigned(
    subject: CsrSubject,
    spki_der: &[u8],
) -> Result<x509_cert::request::CertReqInfo> {
    // Create subject distinguished name
    let subject_dn = Csr::build_distinguished_name(&subject)?;

    // Parse the SPKI DER to validate it's a proper public key
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| PkiError::CsrError(format!("Failed to parse SPKI: {}", e)))?;

    // Verify this is an Ed25519 public key
    if spki.algorithm.oid != const_oid::db::rfc8410::ID_ED_25519 {
        return Err(PkiError::CsrError(
            "Only Ed25519 public keys are supported".to_string(),
        ));
    }

    // Create CertReqInfo
    let cert_req_info = x509_cert::request::CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: subject_dn,
        public_key: spki,
        attributes: Default::default(),
    };

    Ok(cert_req_info)
}

/// Create a new CSR using the provided key and subject information (convenience function)
///
/// This function combines build_unsigned, signing, and assemble into a single operation.
pub fn create_csr<K: Key + KeySign>(key: &K, subject: CsrSubject) -> Result<Csr> {
    // Get public key in SPKI format
    let public_keys = key.public_keys();
    let signing_key = public_keys
        .signing_key()
        .ok_or_else(|| PkiError::CsrError("No signing key available".to_string()))?;
    let spki_der = signing_key.spki_der.clone();

    // Build unsigned CSR info
    let cert_req_info = build_unsigned(subject, &spki_der)?;

    // Encode CertReqInfo for signing
    let info_der = cert_req_info
        .to_der()
        .map_err(|e| PkiError::CsrError(format!("Failed to encode CertReqInfo: {}", e)))?;

    // Sign the CSR info
    let signature = key
        .sign(&info_der)
        .map_err(|_| PkiError::CsrError("Failed to sign CSR".to_string()))?;

    // Convert to fixed-size array (Ed25519 signatures are 64 bytes)
    if signature.len() != 64 {
        return Err(PkiError::CsrError(format!(
            "Expected 64-byte signature, got {} bytes",
            signature.len()
        )));
    }
    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(&signature);

    // Assemble the complete CSR
    Csr::assemble(cert_req_info, &signature_bytes)
}

/// Type alias for backward compatibility
pub type CertificateSigningRequest = Csr;

impl Csr {
    /// Assemble a complete CSR from CertReqInfo and signature
    ///
    /// This function combines the unsigned CSR info with a signature to create
    /// a complete, signed Certificate Signing Request.
    ///
    /// # Arguments
    /// * `cert_req_info` - The unsigned CSR information
    /// * `signature` - The Ed25519 signature bytes (64 bytes)
    ///
    /// # Returns
    /// Returns a complete, signed CSR
    pub fn assemble(
        cert_req_info: x509_cert::request::CertReqInfo,
        signature: &[u8; 64],
    ) -> Result<Self> {
        // Create signature algorithm identifier for Ed25519
        let sig_alg = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc8410::ID_ED_25519,
            parameters: None,
        };

        // Create the complete CSR
        let inner = CertReq {
            info: cert_req_info,
            algorithm: sig_alg,
            signature: der::asn1::BitString::from_bytes(signature)
                .map_err(|e| PkiError::CsrError(format!("Failed to create signature: {}", e)))?,
        };

        Ok(Self { inner })
    }

    /// Parse CSR from PEM format
    pub fn from_pem(pem: &str) -> Result<Self> {
        let der = pem::parse(pem)
            .map_err(|e| PkiError::CsrError(format!("Failed to parse PEM: {}", e)))?;

        if der.tag() != "CERTIFICATE REQUEST" && der.tag() != "NEW CERTIFICATE REQUEST" {
            return Err(PkiError::CsrError(
                "Invalid PEM tag, expected CERTIFICATE REQUEST or NEW CERTIFICATE REQUEST"
                    .to_string(),
            ));
        }

        Self::from_der(der.contents())
    }

    /// Parse CSR from DER format
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let inner = CertReq::from_der(der)
            .map_err(|e| PkiError::CsrError(format!("Failed to parse DER: {}", e)))?;

        Ok(Self { inner })
    }

    /// Export CSR to PEM format
    pub fn to_pem(&self) -> Result<String> {
        let der = self.to_der()?;
        let pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", der));
        Ok(pem)
    }

    /// Export CSR to DER format
    pub fn to_der(&self) -> Result<Vec<u8>> {
        self.inner
            .to_der()
            .map_err(|e| PkiError::CsrError(format!("Failed to encode DER: {}", e)))
    }

    /// Get the subject of the CSR
    pub fn subject(&self) -> Result<CsrSubject> {
        Self::parse_distinguished_name(&self.inner.info.subject)
    }

    /// Extract Ed25519 public key bytes from SPKI
    pub fn ed25519_public_key_bytes(&self) -> Result<[u8; 32]> {
        let spki = &self.inner.info.public_key;

        // Verify this is an Ed25519 key
        if spki.algorithm.oid != const_oid::db::rfc8410::ID_ED_25519 {
            return Err(PkiError::CsrError("Not an Ed25519 public key".to_string()));
        }

        // Get the public key bytes
        let key_bytes = spki.subject_public_key.raw_bytes();
        if key_bytes.len() != 32 {
            return Err(PkiError::CsrError(format!(
                "Invalid Ed25519 public key length: {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key_bytes);
        Ok(key_array)
    }

    /// Verify the CSR signature
    pub fn verify_signature(&self) -> Result<()> {
        // Encode the CertReqInfo for verification
        let info_der = self.inner.info.to_der().map_err(|e| {
            PkiError::CsrError(format!("Failed to encode info for verification: {}", e))
        })?;

        // Get signature bytes
        let signature = self.inner.signature.raw_bytes();
        if signature.len() != 64 {
            return Err(PkiError::CsrError(
                "Invalid signature length for Ed25519".to_string(),
            ));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature);

        // Extract the actual public key from the SPKI
        let public_key_bytes = self.ed25519_public_key_bytes()?;

        // Verify using the public key from the CSR
        if capsula_key::verify(&public_key_bytes, &info_der, &sig_array) {
            Ok(())
        } else {
            Err(PkiError::CsrError(
                "Signature verification failed".to_string(),
            ))
        }
    }

    // ========================================================================
    // File I/O Operations
    // ========================================================================

    /// Save CSR to PEM file
    pub fn save_pem_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let pem = self.to_pem()?;
        std::fs::write(path, pem).map_err(PkiError::IoError)
    }

    /// Load CSR from PEM file
    pub fn load_pem_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let pem = std::fs::read_to_string(path).map_err(PkiError::IoError)?;
        Self::from_pem(&pem)
    }

    /// Save CSR to DER file
    pub fn save_der_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let der = self.to_der()?;
        std::fs::write(path, der).map_err(PkiError::IoError)
    }

    /// Load CSR from DER file
    pub fn load_der_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let der = std::fs::read(path).map_err(PkiError::IoError)?;
        Self::from_der(&der)
    }

    /// Build X.509 Distinguished Name from CsrSubject
    pub(crate) fn build_distinguished_name(subject: &CsrSubject) -> Result<x509_cert::name::Name> {
        let mut rdns = Vec::new();

        // Add Common Name (required)
        if subject.common_name.is_empty() {
            return Err(PkiError::CsrError(
                "Common Name (CN) is required".to_string(),
            ));
        }
        let cn_oid = ObjectIdentifier::from_str("2.5.4.3")
            .map_err(|e| PkiError::CsrError(format!("Invalid CN OID: {}", e)))?;
        let cn_value = Utf8StringRef::new(&subject.common_name)
            .map_err(|e| PkiError::CsrError(format!("Invalid CN value: {}", e)))?;
        let mut cn_set = SetOfVec::new();
        cn_set
            .insert(AttributeTypeAndValue {
                oid: cn_oid,
                value: der::Any::from(cn_value),
            })
            .map_err(|e| PkiError::CsrError(format!("Failed to add CN: {}", e)))?;
        rdns.push(RelativeDistinguishedName(cn_set));

        // Add optional attributes
        if let Some(ref org) = subject.organization {
            let o_oid = ObjectIdentifier::from_str("2.5.4.10")
                .map_err(|e| PkiError::CsrError(format!("Invalid O OID: {}", e)))?;
            let o_value = Utf8StringRef::new(org)
                .map_err(|e| PkiError::CsrError(format!("Invalid O value: {}", e)))?;
            let mut o_set = SetOfVec::new();
            o_set
                .insert(AttributeTypeAndValue {
                    oid: o_oid,
                    value: der::Any::from(o_value),
                })
                .map_err(|e| PkiError::CsrError(format!("Failed to add O: {}", e)))?;
            rdns.push(RelativeDistinguishedName(o_set));
        }

        if let Some(ref ou) = subject.organizational_unit {
            let ou_oid = ObjectIdentifier::from_str("2.5.4.11")
                .map_err(|e| PkiError::CsrError(format!("Invalid OU OID: {}", e)))?;
            let ou_value = Utf8StringRef::new(ou)
                .map_err(|e| PkiError::CsrError(format!("Invalid OU value: {}", e)))?;
            let mut ou_set = SetOfVec::new();
            ou_set
                .insert(AttributeTypeAndValue {
                    oid: ou_oid,
                    value: der::Any::from(ou_value),
                })
                .map_err(|e| PkiError::CsrError(format!("Failed to add OU: {}", e)))?;
            rdns.push(RelativeDistinguishedName(ou_set));
        }

        if let Some(ref country) = subject.country {
            let c_oid = ObjectIdentifier::from_str("2.5.4.6")
                .map_err(|e| PkiError::CsrError(format!("Invalid C OID: {}", e)))?;
            let c_value = Utf8StringRef::new(country)
                .map_err(|e| PkiError::CsrError(format!("Invalid C value: {}", e)))?;
            let mut c_set = SetOfVec::new();
            c_set
                .insert(AttributeTypeAndValue {
                    oid: c_oid,
                    value: der::Any::from(c_value),
                })
                .map_err(|e| PkiError::CsrError(format!("Failed to add C: {}", e)))?;
            rdns.push(RelativeDistinguishedName(c_set));
        }

        if let Some(ref state) = subject.state {
            let st_oid = ObjectIdentifier::from_str("2.5.4.8")
                .map_err(|e| PkiError::CsrError(format!("Invalid ST OID: {}", e)))?;
            let st_value = Utf8StringRef::new(state)
                .map_err(|e| PkiError::CsrError(format!("Invalid ST value: {}", e)))?;
            let mut st_set = SetOfVec::new();
            st_set
                .insert(AttributeTypeAndValue {
                    oid: st_oid,
                    value: der::Any::from(st_value),
                })
                .map_err(|e| PkiError::CsrError(format!("Failed to add ST: {}", e)))?;
            rdns.push(RelativeDistinguishedName(st_set));
        }

        if let Some(ref locality) = subject.locality {
            let l_oid = ObjectIdentifier::from_str("2.5.4.7")
                .map_err(|e| PkiError::CsrError(format!("Invalid L OID: {}", e)))?;
            let l_value = Utf8StringRef::new(locality)
                .map_err(|e| PkiError::CsrError(format!("Invalid L value: {}", e)))?;
            let mut l_set = SetOfVec::new();
            l_set
                .insert(AttributeTypeAndValue {
                    oid: l_oid,
                    value: der::Any::from(l_value),
                })
                .map_err(|e| PkiError::CsrError(format!("Failed to add L: {}", e)))?;
            rdns.push(RelativeDistinguishedName(l_set));
        }

        Ok(x509_cert::name::Name::from(RdnSequence::from(rdns)))
    }

    /// Parse X.509 Distinguished Name to CsrSubject
    pub(crate) fn parse_distinguished_name(name: &x509_cert::name::Name) -> Result<CsrSubject> {
        let mut subject = CsrSubject {
            common_name: String::new(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        };

        let cn_oid = ObjectIdentifier::from_str("2.5.4.3").unwrap();
        let o_oid = ObjectIdentifier::from_str("2.5.4.10").unwrap();
        let ou_oid = ObjectIdentifier::from_str("2.5.4.11").unwrap();
        let c_oid = ObjectIdentifier::from_str("2.5.4.6").unwrap();
        let st_oid = ObjectIdentifier::from_str("2.5.4.8").unwrap();
        let l_oid = ObjectIdentifier::from_str("2.5.4.7").unwrap();

        for rdn in name.0.iter() {
            for attr in rdn.0.iter() {
                let value_str = if let Ok(utf8_str) = Utf8StringRef::try_from(&attr.value) {
                    utf8_str.as_str().to_string()
                } else {
                    // Try other string types or fallback
                    continue;
                };

                if attr.oid == cn_oid {
                    subject.common_name = value_str;
                } else if attr.oid == o_oid {
                    subject.organization = Some(value_str);
                } else if attr.oid == ou_oid {
                    subject.organizational_unit = Some(value_str);
                } else if attr.oid == c_oid {
                    subject.country = Some(value_str);
                } else if attr.oid == st_oid {
                    subject.state = Some(value_str);
                } else if attr.oid == l_oid {
                    subject.locality = Some(value_str);
                }
            }
        }

        if subject.common_name.is_empty() {
            return Err(PkiError::CsrError(
                "Distinguished name missing required CN".to_string(),
            ));
        }

        Ok(subject)
    }
}

// Re-export CertReqInfo for external use in build_unsigned/assemble pattern
pub use x509_cert::request::CertReqInfo;

#[cfg(test)]
mod tests {
    use capsula_key::Curve25519;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_csr_creation() {
        let key = Curve25519::generate().unwrap();

        let subject = CsrSubject {
            common_name: "test.example.com".to_string(),
            organization: Some("Test Org".to_string()),
            organizational_unit: None,
            country: Some("US".to_string()),
            state: Some("CA".to_string()),
            locality: Some("San Francisco".to_string()),
        };

        let csr = create_csr(&key, subject.clone()).unwrap();

        // Test subject parsing
        let parsed_subject = csr.subject().unwrap();
        assert_eq!(parsed_subject.common_name, subject.common_name);
        assert_eq!(parsed_subject.organization, subject.organization);
        assert_eq!(parsed_subject.country, subject.country);
        assert_eq!(parsed_subject.state, subject.state);
        assert_eq!(parsed_subject.locality, subject.locality);
    }

    #[test]
    fn test_csr_pem_roundtrip() {
        let key = Curve25519::generate().unwrap();

        let subject = CsrSubject {
            common_name: "test.example.com".to_string(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        };

        let original_csr = create_csr(&key, subject).unwrap();
        let pem = original_csr.to_pem().unwrap();
        let parsed_csr = Csr::from_pem(&pem).unwrap();

        // Compare DER representations
        let original_der = original_csr.to_der().unwrap();
        let parsed_der = parsed_csr.to_der().unwrap();
        assert_eq!(original_der, parsed_der);
    }

    #[test]
    fn test_csr_file_operations() {
        let dir = tempdir().unwrap();
        let pem_path = dir.path().join("test.csr");
        let der_path = dir.path().join("test.der");

        let key = Curve25519::generate().unwrap();
        let subject = CsrSubject {
            common_name: "file-test.example.com".to_string(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        };

        let original_csr = create_csr(&key, subject.clone()).unwrap();

        // Test PEM file operations
        original_csr.save_pem_file(&pem_path).unwrap();
        let loaded_pem = Csr::load_pem_file(&pem_path).unwrap();
        assert_eq!(loaded_pem.to_der().unwrap(), original_csr.to_der().unwrap());

        // Test DER file operations
        original_csr.save_der_file(&der_path).unwrap();
        let loaded_der = Csr::load_der_file(&der_path).unwrap();
        assert_eq!(loaded_der.to_der().unwrap(), original_csr.to_der().unwrap());
    }

    #[test]
    fn test_csr_validation_errors() {
        // Test CSR with invalid subject (empty CN)
        let key = Curve25519::generate().unwrap();
        let subject = CsrSubject {
            common_name: String::new(), // Invalid: empty CN
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        };

        // This should fail during CSR creation due to empty CN
        assert!(create_csr(&key, subject).is_err());
    }

    #[test]
    fn test_signature_verification() {
        let key = Curve25519::generate().unwrap();

        let subject = CsrSubject {
            common_name: "verify.example.com".to_string(),
            organization: Some("Verify Org".to_string()),
            organizational_unit: None,
            country: Some("US".to_string()),
            state: None,
            locality: None,
        };

        let csr = create_csr(&key, subject).unwrap();

        // Test signature verification
        csr.verify_signature().unwrap();
    }

    #[test]
    fn test_ed25519_public_key_extraction() {
        let key = Curve25519::generate().unwrap();

        let subject = CsrSubject {
            common_name: "pubkey.example.com".to_string(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        };

        let csr = create_csr(&key, subject).unwrap();

        // Test public key extraction
        let pubkey_bytes = csr.ed25519_public_key_bytes().unwrap();
        assert_eq!(pubkey_bytes.len(), 32);

        // Should match the key used to create the CSR
        let key_public_keys = key.public_keys();
        let signing_key = key_public_keys.signing_key().unwrap();
        let original_pubkey = signing_key.raw_public_key.as_ref().unwrap();
        assert_eq!(pubkey_bytes, original_pubkey.as_slice());
    }

    #[test]
    fn test_from_pem_with_different_tags() {
        let key = Curve25519::generate().unwrap();

        let subject = CsrSubject {
            common_name: "tag-test.example.com".to_string(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
        };

        let original_csr = create_csr(&key, subject).unwrap();
        let der = original_csr.to_der().unwrap();

        // Test with "CERTIFICATE REQUEST" tag
        let pem1 = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", der.clone()));
        let parsed_csr1 = Csr::from_pem(&pem1).unwrap();
        assert_eq!(parsed_csr1.to_der().unwrap(), der);

        // Test with "NEW CERTIFICATE REQUEST" tag
        let pem2 = pem::encode(&pem::Pem::new("NEW CERTIFICATE REQUEST", der.clone()));
        let parsed_csr2 = Csr::from_pem(&pem2).unwrap();
        assert_eq!(parsed_csr2.to_der().unwrap(), der);

        // Test with invalid tag
        let pem3 = pem::encode(&pem::Pem::new("INVALID TAG", der));
        assert!(Csr::from_pem(&pem3).is_err());
    }

    #[test]
    fn test_build_unsigned_and_assemble() {
        let key = Curve25519::generate().unwrap();
        let subject = CsrSubject {
            common_name: "test-unsigned.example.com".to_string(),
            organization: Some("Test Org".to_string()),
            organizational_unit: None,
            country: Some("US".to_string()),
            state: None,
            locality: None,
        };

        // Get the public key in SPKI format
        let key_public_keys = key.public_keys();
        let signing_key = key_public_keys.signing_key().unwrap();
        let spki_der = &signing_key.spki_der;

        // Test 1: Build unsigned CSR info
        let cert_req_info = build_unsigned(subject.clone(), &spki_der).unwrap();

        // Verify the subject was set correctly
        let parsed_subject = Csr::parse_distinguished_name(&cert_req_info.subject).unwrap();
        assert_eq!(parsed_subject.common_name, "test-unsigned.example.com");
        assert_eq!(parsed_subject.organization, Some("Test Org".to_string()));
        assert_eq!(parsed_subject.country, Some("US".to_string()));

        // Test 2: Sign the CertReqInfo manually using trait
        let info_der = cert_req_info.to_der().unwrap();
        let signature_vec = <Curve25519 as KeySign>::sign(&key, &info_der).unwrap();
        let signature: [u8; 64] = signature_vec.try_into().unwrap();

        // Test 3: Assemble the complete CSR
        let csr = Csr::assemble(cert_req_info, &signature).unwrap();

        // Test 4: Verify the assembled CSR signature
        csr.verify_signature().unwrap();

        // Test 5: Compare with the traditional new() method
        let traditional_csr = create_csr(&key, subject).unwrap();

        // Both CSRs should have the same subject
        let assembled_subject = csr.subject().unwrap();
        let traditional_subject = traditional_csr.subject().unwrap();
        assert_eq!(
            assembled_subject.common_name,
            traditional_subject.common_name
        );
        assert_eq!(
            assembled_subject.organization,
            traditional_subject.organization
        );

        // Both CSRs should have valid signatures
        traditional_csr.verify_signature().unwrap();

        // Test error cases

        // Test with invalid SPKI (non-Ed25519)
        let invalid_spki = [0u8; 32]; // Invalid DER
        assert!(build_unsigned(
            CsrSubject {
                common_name: "test.example.com".to_string(),
                organization: None,
                organizational_unit: None,
                country: None,
                state: None,
                locality: None,
            },
            &invalid_spki
        )
        .is_err());
    }
}
