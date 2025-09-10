use base64::{engine::general_purpose, Engine as _};
use pkcs8::{
    der::{asn1::OctetString, Decode, Encode, EncodePem},
    AlgorithmIdentifierRef, LineEnding, ObjectIdentifier, PrivateKeyInfo, SubjectPublicKeyInfoRef,
};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};

const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

pub struct X25519 {
    pub inner: StaticSecret,
}

impl From<StaticSecret> for X25519 {
    fn from(value: StaticSecret) -> Self {
        Self { inner: value }
    }
}

impl X25519 {
    /// Generate a new X25519 key using OS CSPRNG
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::GetrandomError(e.to_string()))?;
        Ok(StaticSecret::from(seed).into())
    }

    /// Create X25519 from raw seed bytes
    pub fn from_raw_seed(seed: &[u8; 32]) -> Self {
        StaticSecret::from(*seed).into()
    }

    /// Import from PKCS8 DER format
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let pki = PrivateKeyInfo::from_der(der)?;

        // Verify the algorithm OID
        if pki.algorithm.oid != X25519_OID {
            return Err(Error::Other("Invalid algorithm OID for X25519".to_string()));
        }

        // Extract the private key bytes
        let private_key = OctetString::from_der(pki.private_key)?;
        let bytes: [u8; 32] = private_key
            .as_bytes()
            .try_into()
            .map_err(|_| Error::Other("Invalid private key length".to_string()))?;

        Ok(Self::from_raw_seed(&bytes))
    }

    /// Import from PEM format
    pub fn from_pem(pem: &str) -> Result<Self> {
        let parsed = pem::parse(pem).map_err(|e| Error::Other(e.to_string()))?;

        if parsed.tag() != "PRIVATE KEY" {
            return Err(Error::Other(format!(
                "Invalid PEM label: expected PRIVATE KEY, got {}",
                parsed.tag()
            )));
        }

        Self::from_pkcs8_der(parsed.contents())
    }
}

impl X25519 {
    /// Export the private key as raw bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Export to PKCS8 DER format
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let algorithm = AlgorithmIdentifierRef {
            oid: X25519_OID,
            parameters: None,
        };

        let private_key_bytes = self.to_bytes();
        let private_key = OctetString::new(private_key_bytes)?;
        let private_key_der = private_key.to_der()?;

        let pki = PrivateKeyInfo::new(algorithm, &private_key_der);
        Ok(pki.to_der()?)
    }

    /// Export to SPKI DER format (public key)
    pub fn to_spki_der(&self) -> Result<Vec<u8>> {
        let algorithm = AlgorithmIdentifierRef {
            oid: X25519_OID,
            parameters: None,
        };

        let public_key = self.public_key();
        let public_key_bytes = public_key.to_bytes();

        let spki = SubjectPublicKeyInfoRef {
            algorithm,
            subject_public_key: pkcs8::der::asn1::BitStringRef::from_bytes(&public_key_bytes)?,
        };

        Ok(spki.to_der()?)
    }

    /// Export private key to PEM format
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        let algorithm = AlgorithmIdentifierRef {
            oid: X25519_OID,
            parameters: None,
        };

        let private_key_bytes = self.to_bytes();
        let private_key = OctetString::new(private_key_bytes)?;
        let private_key_der = private_key.to_der()?;

        let pki = PrivateKeyInfo::new(algorithm, &private_key_der);
        let pem = pki.to_pem(LineEnding::LF)?;

        Ok(pem)
    }

    /// Export public key to PEM format
    pub fn to_spki_pem(&self) -> Result<String> {
        let algorithm = AlgorithmIdentifierRef {
            oid: X25519_OID,
            parameters: None,
        };

        let public_key = self.public_key();
        let public_key_bytes = public_key.to_bytes();

        let spki = SubjectPublicKeyInfoRef {
            algorithm,
            subject_public_key: pkcs8::der::asn1::BitStringRef::from_bytes(&public_key_bytes)?,
        };

        let pem = spki.to_pem(LineEnding::LF)?;
        Ok(pem)
    }

    /// Export to JWK format
    pub fn to_jwk(&self) -> Result<String> {
        let public_key = self.public_key();
        // compute SPKI fingerprint as kid
        let spki = self.to_spki_der()?;
        let fp: [u8; 32] = Sha256::digest(&spki).into();
        let kid = general_purpose::URL_SAFE_NO_PAD.encode(fp);
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": general_purpose::URL_SAFE_NO_PAD.encode(public_key.to_bytes()),
            "kid": kid
        });
        Ok(jwk.to_string())
    }
}

impl X25519 {
    /// Get the public key for this keypair
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.inner)
    }

    pub fn compute_shared_secret(&self, their_public_key: &[u8; 32]) -> [u8; 32] {
        let their_public = PublicKey::from(*their_public_key);
        self.inner.diffie_hellman(&their_public).to_bytes()
    }

    pub fn spki_sha256_fingerprint(&self) -> Result<[u8; 32]> {
        let spki = self.to_spki_der()?;
        Ok(Sha256::digest(&spki).into())
    }
}

/// Create public key from raw bytes
pub fn public_key_from_bytes(bytes: &[u8; 32]) -> PublicKey {
    PublicKey::from(*bytes)
}

/// Import public key from SPKI DER format
pub fn public_key_from_spki_der(der: &[u8]) -> Result<PublicKey> {
    let spki = SubjectPublicKeyInfoRef::from_der(der)?;

    // Verify the algorithm OID
    if spki.algorithm.oid != X25519_OID {
        return Err(Error::Other("Invalid algorithm OID for X25519".to_string()));
    }

    // Extract the public key bytes
    let public_key_bits = spki.subject_public_key;
    let bytes: [u8; 32] = public_key_bits
        .as_bytes()
        .ok_or_else(|| Error::Other("Invalid public key bits".to_string()))?
        .try_into()
        .map_err(|_| Error::Other("Invalid public key length".to_string()))?;

    Ok(PublicKey::from(bytes))
}

/// Import public key from SPKI PEM format
pub fn public_key_from_spki_pem(pem: &str) -> Result<PublicKey> {
    let parsed = pem::parse(pem).map_err(|e| Error::Other(e.to_string()))?;

    if parsed.tag() != "PUBLIC KEY" {
        return Err(Error::Other(format!(
            "Invalid PEM label: expected PUBLIC KEY, got {}",
            parsed.tag()
        )));
    }

    public_key_from_spki_der(parsed.contents())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = X25519::generate().unwrap();
        let public_key = key.public_key();
        assert_eq!(public_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_key_exchange() {
        let alice = X25519::generate().unwrap();
        let bob = X25519::generate().unwrap();

        let alice_public = alice.public_key().to_bytes();
        let bob_public = bob.public_key().to_bytes();

        let alice_shared = alice.compute_shared_secret(&bob_public);
        let bob_shared = bob.compute_shared_secret(&alice_public);

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_pem_export_import() {
        let key = X25519::generate().unwrap();

        // Test private key PEM
        let pem = key.to_pkcs8_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        let imported = X25519::from_pem(&pem).unwrap();
        assert_eq!(key.to_bytes(), imported.to_bytes());

        // Test public key PEM
        let public_pem = key.to_spki_pem().unwrap();
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_der_export_import() {
        let key = X25519::generate().unwrap();

        // Test private key DER
        let der = key.to_pkcs8_der().unwrap();
        let imported = X25519::from_pkcs8_der(&der).unwrap();
        assert_eq!(key.to_bytes(), imported.to_bytes());

        // Test public key DER
        let public_der = key.to_spki_der().unwrap();
        let public_key = public_key_from_spki_der(&public_der).unwrap();
        assert_eq!(key.public_key().to_bytes(), public_key.to_bytes());
    }

    #[test]
    fn test_jwk_export() {
        let key = X25519::generate().unwrap();
        let jwk = key.to_jwk().unwrap();

        // Parse JSON to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&jwk).unwrap();
        assert_eq!(parsed["kty"], "OKP");
        assert_eq!(parsed["crv"], "X25519");
        assert!(parsed["x"].is_string());
        assert!(parsed["kid"].is_string());
    }

    #[test]
    fn test_fingerprint() {
        let key = X25519::generate().unwrap();
        let fingerprint = key.spki_sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);

        // Fingerprint should be deterministic
        let fingerprint2 = key.spki_sha256_fingerprint().unwrap();
        assert_eq!(fingerprint, fingerprint2);
    }

    #[test]
    fn test_from_raw_seed() {
        let seed = [42u8; 32];
        let key1 = X25519::from_raw_seed(&seed);
        let key2 = X25519::from_raw_seed(&seed);

        // Same seed should produce same keys
        assert_eq!(key1.to_bytes(), key2.to_bytes());
        assert_eq!(key1.public_key().to_bytes(), key2.public_key().to_bytes());
    }
}
