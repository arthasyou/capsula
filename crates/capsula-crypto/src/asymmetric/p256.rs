use base64::{engine::general_purpose, Engine as _};
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    elliptic_curve::{
        rand_core::OsRng,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
    EncodedPoint, PublicKey, SecretKey,
};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub struct P256 {
    pub inner: SecretKey,
}

impl From<SecretKey> for P256 {
    fn from(value: SecretKey) -> Self {
        Self { inner: value }
    }
}

impl P256 {
    /// Generate a new P-256 key pair
    pub fn generate() -> Result<Self> {
        let secret_key = SecretKey::random(&mut OsRng);
        Ok(secret_key.into())
    }

    /// Create from raw scalar bytes
    pub fn from_raw_scalar(bytes: &[u8; 32]) -> Result<Self> {
        let secret_key = SecretKey::from_bytes(bytes.into())
            .map_err(|e| Error::Other(format!("Invalid P256 scalar: {}", e)))?;
        Ok(secret_key.into())
    }

    /// Import from PKCS8 DER format
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let secret_key = SecretKey::from_pkcs8_der(der)?;
        Ok(secret_key.into())
    }

    /// Import from PKCS8 PEM format
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let secret_key = SecretKey::from_pkcs8_pem(pem)?;
        Ok(secret_key.into())
    }
}

impl P256 {
    /// Export private key to PKCS8 DER format
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let der = self.inner.to_pkcs8_der()?;
        Ok(der.as_bytes().to_vec())
    }

    /// Export private key to PKCS8 PEM format
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        let pem = self.inner.to_pkcs8_pem(LineEnding::LF)?;
        Ok(pem.to_string())
    }

    /// Export public key to SPKI DER format
    pub fn to_spki_der(&self) -> Result<Vec<u8>> {
        let der = self.inner.public_key().to_public_key_der()?;
        Ok(der.as_bytes().to_vec())
    }

    /// Export public key to SPKI PEM format
    pub fn to_spki_pem(&self) -> Result<String> {
        let pem = self.inner.public_key().to_public_key_pem(LineEnding::LF)?;
        Ok(pem)
    }

    /// Export to JWK format
    pub fn to_jwk(&self) -> Result<String> {
        let public_key = self.inner.public_key();
        let encoded_point = public_key.to_encoded_point(false);
        
        // compute SPKI fingerprint as kid
        let spki = self.to_spki_der()?;
        let fp: [u8; 32] = Sha256::digest(&spki).into();
        let kid = general_purpose::URL_SAFE_NO_PAD.encode(fp);

        // Extract x and y coordinates (uncompressed point format)
        let coords = encoded_point.coordinates();
        if let p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } = coords {
            
            let jwk = serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": general_purpose::URL_SAFE_NO_PAD.encode(x),
                "y": general_purpose::URL_SAFE_NO_PAD.encode(y),
                "kid": kid
            });
            Ok(jwk.to_string())
        } else {
            return Err(Error::Other("Failed to extract coordinates".to_string()));
        }
    }

    /// Get raw scalar bytes
    pub fn to_scalar_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }
}

impl P256 {
    /// Get the public key for this keypair
    pub fn public_key(&self) -> PublicKey {
        self.inner.public_key()
    }

    /// Sign data using ECDSA with SHA-256
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::from(&self.inner);
        let signature: Signature = signing_key.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }

    /// Perform ECDH key agreement
    pub fn compute_shared_secret(&self, their_public_key: &PublicKey) -> Result<[u8; 32]> {
        let shared_secret = p256::ecdh::diffie_hellman(self.inner.to_nonzero_scalar(), their_public_key.as_affine());
        let bytes = shared_secret.raw_secret_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(bytes);
        Ok(result)
    }

    /// Generate SPKI SHA-256 fingerprint
    pub fn spki_sha256_fingerprint(&self) -> Result<[u8; 32]> {
        let spki = self.to_spki_der()?;
        Ok(Sha256::digest(&spki).into())
    }
}

/// Verify P-256 ECDSA signature with SHA-256
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    let verifying_key = VerifyingKey::from(public_key);
    let signature = match Signature::from_der(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    verifying_key.verify(message, &signature).is_ok()
}

/// Import public key from SPKI DER format
pub fn public_key_from_spki_der(der: &[u8]) -> Result<PublicKey> {
    PublicKey::from_public_key_der(der).map_err(Into::into)
}

/// Import public key from SPKI PEM format
pub fn public_key_from_spki_pem(pem: &str) -> Result<PublicKey> {
    PublicKey::from_public_key_pem(pem).map_err(Into::into)
}

/// Import public key from SEC1 encoded point
pub fn public_key_from_encoded_point(bytes: &[u8]) -> Result<PublicKey> {
    let encoded_point = EncodedPoint::from_bytes(bytes)
        .map_err(|e| Error::Other(format!("Invalid encoded point: {}", e)))?;
    
    let result = PublicKey::from_encoded_point(&encoded_point);
    if result.is_some().into() {
        Ok(result.unwrap())
    } else {
        Err(Error::Other("Invalid public key point".to_string()))
    }
}

/// Export public key to SEC1 encoded point (uncompressed)
pub fn public_key_to_encoded_point(public_key: &PublicKey) -> Vec<u8> {
    public_key.to_encoded_point(false).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = P256::generate().unwrap();
        let public_key = key.public_key();
        
        // P-256 public keys are 65 bytes uncompressed (0x04 + 32 + 32)
        let encoded = public_key.to_encoded_point(false);
        assert_eq!(encoded.len(), 65);
    }

    #[test]
    fn test_sign_verify() {
        let key = P256::generate().unwrap();
        let message = b"Hello, P-256!";
        
        let signature = key.sign(message).unwrap();
        let public_key = key.public_key();
        
        assert!(verify(&public_key, message, &signature));
    }

    #[test]
    fn test_ecdh() {
        let alice = P256::generate().unwrap();
        let bob = P256::generate().unwrap();
        
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();
        
        let alice_shared = alice.compute_shared_secret(&bob_public).unwrap();
        let bob_shared = bob.compute_shared_secret(&alice_public).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_pem_export_import() {
        let key = P256::generate().unwrap();
        
        // Test private key PEM
        let pem = key.to_pkcs8_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        
        let imported = P256::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(key.to_scalar_bytes(), imported.to_scalar_bytes());
        
        // Test public key PEM
        let public_pem = key.to_spki_pem().unwrap();
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_der_export_import() {
        let key = P256::generate().unwrap();
        
        // Test private key DER
        let der = key.to_pkcs8_der().unwrap();
        let imported = P256::from_pkcs8_der(&der).unwrap();
        assert_eq!(key.to_scalar_bytes(), imported.to_scalar_bytes());
        
        // Test public key DER
        let public_der = key.to_spki_der().unwrap();
        let public_key = public_key_from_spki_der(&public_der).unwrap();
        assert_eq!(key.public_key().to_encoded_point(false), public_key.to_encoded_point(false));
    }

    #[test]
    fn test_jwk_export() {
        let key = P256::generate().unwrap();
        let jwk = key.to_jwk().unwrap();
        
        // Parse JSON to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&jwk).unwrap();
        assert_eq!(parsed["kty"], "EC");
        assert_eq!(parsed["crv"], "P-256");
        assert!(parsed["x"].is_string());
        assert!(parsed["y"].is_string());
        assert!(parsed["kid"].is_string());
    }

    #[test]
    fn test_fingerprint() {
        let key = P256::generate().unwrap();
        let fingerprint = key.spki_sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);
        
        // Fingerprint should be deterministic
        let fingerprint2 = key.spki_sha256_fingerprint().unwrap();
        assert_eq!(fingerprint, fingerprint2);
    }

    #[test]
    fn test_encoded_point_roundtrip() {
        let key = P256::generate().unwrap();
        let public_key = key.public_key();
        
        let encoded_bytes = public_key_to_encoded_point(&public_key);
        let recovered_key = public_key_from_encoded_point(&encoded_bytes).unwrap();
        
        assert_eq!(public_key.to_encoded_point(false), recovered_key.to_encoded_point(false));
    }

    #[test]
    fn test_from_raw_scalar() {
        let scalar_bytes = [42u8; 32];
        let key1 = P256::from_raw_scalar(&scalar_bytes).unwrap();
        let key2 = P256::from_raw_scalar(&scalar_bytes).unwrap();
        
        // Same scalar should produce same keys
        assert_eq!(key1.to_scalar_bytes(), key2.to_scalar_bytes());
        assert_eq!(key1.public_key().to_encoded_point(false), key2.public_key().to_encoded_point(false));
    }
}