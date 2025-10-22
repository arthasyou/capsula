use base64::{engine::general_purpose, Engine as _};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub struct Rsa {
    pub inner: RsaPrivateKey,
}

impl From<RsaPrivateKey> for Rsa {
    fn from(value: RsaPrivateKey) -> Self {
        Self { inner: value }
    }
}

impl Rsa {
    /// Generate a new RSA key pair with specified bit length (2048, 3072, or 4096)
    pub fn generate(bits: usize) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| Error::Other(format!("Failed to generate RSA key: {}", e)))?;
        Ok(private_key.into())
    }

    /// Generate 2048-bit RSA key (default)
    pub fn generate_2048() -> Result<Self> {
        Self::generate(2048)
    }

    /// Generate 3072-bit RSA key
    pub fn generate_3072() -> Result<Self> {
        Self::generate(3072)
    }

    /// Generate 4096-bit RSA key
    pub fn generate_4096() -> Result<Self> {
        Self::generate(4096)
    }

    /// Import from PKCS8 DER format
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der)?;
        Ok(private_key.into())
    }

    /// Import from PKCS8 PEM format
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)?;
        Ok(private_key.into())
    }
}

impl Rsa {
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
        let der = self.inner.to_public_key().to_public_key_der()?;
        Ok(der.as_bytes().to_vec())
    }

    /// Export public key to SPKI PEM format
    pub fn to_spki_pem(&self) -> Result<String> {
        let pem = self
            .inner
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)?;
        Ok(pem)
    }

    /// Export to JWK format
    pub fn to_jwk(&self) -> Result<String> {
        let public_key = self.inner.to_public_key();
        // compute SPKI fingerprint as kid
        let spki = self.to_spki_der()?;
        let fp: [u8; 32] = Sha256::digest(&spki).into();
        let kid = general_purpose::URL_SAFE_NO_PAD.encode(fp);

        let n = general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let jwk = serde_json::json!({
            "kty": "RSA",
            "n": n,
            "e": e,
            "kid": kid
        });
        Ok(jwk.to_string())
    }
}

impl Rsa {
    /// Get the public key for this keypair
    pub fn public_key(&self) -> RsaPublicKey {
        self.inner.to_public_key()
    }

    /// Get key size in bits
    pub fn size(&self) -> usize {
        self.inner.size() * 8
    }

    /// Sign data using PKCS#1 v1.5 with SHA-256
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let hashed = Sha256::digest(message);
        let signature = self
            .inner
            .sign_with_rng(&mut rng, rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed)
            .map_err(|e| Error::Other(format!("RSA signing failed: {}", e)))?;
        Ok(signature)
    }

    /// Encrypt data using own public key with PKCS#1 v1.5 padding
    /// Use this when you want to encrypt data that only this key can decrypt
    pub fn encrypt_with_own_key(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let public_key = self.public_key();
        encrypt(&public_key, plaintext)
    }

    /// Decrypt data using PKCS#1 v1.5 padding
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = self
            .inner
            .decrypt(rsa::Pkcs1v15Encrypt, ciphertext)
            .map_err(|e| Error::Other(format!("RSA decryption failed: {}", e)))?;
        Ok(plaintext)
    }

    /// Generate SPKI SHA-256 fingerprint
    pub fn spki_sha256_fingerprint(&self) -> Result<[u8; 32]> {
        let spki = self.to_spki_der()?;
        Ok(Sha256::digest(&spki).into())
    }
}

/// Verify RSA signature with standard SPKI DER interface
pub fn verify_with_spki_der(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    // Parse RSA public key from SPKI DER
    let public_key = public_key_from_spki_der(spki_der)?;

    // Verify using PKCS#1 v1.5 with SHA-256
    let hashed = Sha256::digest(message);
    Ok(public_key
        .verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed, signature)
        .is_ok())
}

/// Import public key from SPKI DER format
pub fn public_key_from_spki_der(der: &[u8]) -> Result<RsaPublicKey> {
    RsaPublicKey::from_public_key_der(der).map_err(Into::into)
}

/// Import public key from SPKI PEM format
pub fn public_key_from_spki_pem(pem: &str) -> Result<RsaPublicKey> {
    RsaPublicKey::from_public_key_pem(pem).map_err(Into::into)
}

/// Encrypt data using RSA public key with PKCS#1 v1.5 padding
pub fn encrypt(public_key: &RsaPublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let ciphertext = public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, plaintext)
        .map_err(|e| Error::Other(format!("RSA encryption failed: {}", e)))?;
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = Rsa::generate_2048().unwrap();
        assert_eq!(key.size(), 2048);

        let key = Rsa::generate_3072().unwrap();
        assert_eq!(key.size(), 3072);
    }

    #[test]
    fn test_sign_verify() {
        let key = Rsa::generate_2048().unwrap();
        let message = b"Hello, RSA!";

        let signature = key.sign(message).unwrap();

        let spki_der = key.to_spki_der().unwrap();
        assert!(verify_with_spki_der(&spki_der, message, &signature).unwrap());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = Rsa::generate_2048().unwrap();
        let message = b"Secret message";

        let public_key = key.public_key();
        let ciphertext = encrypt(&public_key, message).unwrap();
        let plaintext = key.decrypt(&ciphertext).unwrap();

        assert_eq!(message.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_with_own_key() {
        let key = Rsa::generate_2048().unwrap();
        let message = b"Secret message encrypted with own key";

        // Encrypt using own public key
        let ciphertext = key.encrypt_with_own_key(message).unwrap();

        // Decrypt using own private key
        let plaintext = key.decrypt(&ciphertext).unwrap();

        assert_eq!(message.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_pem_export_import() {
        let key = Rsa::generate_2048().unwrap();

        // Test private key PEM
        let pem = key.to_pkcs8_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        let imported = Rsa::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(key.size(), imported.size());

        // Test public key PEM
        let public_pem = key.to_spki_pem().unwrap();
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_der_export_import() {
        let key = Rsa::generate_2048().unwrap();

        // Test private key DER
        let der = key.to_pkcs8_der().unwrap();
        let imported = Rsa::from_pkcs8_der(&der).unwrap();
        assert_eq!(key.size(), imported.size());

        // Test public key DER
        let public_der = key.to_spki_der().unwrap();
        let public_key = public_key_from_spki_der(&public_der).unwrap();
        assert_eq!(key.public_key().n(), public_key.n());
        assert_eq!(key.public_key().e(), public_key.e());
    }

    #[test]
    fn test_jwk_export() {
        let key = Rsa::generate_2048().unwrap();
        let jwk = key.to_jwk().unwrap();

        // Parse JSON to verify structure
        let parsed: serde_json::Value = serde_json::from_str(&jwk).unwrap();
        assert_eq!(parsed["kty"], "RSA");
        assert!(parsed["n"].is_string());
        assert!(parsed["e"].is_string());
        assert!(parsed["kid"].is_string());
    }

    #[test]
    fn test_fingerprint() {
        let key = Rsa::generate_2048().unwrap();
        let fingerprint = key.spki_sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 32);

        // Fingerprint should be deterministic
        let fingerprint2 = key.spki_sha256_fingerprint().unwrap();
        assert_eq!(fingerprint, fingerprint2);
    }
}
