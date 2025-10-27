use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
};
use pkcs8::{DecodePublicKey, LineEnding};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub struct Ed25519 {
    pub inner: SigningKey,
}

impl From<SigningKey> for Ed25519 {
    fn from(value: SigningKey) -> Self {
        Self { inner: value }
    }
}

impl Ed25519 {
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::GetrandomError(e.to_string()))?;
        Ok(SigningKey::from_bytes(&seed).into())
    }

    pub fn from_raw_seed(seed: &[u8; 32]) -> Self {
        SigningKey::from_bytes(seed).into()
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_der(der)?;
        Ok(signing_key.into())
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)?;
        Ok(signing_key.into())
    }
}

impl Ed25519 {
    /// Export the private key as raw bytes
    pub fn to_seed_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Get the public key for this keypair
    pub fn public_key(&self) -> VerifyingKey {
        self.inner.verifying_key()
    }

    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        let der = self.inner.to_pkcs8_der()?;
        Ok(der.as_bytes().to_vec())
    }

    pub fn to_pkcs8_pem(&self) -> Result<String> {
        let pem = self.inner.to_pkcs8_pem(LineEnding::LF)?;
        Ok(pem.to_string())
    }

    pub fn to_spki_der(&self) -> Result<Vec<u8>> {
        let der = self.public_key().to_public_key_der()?;
        Ok(der.as_bytes().to_vec())
    }

    pub fn to_spki_pem(&self) -> Result<String> {
        let pem = self.public_key().to_public_key_pem(LineEnding::LF)?;
        Ok(pem)
    }

    pub fn to_jwk(&self) -> Result<String> {
        let public_key = self.inner.verifying_key();
        // compute SPKI fingerprint as kid
        let spki = self.inner.verifying_key().to_public_key_der()?;
        let fp: [u8; 32] = Sha256::digest(spki.as_bytes()).into();
        let kid = general_purpose::URL_SAFE_NO_PAD.encode(fp);
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": general_purpose::URL_SAFE_NO_PAD.encode(public_key.to_bytes()),
            "kid": kid
        });
        Ok(jwk.to_string())
    }
}

impl Ed25519 {
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signature = self.inner.sign(message);
        signature.to_bytes()
    }

    pub fn spki_sha256_fingerprint(&self) -> Result<[u8; 32]> {
        let spki = self.to_spki_der()?;
        Ok(Sha256::digest(&spki).into())
    }
}

/// Verify Ed25519 signature with raw bytes (for internal/test use)
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let verifying_key = match public_key_from_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(signature);
    verifying_key.verify(message, &signature).is_ok()
}

/// Verify Ed25519 signature with standard SPKI DER interface
pub fn verify_with_spki_der(spki_der: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    // Parse Ed25519 public key from SPKI DER
    let verifying_key = public_key_from_spki_der(spki_der)?;

    // Signature must be exactly 64 bytes for Ed25519
    if signature.len() != 64 {
        return Ok(false);
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature);
    let signature_obj = Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(message, &signature_obj).is_ok())
}

pub fn public_key_from_spki_der(der: &[u8]) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_der(der).map_err(Into::into)
}

pub fn public_key_from_spki_pem(pem: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_pem(pem).map_err(Into::into)
}

pub fn public_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).map_err(Into::into)
}
