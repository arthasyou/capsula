use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use ed25519_dalek::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    Signature, Signer, SigningKey, VerifyingKey,
};

use crate::{
    error::{Error, Result},
    provider::KeyProvider,
    types::{Algorithm, KeyHandle},
};

pub struct Ed25519Provider {
    keys: Arc<Mutex<HashMap<KeyHandle, SigningKey>>>,
    next_handle: Arc<Mutex<u64>>,
}

impl Ed25519Provider {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            next_handle: Arc::new(Mutex::new(1)),
        }
    }

    fn generate_handle(&self) -> KeyHandle {
        let mut handle = self.next_handle.lock().unwrap();
        let current = *handle;
        *handle += 1;
        KeyHandle(current)
    }
}

impl Default for Ed25519Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for Ed25519Provider {
    fn generate(&self) -> Result<KeyHandle> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| Error::KeyError(format!("Failed to generate random bytes: {}", e)))?;
        let signing_key = SigningKey::from_bytes(&bytes);

        let handle = self.generate_handle();
        self.keys.lock().unwrap().insert(handle, signing_key);

        Ok(handle)
    }

    fn get_alg(&self) -> Result<Algorithm> {
        Ok(Algorithm::Ed25519)
    }

    fn import_pkcs8_der(&self, der: &[u8]) -> Result<KeyHandle> {
        let signing_key = SigningKey::from_pkcs8_der(der)
            .map_err(|e| Error::ImportError(format!("Failed to import PKCS8 DER: {}", e)))?;

        let handle = self.generate_handle();
        self.keys.lock().unwrap().insert(handle, signing_key);

        Ok(handle)
    }

    fn export_pkcs8_der(&self, handle: KeyHandle) -> Result<Vec<u8>> {
        let keys = self.keys.lock().unwrap();
        let signing_key = keys
            .get(&handle)
            .ok_or_else(|| Error::KeyError("Key handle not found".to_string()))?;

        signing_key
            .to_pkcs8_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| Error::ExportError(format!("Failed to export PKCS8 DER: {}", e)))
    }

    fn public_spki_der(&self, handle: KeyHandle) -> Result<Vec<u8>> {
        let keys = self.keys.lock().unwrap();
        let signing_key = keys
            .get(&handle)
            .ok_or_else(|| Error::KeyError("Key handle not found".to_string()))?;

        let verifying_key = signing_key.verifying_key();

        verifying_key
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| Error::ExportError(format!("Failed to export public key SPKI DER: {}", e)))
    }

    fn sign(&self, handle: KeyHandle, msg: &[u8]) -> Result<Vec<u8>> {
        let keys = self.keys.lock().unwrap();
        let signing_key = keys
            .get(&handle)
            .ok_or_else(|| Error::KeyError("Key handle not found".to_string()))?;

        let signature = signing_key.sign(msg);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, spki_der: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        let verifying_key = VerifyingKey::from_public_key_der(spki_der)
            .map_err(|e| Error::KeyError(format!("Failed to parse public key: {}", e)))?;

        let signature = Signature::from_slice(sig)
            .map_err(|e| Error::SignatureError(format!("Invalid signature format: {}", e)))?;

        Ok(verifying_key.verify_strict(msg, &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign() {
        let provider = Ed25519Provider::new();

        // Generate a key
        let handle = provider.generate().unwrap();

        // Sign a message
        let message = b"Hello, world!";
        let signature = provider.sign(handle, message).unwrap();

        // Get public key
        let public_key = provider.public_spki_der(handle).unwrap();

        // Verify signature
        let is_valid = provider.verify(&public_key, message, &signature).unwrap();
        assert!(is_valid);

        // Verify with wrong message should fail
        let wrong_message = b"Hello, world";
        let is_valid = provider
            .verify(&public_key, wrong_message, &signature)
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_import_export() {
        let provider = Ed25519Provider::new();

        // Generate a key
        let handle1 = provider.generate().unwrap();

        // Export as PKCS8 DER
        let der = provider.export_pkcs8_der(handle1).unwrap();

        // Import the key
        let handle2 = provider.import_pkcs8_der(&der).unwrap();

        // Sign with both handles and verify they produce the same signature
        let message = b"Test message";
        let sig1 = provider.sign(handle1, message).unwrap();
        let sig2 = provider.sign(handle2, message).unwrap();

        assert_eq!(sig1, sig2);

        // Verify both public keys are the same
        let pub1 = provider.public_spki_der(handle1).unwrap();
        let pub2 = provider.public_spki_der(handle2).unwrap();

        assert_eq!(pub1, pub2);
    }
}
