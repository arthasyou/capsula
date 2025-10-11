use std::sync::OnceLock;

use capsula_key::RsaKey;

use crate::error::{AppError, Result};

/// Static holder for the system RSA key, initialized once
static SYSTEM_RSA_KEY: OnceLock<RsaKey> = OnceLock::new();

/// Initialize the system RSA key from the configured path
/// This MUST be called once during application startup in main()
/// If initialization fails, the application should panic and not start
pub fn init_system_key(private_key_path: &str) -> Result<()> {
    // Read the PEM file content
    let pem_content = std::fs::read_to_string(private_key_path)
        .map_err(|e| AppError::IoError(e))?;

    // Parse the RSA key from PEM
    let key = RsaKey::from_pkcs8_pem(&pem_content)
        .map_err(|e| AppError::Internal(format!("Failed to load system private key from {}: {}", private_key_path, e)))?;

    // Store the key in the static holder
    SYSTEM_RSA_KEY
        .set(key)
        .map_err(|_| AppError::Internal("System RSA key already initialized".to_string()))?;

    Ok(())
}

/// Get a reference to the system RSA key
///
/// # Panics
/// Panics if the key has not been initialized via init_system_key()
/// This should never happen in production if init_system_key() is called in main()
#[inline]
pub fn get_system_key() -> &'static RsaKey {
    SYSTEM_RSA_KEY
        .get()
        .expect("System RSA key not initialized. init_system_key() must be called in main() before starting the server.")
}
