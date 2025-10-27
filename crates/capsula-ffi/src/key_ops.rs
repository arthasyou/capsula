//! Key generation, import/export operations

use std::{
    ffi::CStr,
    os::raw::{c_char, c_uchar, c_uint},
};

use capsula_key::{Curve25519, KeyExport, P256Key, RsaKey};

use crate::types::{CapsulaAlgorithm, CapsulaError, CapsulaResult};

// ============================================================================
// Key Management Functions
// ============================================================================

/// Generate a new key pair with specified algorithm
#[no_mangle]
pub extern "C" fn capsula_key_generate(algorithm: CapsulaAlgorithm) -> *mut CapsulaResult {
    match algorithm {
        CapsulaAlgorithm::Curve25519 => match Curve25519::generate() {
            Ok(key) => match key.to_pkcs8_der() {
                Ok(private_key_der) => CapsulaResult::success_boxed(private_key_der),
                Err(e) => CapsulaResult::error_boxed(
                    CapsulaError::ExportFailed,
                    &format!("Failed to export private key: {}", e),
                ),
            },
            Err(e) => CapsulaResult::error_boxed(
                CapsulaError::KeyGenerationFailed,
                &format!("Curve25519 key generation failed: {}", e),
            ),
        },
        CapsulaAlgorithm::Rsa2048 => match RsaKey::generate_2048() {
            Ok(key) => match key.to_pkcs8_der() {
                Ok(private_key_der) => CapsulaResult::success_boxed(private_key_der),
                Err(e) => CapsulaResult::error_boxed(
                    CapsulaError::ExportFailed,
                    &format!("Failed to export private key: {}", e),
                ),
            },
            Err(e) => CapsulaResult::error_boxed(
                CapsulaError::KeyGenerationFailed,
                &format!("RSA key generation failed: {}", e),
            ),
        },
        CapsulaAlgorithm::P256 => match P256Key::generate() {
            Ok(key) => match key.to_pkcs8_der() {
                Ok(private_key_der) => CapsulaResult::success_boxed(private_key_der),
                Err(e) => CapsulaResult::error_boxed(
                    CapsulaError::ExportFailed,
                    &format!("Failed to export private key: {}", e),
                ),
            },
            Err(e) => CapsulaResult::error_boxed(
                CapsulaError::KeyGenerationFailed,
                &format!("P256 key generation failed: {}", e),
            ),
        },
    }
}

/// Import private key from PEM file (auto-detect algorithm)
#[no_mangle]
pub extern "C" fn capsula_key_import_from_file(file_path: *const c_char) -> *mut CapsulaResult {
    if file_path.is_null() {
        return CapsulaResult::error_boxed(CapsulaError::InvalidInput, "File path pointer is null");
    }

    let path_str = unsafe {
        match CStr::from_ptr(file_path).to_str() {
            Ok(s) => s,
            Err(_) => {
                return CapsulaResult::error_boxed(
                    CapsulaError::InvalidInput,
                    "Invalid file path string",
                )
            }
        }
    };

    // Read PEM file
    let pem_content = match std::fs::read_to_string(path_str) {
        Ok(content) => content,
        Err(e) => {
            return CapsulaResult::error_boxed(
                CapsulaError::IoError,
                &format!("Failed to read file: {}", e),
            )
        }
    };

    // Try to import with each algorithm until one succeeds
    // Try Curve25519 first
    if let Ok(key) = Curve25519::from_pkcs8_pem(&pem_content) {
        match key.to_pkcs8_der() {
            Ok(private_key_der) => return CapsulaResult::success_boxed(private_key_der),
            Err(e) => {
                return CapsulaResult::error_boxed(
                    CapsulaError::ExportFailed,
                    &format!("Failed to export Curve25519 private key: {}", e),
                )
            }
        }
    }

    // Try RSA
    if let Ok(key) = RsaKey::from_pkcs8_pem(&pem_content) {
        match key.to_pkcs8_der() {
            Ok(private_key_der) => return CapsulaResult::success_boxed(private_key_der),
            Err(e) => {
                return CapsulaResult::error_boxed(
                    CapsulaError::ExportFailed,
                    &format!("Failed to export RSA private key: {}", e),
                )
            }
        }
    }

    // Try P256
    if let Ok(key) = P256Key::from_pkcs8_pem(&pem_content) {
        match key.to_pkcs8_der() {
            Ok(private_key_der) => return CapsulaResult::success_boxed(private_key_der),
            Err(e) => {
                return CapsulaResult::error_boxed(
                    CapsulaError::ExportFailed,
                    &format!("Failed to export P256 private key: {}", e),
                )
            }
        }
    }

    // If none worked, return error
    CapsulaResult::error_boxed(
        CapsulaError::ImportFailed,
        "Unable to import key with any supported algorithm (Curve25519, RSA, P256)",
    )
}

/// Export private key to PEM file (auto-detect algorithm)
#[no_mangle]
pub extern "C" fn capsula_key_export_to_file(
    private_key_der: *const c_uchar,
    key_len: c_uint,
    file_path: *const c_char,
) -> *mut CapsulaResult {
    if private_key_der.is_null() || file_path.is_null() {
        return CapsulaResult::error_boxed(CapsulaError::InvalidInput, "Input pointers are null");
    }

    let key_slice = unsafe { std::slice::from_raw_parts(private_key_der, key_len as usize) };
    let path_str = unsafe {
        match CStr::from_ptr(file_path).to_str() {
            Ok(s) => s,
            Err(_) => {
                return CapsulaResult::error_boxed(
                    CapsulaError::InvalidInput,
                    "Invalid file path string",
                )
            }
        }
    };

    // Auto-detect algorithm
    let algorithm = match crate::utils::detect_algorithm_from_der(key_slice) {
        Some(alg) => alg,
        None => {
            return CapsulaResult::error_boxed(
                CapsulaError::ImportFailed,
                "Unable to detect key algorithm from DER data",
            )
        }
    };

    match algorithm {
        CapsulaAlgorithm::Curve25519 => match Curve25519::from_pkcs8_der(key_slice) {
            Ok(key) => match key.to_pkcs8_pem() {
                Ok(pem_content) => match std::fs::write(path_str, pem_content) {
                    Ok(_) => CapsulaResult::success_boxed(vec![]),
                    Err(e) => CapsulaResult::error_boxed(
                        CapsulaError::IoError,
                        &format!("Failed to write file: {}", e),
                    ),
                },
                Err(e) => CapsulaResult::error_boxed(
                    CapsulaError::ExportFailed,
                    &format!("Failed to export Curve25519 private key: {}", e),
                ),
            },
            Err(e) => CapsulaResult::error_boxed(
                CapsulaError::ImportFailed,
                &format!("Failed to import Curve25519 private key: {}", e),
            ),
        },
        CapsulaAlgorithm::Rsa2048 => match RsaKey::from_pkcs8_der(key_slice) {
            Ok(key) => match key.to_pkcs8_pem() {
                Ok(pem_content) => match std::fs::write(path_str, pem_content) {
                    Ok(_) => CapsulaResult::success_boxed(vec![]),
                    Err(e) => CapsulaResult::error_boxed(
                        CapsulaError::IoError,
                        &format!("Failed to write file: {}", e),
                    ),
                },
                Err(e) => CapsulaResult::error_boxed(
                    CapsulaError::ExportFailed,
                    &format!("Failed to export RSA private key: {}", e),
                ),
            },
            Err(e) => CapsulaResult::error_boxed(
                CapsulaError::ImportFailed,
                &format!("Failed to import RSA private key: {}", e),
            ),
        },
        CapsulaAlgorithm::P256 => match P256Key::from_pkcs8_der(key_slice) {
            Ok(key) => match key.to_pkcs8_pem() {
                Ok(pem_content) => match std::fs::write(path_str, pem_content) {
                    Ok(_) => CapsulaResult::success_boxed(vec![]),
                    Err(e) => CapsulaResult::error_boxed(
                        CapsulaError::IoError,
                        &format!("Failed to write file: {}", e),
                    ),
                },
                Err(e) => CapsulaResult::error_boxed(
                    CapsulaError::ExportFailed,
                    &format!("Failed to export P256 private key: {}", e),
                ),
            },
            Err(e) => CapsulaResult::error_boxed(
                CapsulaError::ImportFailed,
                &format!("Failed to import P256 private key: {}", e),
            ),
        },
    }
}
