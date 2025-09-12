//! Digital signature operations

use std::os::raw::{c_uchar, c_uint};

use capsula_key::{Curve25519, KeySign, P256Key, RsaKey};

use crate::{
    types::{CapsulaAlgorithm, CapsulaError, CapsulaResult},
    utils::detect_algorithm_from_der,
};

// ============================================================================
// Signing Functions
// ============================================================================

/// Sign a message with auto-detected algorithm
#[no_mangle]
pub extern "C" fn capsula_sign(
    private_key_der: *const c_uchar,
    key_len: c_uint,
    message: *const c_uchar,
    message_len: c_uint,
) -> *mut CapsulaResult {
    if private_key_der.is_null() || message.is_null() {
        return CapsulaResult::error_boxed(
            CapsulaError::InvalidInput,
            "Input pointers are null",
        );
    }

    let key_slice = unsafe { std::slice::from_raw_parts(private_key_der, key_len as usize) };
    let message_slice = unsafe { std::slice::from_raw_parts(message, message_len as usize) };

    // Auto-detect algorithm
    let algorithm = match detect_algorithm_from_der(key_slice) {
        Some(alg) => alg,
        None => {
            return CapsulaResult::error_boxed(
                CapsulaError::ImportFailed,
                "Unable to detect key algorithm from DER data",
            )
        }
    };

    // Use the detected algorithm to sign
    match algorithm {
        CapsulaAlgorithm::Curve25519 => match Curve25519::from_pkcs8_der(key_slice) {
            Ok(key) => match key.sign(message_slice) {
                Ok(signature) => CapsulaResult::success_boxed(signature),
                Err(e) => CapsulaResult::error_boxed(
                    CapsulaError::SigningFailed,
                    &format!("Curve25519 signing failed: {}", e),
                ),
            },
            Err(e) => CapsulaResult::error_boxed(
                CapsulaError::ImportFailed,
                &format!("Failed to import Curve25519 private key: {}", e),
            ),
        },
        CapsulaAlgorithm::Rsa2048 => match RsaKey::from_pkcs8_der(key_slice) {
            Ok(key) => match key.sign(message_slice) {
                Ok(signature) => CapsulaResult::success_boxed(signature),
                Err(e) => CapsulaResult::error_boxed(
                    CapsulaError::SigningFailed,
                    &format!("RSA signing failed: {}", e),
                ),
            },
            Err(e) => CapsulaResult::error_boxed(
                CapsulaError::ImportFailed,
                &format!("Failed to import RSA private key: {}", e),
            ),
        },
        CapsulaAlgorithm::P256 => match P256Key::from_pkcs8_der(key_slice) {
            Ok(key) => match key.sign(message_slice) {
                Ok(signature) => CapsulaResult::success_boxed(signature),
                Err(e) => CapsulaResult::error_boxed(
                    CapsulaError::SigningFailed,
                    &format!("P256 signing failed: {}", e),
                ),
            },
            Err(e) => CapsulaResult::error_boxed(
                CapsulaError::ImportFailed,
                &format!("Failed to import P256 private key: {}", e),
            ),
        },
    }
}
