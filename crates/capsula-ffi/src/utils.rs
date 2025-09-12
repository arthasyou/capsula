//! FFI utility functions

use capsula_key::{Curve25519, P256Key, RsaKey};
use crate::types::CapsulaAlgorithm;

// ============================================================================
// Helper Functions
// ============================================================================

/// Auto-detect algorithm from PKCS8 DER private key
pub fn detect_algorithm_from_der(der_data: &[u8]) -> Option<CapsulaAlgorithm> {
    // Try to import as different algorithms to detect which one works
    if Curve25519::from_pkcs8_der(der_data).is_ok() {
        Some(CapsulaAlgorithm::Curve25519)
    } else if RsaKey::from_pkcs8_der(der_data).is_ok() {
        Some(CapsulaAlgorithm::Rsa2048)
    } else if P256Key::from_pkcs8_der(der_data).is_ok() {
        Some(CapsulaAlgorithm::P256)
    } else {
        None
    }
}