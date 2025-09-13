pub mod error;
pub mod protocol;
pub mod encapsulator;
pub mod decapsulator;
pub mod api;

// Re-export commonly used types
pub use error::{CoreError, Result};
pub use protocol::capsule::*;
pub use protocol::types::*;
pub use encapsulator::CapsulaBuilder;
pub use decapsulator::{CapsuleDecryptor, DecapsulationResult, VerificationInfo};
pub use api::{CapsulaApi, create_medical_capsule, decrypt_medical_capsule_rsa};
