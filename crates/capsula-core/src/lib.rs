pub mod api;
pub mod capsule;
pub mod decapsulator;
pub mod encapsulator;
pub mod error;
pub mod protocol;

// Re-export commonly used types
pub use api::{create_medical_capsule, decrypt_medical_capsule_rsa, CapsulaApi};
pub use decapsulator::{CapsuleDecryptor, DecapsulationResult, VerificationInfo};
pub use encapsulator::CapsulaBuilder;
pub use error::{CoreError, Result};
pub use protocol::{capsule::*, types::*};
