// pub mod api;
pub mod capsule;

pub mod audit;
pub mod block;
pub mod error;
pub mod integrity;
pub mod keyring;
pub mod policy;
pub mod types;

// pub mod decapsulator;
// pub mod encapsulator;

// Re-export commonly used types
// pub use api::{create_medical_capsule, decrypt_medical_capsule_rsa, CapsulaApi};
// pub use decapsulator::{CapsuleDecryptor, DecapsulationResult, VerificationInfo};
// pub use encapsulator::CapsulaBuilder;
pub use error::{CoreError, Result};
pub use keyring::{KeyWrap, Keyring};
pub use types::*;
