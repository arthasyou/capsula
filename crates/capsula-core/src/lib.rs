pub mod audit;
pub mod block;
pub mod capsule;
pub mod error;
pub mod integrity;
pub mod keyring;
pub mod policy;
pub mod state;
pub mod types;

// Re-export commonly used types
// pub use api::{create_medical_capsule, decrypt_medical_capsule_rsa, CapsulaApi};
// pub use decapsulator::{CapsuleDecryptor, DecapsulationResult, VerificationInfo};
// pub use encapsulator::CapsulaBuilder;
pub use error::{CoreError, Result};
pub use keyring::{KeyWrap, Keyring};
pub use state::{CapsuleState, StateTransitionError, UploadMeta, UploadVerification};
pub use types::*;
