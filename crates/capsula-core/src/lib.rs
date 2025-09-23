pub mod aad;
pub mod audit;
pub mod block;
pub mod capsule;
pub mod error;
pub mod integrity;
pub mod keyring;
pub mod policy;
pub mod types;

// Re-export commonly used types
// pub use api::{create_medical_capsule, decrypt_medical_capsule_rsa, CapsulaApi};
// pub use decapsulator::{CapsuleDecryptor, DecapsulationResult, VerificationInfo};
// pub use encapsulator::CapsulaBuilder;
pub use capsule::{Cap0, Cap0ExternalSeal, Cap1, Cap1Summary, ZkpProof, Cap2, RefEntry, RefMetadata, Capsule, CapsuleHeader, CapsulePayload, CapsuleContent, PolicyControl, CapsuleIntegrity};
pub use error::{CoreError, Result};
pub use keyring::{KeyWrap, Keyring};
pub use aad::{AadBinding, AadBinder, AadValidator, AadValidationResult, AadContext};
pub use types::*;
