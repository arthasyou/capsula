pub mod aad;
pub mod audit;
pub mod block;
pub mod builder;
pub mod capsule;
pub mod error;
pub mod integrity;
pub mod keyring;
pub mod policy;
pub mod state;
pub mod types;
pub mod upload;

// Re-export commonly used types
// pub use api::{create_medical_capsule, decrypt_medical_capsule_rsa, CapsulaApi};
// pub use decapsulator::{CapsuleDecryptor, DecapsulationResult, VerificationInfo};
// pub use encapsulator::CapsulaBuilder;
pub use capsule::{Cap0, Cap1, Cap1Summary, ZkpProof, Cap2, RefEntry, RefMetadata, Capsule, CapsuleHeader, CapsulePayload, PolicyControl, CapsuleIntegrity};
pub use error::{CoreError, Result};
pub use keyring::{KeyWrap, Keyring};
pub use state::{CapsuleState, StateTransitionError, UploadMeta, UploadVerification};
pub use upload::{UploadTask, UploadTaskState, UploadTaskManager, UploadPriority};
pub use aad::{AadBinding, AadBinder, AadValidator, AadValidationResult, AadContext};
pub use builder::{CapsuleBuilder, Cap0Builder, Cap1Builder, Cap2Builder, SealedBlockBuilder};
pub use types::*;
