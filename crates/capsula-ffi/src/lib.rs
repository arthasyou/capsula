//! FFI bindings for capsula-key cryptographic operations
//! 
//! Simple FFI interface with basic key operations: generate, import, sign, export.

pub mod types;
pub mod utils;
pub mod key_ops;
pub mod signing;
pub mod memory;

// Re-export public types for cbindgen
pub use types::*;

// Re-export all FFI functions for cbindgen
pub use key_ops::*;
pub use signing::*;
pub use memory::*;