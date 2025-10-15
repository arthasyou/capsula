// API version modules
pub mod v1;
pub mod v2;

// Legacy modules for backward compatibility
// These re-export v1 handlers to maintain existing code compatibility
pub use v1::authorization;
pub use v1::capsule;
