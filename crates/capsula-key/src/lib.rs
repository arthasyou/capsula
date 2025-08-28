pub mod encoding;
pub mod error;
pub mod hash;
pub mod impls;
pub mod ops;
pub mod provider;
pub mod signature;
pub mod store;
pub mod types;
pub mod util;

// 重新导出常用的哈希功能
pub use hash::{hash_data, hash_data_hex, sha256, sha512, verify_hash, HashAlgorithm};
// 重新导出签名相关类型
pub use signature::{
    verify_signature_standalone, DigitalSignature, ExtendedSignatureInfo, LocationInfo,
};
