//! 服务层模块
//!
//! 提供各种业务逻辑服务

pub mod bnf_parser;
pub mod capsule_sealer;
pub mod error;
pub mod metadata_gen;
pub mod storage;
pub mod temp_file;
pub mod text_extractor;

// 重新导出常用类型
pub use bnf_parser::{BnfData, BnfParser, BnfRule, SimpleBnfParser};
pub use capsule_sealer::{CapsuleSealer, SealRequest, SealResponse};
pub use error::{ServiceError, ServiceResult};
pub use metadata_gen::{FileMetadata, MetadataGenerator};
pub use storage::{LocalStorage, StorageProvider};
pub use temp_file::TempFileGuard;
pub use text_extractor::{SimpleTextExtractor, TextExtractor};
