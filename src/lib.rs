//! # Capsula - 数据胶囊
//!
//! 安全的数据封装和管理系统
//!
//! ## 模块
//!
//! - `capsula_crypto` - 基础加密原语
//! - `capsula_pki` - PKI 基础设施
//! - `capsula_core` - 核心功能
//! - `capsula_api` - API 服务
//! - `capsula_cli` - 命令行工具

// Re-export all sub-crates
pub use capsula_api;
pub use capsula_core;
pub use capsula_pki;
