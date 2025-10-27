//! Capsula 统一 API 层
//!
//! 作为所有语言绑定的标准接口规范，保证跨语言的功能对齐和一致性。
//!
//! # 设计理念
//!
//! - **跨语言统一接口**：所有语言绑定必须遵循此标准
//! - **保留类型信息**：使用 enum 包装避免丢失类型优势
//! - **统一错误处理**：提供一致的错误类型和处理方式
//! - **便捷的格式转换**：支持 DER、PEM、Base64、JSON 等格式
//! - **算法自动检测**：智能识别密钥算法类型
//!
//! # 模块结构
//!
//! - `keypair`: 密钥对生成、导入、导出（核心接口）
//! - `signing`: 数字签名操作
//! - `encoding`: 格式编码转换（Base64、Hex等）
//! - `error`: 统一错误类型
//!
//! # 使用示例
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use capsula_api::{KeyPair, Algorithm};
//!
//! // 生成密钥对
//! let keypair = KeyPair::generate(Algorithm::Curve25519)?;
//!
//! // 导出为 PEM
//! let private_pem = keypair.private_key_to_pem()?;
//! let public_pem = keypair.public_key_to_pem()?;
//!
//! // 导出为 JSON（跨语言传输）
//! let json = keypair.to_json()?;
//!
//! // 从 JSON 导入
//! let restored = KeyPair::from_json(&json)?;
//! # Ok(())
//! # }
//! ```
//!
//! # 语言绑定示例
//!
//! 所有语言都应该提供相同的接口：
//!
//! Python:
//! ```python
//! keypair = KeyPair.generate(Algorithm.CURVE25519)
//! json_str = keypair.to_json()
//! ```
//!
//! Java (Android):
//! ```java
//! KeyPair keypair = KeyPair.generate(Algorithm.CURVE25519);
//! String json = keypair.toJson();
//! ```
//!
//! JavaScript:
//! ```javascript
//! const keypair = KeyPair.generate(Algorithm.CURVE25519);
//! const json = keypair.toJson();
//! ```

pub mod error;
pub mod key;
pub mod signing;
pub mod encoding;

// Re-export commonly used types
pub use error::{ApiError, Result};
pub use key::{Algorithm, KeyPair, Base64KeyPair};
pub use signing::SigningApi;
pub use encoding::EncodingApi;
