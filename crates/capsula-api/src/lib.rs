//! 数据胶囊API服务库
//!
//! 该库提供数据胶囊的API服务接口

pub mod error;

// Re-exports
pub use error::{ApiError, Result};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        // TODO: Add tests
    }
}
