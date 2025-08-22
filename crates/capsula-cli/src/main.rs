//! 数据胶囊命令行工具

use capsula_api::ApiError;

fn main() -> Result<(), ApiError> {
    println!("Capsula CLI - 数据胶囊命令行工具");
    println!("版本: {}", env!("CARGO_PKG_VERSION"));

    // TODO: 实现命令行参数解析和功能

    Ok(())
}
