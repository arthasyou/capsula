mod key;
mod hash;
mod signature;
mod utils;

pub use key::*;
pub use hash::*;
pub use signature::*;

use wasm_bindgen::prelude::*;

/// 初始化 panic hook，用于更好的错误信息
#[wasm_bindgen(start)]
pub fn init() {
    utils::set_panic_hook();
}

/// 获取版本信息
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}