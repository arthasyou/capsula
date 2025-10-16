use serde::Deserialize;
use toolcraft_config::load_settings;

use crate::error::Result;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub http: HttpCfg,
    pub surrealdb: crate::db::SurrealdbCfg,
    pub key: KeyCfg,
    pub storage: StorageCfg,
    pub upload: UploadCfg,
}

#[derive(Debug, Deserialize)]
pub struct HttpCfg {
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct KeyCfg {
    pub private_key_path: String,
}

#[derive(Debug, Deserialize)]
pub struct StorageCfg {
    /// 存储根目录
    pub root_dir: String,
    /// URL 前缀
    pub url_prefix: String,
}

#[derive(Debug, Deserialize)]
pub struct UploadCfg {
    /// 临时文件目录
    pub temp_dir: String,
    /// 最大文件大小（字节）
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,
    /// 允许的 MIME 类型列表（空表示允许所有）
    #[serde(default)]
    pub allowed_mime_types: Vec<String>,
}

fn default_max_file_size() -> usize {
    100 * 1024 * 1024 // 100 MB
}

impl Settings {
    pub fn load(config_path: &str) -> Result<Self> {
        let r = load_settings(config_path)?;
        Ok(r)
    }
}
