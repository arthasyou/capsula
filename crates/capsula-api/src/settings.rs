use serde::Deserialize;
use toolcraft_config::load_settings;

use crate::error::Result;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub http: HttpCfg,
    pub pki: PkiCfg,
}

#[derive(Debug, Deserialize)]
pub struct HttpCfg {
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct PkiCfg {
    /// CA storage path
    pub ca_storage_path: String,
    /// Certificate storage path
    pub cert_storage_path: String,
    /// Default certificate validity days
    pub default_validity_days: u32,
}

impl Default for PkiCfg {
    fn default() -> Self {
        Self {
            ca_storage_path: "./storage/ca".to_string(),
            cert_storage_path: "./storage/certificates".to_string(),
            default_validity_days: 365,
        }
    }
}

impl Settings {
    pub fn load(config_path: &str) -> Result<Self> {
        let r = load_settings(config_path)?;
        Ok(r)
    }
}
