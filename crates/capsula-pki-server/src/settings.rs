use serde::Deserialize;
use toolcraft_config::load_settings;

use crate::error::Result;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub http: HttpCfg,
    pub pki: PkiCfg,
    pub surrealdb: crate::db::SurrealdbCfg,
}

#[derive(Debug, Deserialize)]
pub struct HttpCfg {
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PkiCfg {
    /// PKI data directory
    pub data_dir: String,
    
    // CA storage paths
    pub root_ca_path: String,
    pub intermediate_ca_path: String,
    
    // PKI settings
    pub default_validity_days: u32,
    pub root_ca_validity_days: u32,
    pub intermediate_ca_validity_days: u32,
    
    // Security settings
    pub min_key_size_rsa: u32,
    pub require_strong_passwords: bool,
}

impl Default for PkiCfg {
    fn default() -> Self {
        Self {
            data_dir: "./pki_data".to_string(),
            
            // CA paths
            root_ca_path: "./pki_data/ca/root".to_string(),
            intermediate_ca_path: "./pki_data/ca/intermediate".to_string(),
            
            // PKI settings - use RSA 2048 algorithm
            default_validity_days: 365,
            root_ca_validity_days: 7300,    // 20 years for root CA
            intermediate_ca_validity_days: 3650,  // 10 years for intermediate CA
            
            // Security - RSA 2048 minimum
            min_key_size_rsa: 2048,
            require_strong_passwords: false,  // Simplified for development
        }
    }
}

impl Settings {
    pub fn load(config_path: &str) -> Result<Self> {
        let r = load_settings(config_path)?;
        Ok(r)
    }
}
