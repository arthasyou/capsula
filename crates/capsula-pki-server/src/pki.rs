use std::{fs, path::Path};

use tracing::{error, info, warn};

use crate::{
    error::{AppError, Result},
    settings::PkiCfg,
};

pub struct PkiManager {
    pub config: PkiCfg,
    pub root_ca_cert: Option<String>,
    pub intermediate_ca_cert: Option<String>,
    pub ca_chain: Option<String>,
}

impl PkiManager {
    pub fn new(config: PkiCfg) -> Self {
        Self {
            config,
            root_ca_cert: None,
            intermediate_ca_cert: None,
            ca_chain: None,
        }
    }

    /// Initialize PKI manager by loading existing certificates or checking if initialization is
    /// needed
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing PKI Manager...");

        // Check if PKI data directory exists
        if !Path::new(&self.config.data_dir).exists() {
            warn!("PKI data directory not found: {}", self.config.data_dir);
            warn!("Please run './init_pki.sh' to initialize PKI infrastructure");
            return Ok(());
        }

        // Check if PKI is initialized
        let init_marker = format!("{}/.initialized", self.config.data_dir);
        if !Path::new(&init_marker).exists() {
            warn!("PKI not initialized. Please run './init_pki.sh' first");
            return Ok(());
        }

        info!("PKI infrastructure detected, loading certificates...");
        self.load_certificates().await?;
        self.verify_certificates().await?;

        info!("PKI Manager initialized successfully");
        Ok(())
    }

    /// Load CA certificates from disk
    async fn load_certificates(&mut self) -> Result<()> {
        let root_cert_path = format!("{}/certs/ca.cert.pem", self.config.root_ca_path);
        let intermediate_cert_path = format!(
            "{}/certs/intermediate.cert.pem",
            self.config.intermediate_ca_path
        );
        let ca_chain_path = format!(
            "{}/certs/ca-chain.cert.pem",
            self.config.intermediate_ca_path
        );

        // Load Root CA certificate
        if Path::new(&root_cert_path).exists() {
            match fs::read_to_string(&root_cert_path) {
                Ok(cert) => {
                    self.root_ca_cert = Some(cert);
                    info!("Root CA certificate loaded from: {}", root_cert_path);
                }
                Err(e) => {
                    error!("Failed to read Root CA certificate: {}", e);
                    return Err(e.into());
                }
            }
        } else {
            warn!("Root CA certificate not found: {}", root_cert_path);
        }

        // Load Intermediate CA certificate
        if Path::new(&intermediate_cert_path).exists() {
            match fs::read_to_string(&intermediate_cert_path) {
                Ok(cert) => {
                    self.intermediate_ca_cert = Some(cert);
                    info!(
                        "Intermediate CA certificate loaded from: {}",
                        intermediate_cert_path
                    );
                }
                Err(e) => {
                    error!("Failed to read Intermediate CA certificate: {}", e);
                    return Err(e.into());
                }
            }
        } else {
            warn!(
                "Intermediate CA certificate not found: {}",
                intermediate_cert_path
            );
        }

        // Load CA chain
        if Path::new(&ca_chain_path).exists() {
            match fs::read_to_string(&ca_chain_path) {
                Ok(chain) => {
                    self.ca_chain = Some(chain);
                    info!("CA certificate chain loaded from: {}", ca_chain_path);
                }
                Err(e) => {
                    error!("Failed to read CA certificate chain: {}", e);
                    return Err(e.into());
                }
            }
        } else {
            warn!("CA certificate chain not found: {}", ca_chain_path);
        }

        Ok(())
    }

    /// Verify loaded certificates
    async fn verify_certificates(&self) -> Result<()> {
        info!("Verifying loaded certificates...");

        if let Some(ref root_cert) = self.root_ca_cert {
            // Basic validation: check if certificate starts and ends correctly
            if root_cert.contains("-----BEGIN CERTIFICATE-----")
                && root_cert.contains("-----END CERTIFICATE-----")
            {
                info!("Root CA certificate format validation passed");
            } else {
                error!("Root CA certificate format validation failed");
                return Err(AppError::PkiError(
                    "Invalid Root CA certificate format".to_string(),
                ));
            }
        }

        if let Some(ref intermediate_cert) = self.intermediate_ca_cert {
            if intermediate_cert.contains("-----BEGIN CERTIFICATE-----")
                && intermediate_cert.contains("-----END CERTIFICATE-----")
            {
                info!("Intermediate CA certificate format validation passed");
            } else {
                error!("Intermediate CA certificate format validation failed");
                return Err(AppError::PkiError(
                    "Invalid Intermediate CA certificate format".to_string(),
                ));
            }
        }

        if let Some(ref ca_chain) = self.ca_chain {
            // CA chain should contain both certificates
            let cert_count = ca_chain.matches("-----BEGIN CERTIFICATE-----").count();
            if cert_count >= 2 {
                info!("CA certificate chain contains {} certificates", cert_count);
            } else {
                warn!(
                    "CA certificate chain may be incomplete (found {} certificates)",
                    cert_count
                );
            }
        }

        info!("Certificate verification completed");
        Ok(())
    }

    /// Get Root CA certificate in PEM format
    pub fn get_root_ca_cert(&self) -> Option<&String> {
        self.root_ca_cert.as_ref()
    }

    /// Get Intermediate CA certificate in PEM format
    pub fn get_intermediate_ca_cert(&self) -> Option<&String> {
        self.intermediate_ca_cert.as_ref()
    }

    /// Get CA certificate chain in PEM format
    pub fn get_ca_chain(&self) -> Option<&String> {
        self.ca_chain.as_ref()
    }

    /// Check if PKI is fully initialized and ready
    pub fn is_ready(&self) -> bool {
        self.root_ca_cert.is_some()
            && self.intermediate_ca_cert.is_some()
            && self.ca_chain.is_some()
    }

    /// Get CA status information
    pub fn get_ca_status(&self) -> CaStatus {
        CaStatus {
            root_ca_available: self.root_ca_cert.is_some(),
            intermediate_ca_available: self.intermediate_ca_cert.is_some(),
            ca_chain_available: self.ca_chain.is_some(),
            pki_ready: self.is_ready(),
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct CaStatus {
    pub root_ca_available: bool,
    pub intermediate_ca_available: bool,
    pub ca_chain_available: bool,
    pub pki_ready: bool,
}
