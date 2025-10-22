use std::sync::Arc;

use tokio::sync::RwLock;

use crate::pki::PkiManager;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub pki_manager: Arc<RwLock<PkiManager>>,
}

impl AppState {
    pub fn new(pki_manager: PkiManager) -> Self {
        Self {
            pki_manager: Arc::new(RwLock::new(pki_manager)),
        }
    }
}
