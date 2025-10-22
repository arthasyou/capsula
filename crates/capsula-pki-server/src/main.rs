mod certificate;
mod db;
mod error;
mod handlers;
mod logging;
mod models;
mod pki;
mod routes;
mod settings;
mod state;

use settings::Settings;
use toolcraft_axum_kit::http_server;

use crate::{
    db::{create_tables, init_db},
    logging::init_tracing_to_file,
    pki::PkiManager,
    state::AppState,
};

#[tokio::main]
async fn main() {
    init_tracing_to_file();
    let settings = Settings::load("config/services.toml").unwrap();

    // Initialize database for certificate storage
    tracing::info!("Initializing database connection...");
    match init_db(settings.surrealdb).await {
        Ok(()) => {
            create_tables().await.unwrap();
            tracing::info!("Database initialized successfully");
        }
        Err(e) => {
            tracing::warn!(
                "Database initialization failed: {}. Continuing without database.",
                e
            );
            tracing::warn!(
                "Some certificate storage features may not work without database connection"
            );
        }
    }

    // Initialize PKI Manager
    tracing::info!("Initializing PKI Manager...");
    let mut pki_manager = PkiManager::new(settings.pki);
    match pki_manager.initialize().await {
        Ok(()) => {
            let status = pki_manager.get_ca_status();
            tracing::info!(
                "PKI Status: ready={}, root_ca={}, intermediate_ca={}, ca_chain={}",
                status.pki_ready,
                status.root_ca_available,
                status.intermediate_ca_available,
                status.ca_chain_available
            );

            if status.pki_ready {
                tracing::info!("PKI infrastructure ready - CA certificates loaded successfully");
            } else {
                tracing::warn!(
                    "PKI infrastructure not fully ready - some certificates may be missing"
                );
                tracing::warn!("Run './init_pki.sh' to initialize PKI infrastructure");
            }
        }
        Err(e) => {
            tracing::error!("Failed to initialize PKI Manager: {}", e);
            tracing::error!("PKI Server will start but certificate operations may not work");
        }
    }

    // Create shared application state
    let app_state = AppState::new(pki_manager);

    let router = routes::create_routes().with_state(app_state);
    let http_task = http_server::start(settings.http.port, router);

    tracing::info!("PKI Server started on port {}", settings.http.port);
    tracing::info!(
        "Swagger UI available at: http://localhost:{}/swagger-ui",
        settings.http.port
    );
    let _ = tokio::join!(http_task);
}
