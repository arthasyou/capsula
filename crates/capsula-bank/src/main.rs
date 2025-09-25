mod db;
mod error;
mod handlers;
mod logging;
mod models;
mod routes;
mod settings;

use settings::Settings;
use toolcraft_axum_kit::http_server;

use crate::{
    db::{create_tables, init_db},
    logging::init_tracing_to_file,
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

    // Initialize Capsula Bank
    tracing::info!("Initializing Capsula Bank...");

    let router = routes::create_routes();
    let http_task = http_server::start(settings.http.port, router);

    tracing::info!("Capsula Bank started on port {}", settings.http.port);
    tracing::info!(
        "Swagger UI available at: http://localhost:{}/swagger-ui",
        settings.http.port
    );
    let _ = tokio::join!(http_task);
}
